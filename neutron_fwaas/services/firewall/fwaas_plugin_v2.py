# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.db import servicetype_db as st_db
from neutron import service
from neutron.services import provider_configuration as provider_conf
from neutron.services import service_base
from neutron_lib.api.definitions import firewall_v2
from neutron_lib.api.definitions import portbindings as pb_def
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as nl_constants
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.common import exceptions
from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.extensions.firewall_v2 import Firewallv2PluginBase
from neutron_fwaas.services.firewall.service_drivers import driver_api
from neutron_fwaas.services.logapi.agents.drivers.iptables \
    import driver as logging_driver

LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class FirewallPluginV2(Firewallv2PluginBase):
    """Firewall v2 Neutron service plugin class"""

    supported_extension_aliases = [firewall_v2.ALIAS]
    path_prefix = firewall_v2.API_PREFIX

    def __init__(self):
        super(FirewallPluginV2, self).__init__()
        """Do the initialization for the firewall service plugin here."""
        # Initialize the Firewall v2 service plugin
        service_type_manager = st_db.ServiceTypeManager.get_instance()
        service_type_manager.add_provider_configuration(
            fwaas_constants.FIREWALL_V2,
            provider_conf.ProviderConfiguration('neutron_fwaas'))

        # Load the default driver
        drivers, default_provider = service_base.load_drivers(
            fwaas_constants.FIREWALL_V2, self)
        LOG.info("Firewall v2 Service Plugin using Service Driver: %s",
                 default_provider)

        if len(drivers) > 1:
            LOG.warning("Multiple drivers configured for Firewall v2, "
                        "although running multiple drivers in parallel is "
                        "not yet supported")

        self.driver_name = default_provider
        self.driver = drivers[default_provider]

        # start rpc listener if driver required
        if isinstance(self.driver, driver_api.FirewallDriverRPCMixin):
            rpc_worker = service.RpcWorker([self], worker_process_count=0)
            self.add_worker(rpc_worker)

        log_plugin = directory.get_plugin(plugin_const.LOG_API)
        logging_driver.register()
        # If log_plugin was loaded before firewall plugin
        if log_plugin:
            # Register logging driver with LoggingServiceDriverManager again
            log_plugin.driver_manager.register_driver(logging_driver.DRIVER)

    def start_rpc_listeners(self):
        return self.driver.start_rpc_listener()

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    def _ensure_update_firewall_group(self, context, fwg_id):
        """Checks if the firewall group can be updated

        Raises FirewallGroupInPendingState if the firewall group is in pending
        state.
        :param context: neutron context
        :param fwg_id: firewall group ID to check
        :return: Firewall group dict
        """
        fwg = self.get_firewall_group(context, fwg_id)
        if fwg['status'] in [nl_constants.PENDING_CREATE,
                             nl_constants.PENDING_UPDATE,
                             nl_constants.PENDING_DELETE]:
            raise f_exc.FirewallGroupInPendingState(
                firewall_id=fwg_id, pending_state=fwg['status'])
        return fwg

    def _ensure_update_firewall_policy(self, context, fwp_id):
        """Checks if the firewall policy can be updated

        Fetch firewall group associated to the policy and checks if they can be
        updated.
        :param context: neutron context
        :param fwp_id: firewall policy ID to check
        """
        fwp = self.get_firewall_policy(context, fwp_id)
        ing_fwg_ids, eg_fwg_ids = self._get_fwgs_with_policy(context, fwp)
        for fwg_id in list(set(ing_fwg_ids + eg_fwg_ids)):
            self._ensure_update_firewall_group(context, fwg_id)

    def _ensure_update_firewall_rule(self, context, fwr_id):
        """Checks if the firewall rule can be updated

        Fetch firewall policy associated to the rule and checks if they can be
        updated.
        :param context: neutron context
        :param fwr_id: firewall policy ID to check
        """
        fwr = self.get_firewall_rule(context, fwr_id)
        fwp_ids = self._get_policies_with_rule(context, fwr)
        for fwp_id in fwp_ids:
            self._ensure_update_firewall_policy(context, fwp_id)

    def _validate_firewall_policies_for_firewall_group(self, context, fwg):
        """Validate firewall group and policy owner

        Check if the firewall policy is not shared, it have the same project
        owner than the friewall group.
        :param context: neutron context
        :param fwg: firewall group to validate
        """
        for policy_type in ['ingress_firewall_policy_id',
                            'egress_firewall_policy_id']:
            if fwg.get(policy_type):
                fwp = self.get_firewall_policy(context, fwg[policy_type])
                if fwg['tenant_id'] != fwp['tenant_id'] and not fwp['shared']:
                    raise f_exc.FirewallPolicyConflict(
                        firewall_policy_id=fwg[policy_type])

    def _validate_ports_for_firewall_group(self, context, tenant_id,
                                           fwg_ports):
        """Validate firewall group associated ports

        Check if the firewall group associated ports have the same project
        owner and is router interface type or a compute layer 2 and supported
        by the firewall driver
        :param context: neutron context
        :param tenant_id: firewall group project ID
        :param fwg_ports: firewall group associated ports
        """
        # TODO(sridar): elevated context and do we want to use public ?
        for port_id in fwg_ports:
            port = self._core_plugin.get_port(context, port_id)

            if port['tenant_id'] != tenant_id:
                raise f_exc.FirewallGroupPortInvalidProject(
                    port_id=port_id, project_id=port['tenant_id'])
            device_owner = port.get('device_owner', '')
            if device_owner in nl_constants.ROUTER_INTERFACE_OWNERS:
                if not self.driver.is_supported_l3_port(port):
                    raise exceptions.FirewallGroupPortNotSupported(
                        driver_name=self.driver_name, port_id=port_id)
            elif device_owner.startswith(
                    nl_constants.DEVICE_OWNER_COMPUTE_PREFIX):
                if not self._is_supported_l2_port(context, port_id):
                    raise exceptions.FirewallGroupPortNotSupported(
                        driver_name=self.driver_name, port_id=port_id)
            else:
                raise f_exc.FirewallGroupPortInvalid(port_id=port_id)

    def _is_supported_l2_port(self, context, port_id):
        """Whether this l2 port is supported"""

        # Re-fetch to get up-to-date data from db
        port = self._core_plugin.get_port(context, id=port_id)

        # Skip port binding is unbound or failed
        if port[pb_def.VIF_TYPE] in [pb_def.VIF_TYPE_UNBOUND,
                                     pb_def.VIF_TYPE_BINDING_FAILED]:
            return False

        return self.driver.is_supported_l2_port(port)

    def _validate_if_firewall_group_on_ports(self, context, firewall_group,
                                             id=None):
        """Validate if ports are not associated with any firewall_group.

        If any of the ports in the list is already associated with
        a firewall group, raise an exception else just return.
        :param context: neutron context
        :param fwg: firewall group to validate
        """
        if 'ports' not in firewall_group or not firewall_group['ports']:
            return

        filters = {
            'tenant_id': [firewall_group['tenant_id']],
            'ports': firewall_group['ports'],
        }
        ports_in_use = set()
        for fwg in self.get_firewall_groups(context, filters=filters):
            if id is not None and fwg['id'] == id:
                continue
            ports_in_use |= set(fwg.get('ports', [])) & \
                set(firewall_group['ports'])
        if ports_in_use:
            raise f_exc.FirewallGroupPortInUse(port_ids=list(ports_in_use))

    def _get_fwgs_with_policy(self, context, firewall_policy):
        """List firewall group IDs which use a firewall policy

        List all firewall group IDs which have the given firewall policy as
        ingress or egress.
        :param context: neutron context
        :param firewall_policy: firewall policy to filter
        """
        filters = {
            'tenant_id': [firewall_policy['tenant_id']],
            'ingress_firewall_policy_id': [firewall_policy['id']],
        }
        ingress_fwp_ids = [fwg['id']
                           for fwg in self.get_firewall_groups(
                               context, filters=filters)]

        filters = {
            'tenant_id': [firewall_policy['tenant_id']],
            'egress_firewall_policy_id': [firewall_policy['id']],
        }
        egress_fwp_ids = [fwg['id']
                          for fwg in self.get_firewall_groups(
                              context, filters=filters)]

        return ingress_fwp_ids, egress_fwp_ids

    def _get_policies_with_rule(self, context, firewall_rule):
        filters = {
            'tenant_id': [firewall_rule['tenant_id']],
            'firewall_rules': [firewall_rule['id']],
        }
        return [fwp['id'] for fwp in self.get_firewall_policies(
                    context, filters=filters)]

    def _validate_insert_remove_rule_request(self, rule_info):
        """Validate rule_info dict

        Check that all mandatory fields are present, otherwise raise
        proper exception.
        """
        if not rule_info or 'firewall_rule_id' not in rule_info:
            raise f_exc.FirewallRuleInfoMissing()
        # Validator doesn't return anything if the check passes
        if validators.validate_uuid(rule_info['firewall_rule_id']):
            raise f_exc.FirewallRuleNotFound(
                firewall_rule_id=rule_info['firewall_rule_id'])

    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def handle_update_port(self, resource, event, trigger, payload):
        context = payload.context
        original_port = payload.states[0]
        updated_port = payload.states[1]
        if not updated_port['device_owner'].startswith(
                nl_constants.DEVICE_OWNER_COMPUTE_PREFIX):
            return

        if (original_port[pb_def.VIF_TYPE] != pb_def.VIF_TYPE_UNBOUND):
            # Checking newly vm port binding allows us to avoid call to DB
            # when a port update_event like restart, setting name, etc...
            # Moreover, that will help us in case of tenant admin wants to
            # only attach security group to vm port.
            return

        port_id = updated_port['id']
        # Check port is supported by firewall driver
        if not self._is_supported_l2_port(context, port_id):
            return

        project_id = updated_port['project_id']
        fwgs = self.get_firewall_groups(
            context,
            filters={
                'tenant_id': [project_id],
                'name': [fwaas_constants.DEFAULT_FWG],
            },
            fields=['id', 'ports'],
        )
        if len(fwgs) != 1:
            # Cannot found default Firewall Group, abandon
            LOG.warning("Cannot found default firewall group of project %s",
                        project_id)
            return
        default_fwg = fwgs[0]

        # Add default firewall group to the port
        port_ids = default_fwg.get('ports', []) + [port_id]
        try:
            self.update_firewall_group(context, default_fwg['id'],
                                       {'firewall_group': {'ports': port_ids}})
        except f_exc.FirewallGroupPortInUse:
            LOG.warning("Port %s has been already associated with default "
                        "firewall group %s and skip association", port_id,
                        default_fwg['id'])

    # Firewall Group
    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def create_firewall_group(self, context, firewall_group):
        firewall_group = firewall_group['firewall_group']
        ports = firewall_group.get('ports', [])

        self._validate_firewall_policies_for_firewall_group(context,
                                                            firewall_group)
        # Validate ports owner type and project
        self._validate_ports_for_firewall_group(context,
                                                firewall_group['tenant_id'],
                                                ports)

        self._validate_if_firewall_group_on_ports(context, firewall_group)

        return self.driver.create_firewall_group(context, firewall_group)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def delete_firewall_group(self, context, id):
        # if no such group exists -> don't raise an exception according to
        # 80fe2ba1, return None
        try:
            fwg = self.get_firewall_group(context, id)
        except f_exc.FirewallGroupNotFound:
            return

        if fwg['ports']:
            raise f_exc.FirewallGroupInUse(firewall_id=id)

        self.driver.delete_firewall_group(context, id)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_firewall_group(self, context, id, fields=None):
        return self.driver.get_firewall_group(context, id, fields=fields)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def get_firewall_groups(self, context, filters=None, fields=None):
        return self.driver.get_firewall_groups(context, filters, fields)

    @log_helpers.log_method_call
    def get_firewall_groups_count(self, context, filters=None):
        filters = filters or {}
        return len(self.get_firewall_groups(context=context, filters=filters))

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def update_firewall_group(self, context, id, firewall_group):
        firewall_group = firewall_group['firewall_group']
        ports = firewall_group.get('ports', [])

        old_firewall_group = self._ensure_update_firewall_group(context, id)
        firewall_group['tenant_id'] = old_firewall_group['tenant_id']

        self._validate_firewall_policies_for_firewall_group(context,
                                                            firewall_group)
        # Validate ports owner type and project
        self._validate_ports_for_firewall_group(context,
                                                firewall_group['tenant_id'],
                                                ports)
        self._validate_if_firewall_group_on_ports(context, firewall_group,
                                                  id=id)

        return self.driver.update_firewall_group(context, id, firewall_group)

    # Firewall Policy
    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def create_firewall_policy(self, context, firewall_policy):
        firewall_policy = firewall_policy['firewall_policy']
        return self.driver.create_firewall_policy(context, firewall_policy)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def delete_firewall_policy(self, context, id):
        self.driver.delete_firewall_policy(context, id)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_firewall_policy(self, context, id, fields=None):
        return self.driver.get_firewall_policy(context, id, fields)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_firewall_policies(self, context, filters=None, fields=None):
        return self.driver.get_firewall_policies(context, filters, fields)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def update_firewall_policy(self, context, id, firewall_policy):
        firewall_policy = firewall_policy['firewall_policy']
        self._ensure_update_firewall_policy(context, id)
        return self.driver.update_firewall_policy(context, id, firewall_policy)

    # Firewall Rule
    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def create_firewall_rule(self, context, firewall_rule):
        firewall_rule = firewall_rule['firewall_rule']
        return self.driver.create_firewall_rule(context, firewall_rule)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def delete_firewall_rule(self, context, id):
        self.driver.delete_firewall_rule(context, id)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_firewall_rule(self, context, id, fields=None):
        return self.driver.get_firewall_rule(context, id, fields)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def get_firewall_rules(self, context, filters=None, fields=None):
        return self.driver.get_firewall_rules(context, filters, fields)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def update_firewall_rule(self, context, id, firewall_rule):
        firewall_rule = firewall_rule['firewall_rule']
        self._ensure_update_firewall_rule(context, id)
        return self.driver.update_firewall_rule(context, id, firewall_rule)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def insert_rule(self, context, policy_id, rule_info):
        self._ensure_update_firewall_policy(context, policy_id)
        self._validate_insert_remove_rule_request(rule_info)
        return self.driver.insert_rule(context, policy_id, rule_info)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def remove_rule(self, context, policy_id, rule_info):
        self._ensure_update_firewall_policy(context, policy_id)
        self._validate_insert_remove_rule_request(rule_info)
        return self.driver.remove_rule(context, policy_id, rule_info)
