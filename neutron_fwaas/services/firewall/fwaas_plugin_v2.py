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

from neutron.common import rpc as n_rpc
from neutron.db import servicetype_db as st_db
from neutron.services import provider_configuration as provider_conf
from neutron_lib.api.definitions import firewall_v2
from neutron_lib.api.definitions import portbindings as pb_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as nl_constants
from neutron_lib import context as neutron_context
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas.common import exceptions
from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.db.firewall.v2 import firewall_db_v2

LOG = logging.getLogger(__name__)


def add_provider_configuration(type_manager, service_type):
    type_manager.add_provider_configuration(
        service_type,
        provider_conf.ProviderConfiguration('neutron_fwaas'))


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def create_firewall_group(self, context, firewall_group):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_firewall_group',
                   firewall_group=firewall_group,
                   host=self.host)

    def update_firewall_group(self, context, firewall_group):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_firewall_group',
                   firewall_group=firewall_group,
                   host=self.host)

    def delete_firewall_group(self, context, firewall_group):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_firewall_group',
                   firewall_group=firewall_group,
                   host=self.host)


class FirewallCallbacks(object):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    def set_firewall_group_status(self, context, fwg_id, status, **kwargs):
        """Agent uses this to set a firewall_group's status."""
        LOG.debug("Setting firewall_group %s to status: %s",
                  fwg_id, status)
        # Sanitize status first
        if status in (nl_constants.ACTIVE, nl_constants.DOWN,
                      nl_constants.INACTIVE):
            to_update = status
        else:
            to_update = nl_constants.ERROR
        # ignore changing status if firewall_group expects to be deleted
        # That case means that while some pending operation has been
        # performed on the backend, neutron server received delete request
        # and changed firewall status to PENDING_DELETE
        updated = self.plugin.update_firewall_group_status(
            context, fwg_id, to_update, not_in=(nl_constants.PENDING_DELETE,))
        if updated:
            LOG.debug("firewall %s status set: %s", fwg_id, to_update)
        return updated and to_update != nl_constants.ERROR

    def firewall_group_deleted(self, context, fwg_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug("firewall_group_deleted() called")
        try:
            with context.session.begin(subtransactions=True):
                fwg_db = self.plugin._get_firewall_group(context, fwg_id)
                # allow to delete firewalls in ERROR state
                if fwg_db.status in (nl_constants.PENDING_DELETE,
                                     nl_constants.ERROR):
                    self.plugin.delete_db_firewall_group_object(context,
                                                                fwg_id)
                    return True
                else:
                    LOG.warning(('Firewall %(fwg)s unexpectedly deleted by '
                                 'agent, status was %(status)s'),
                                {'fwg': fwg_id, 'status': fwg_db.status})
                    fwg_db.update({"status": nl_constants.ERROR})
                    return False
        except f_exc.FirewallGroupNotFound:
            LOG.info('Firewall group %s already deleted', fwg_id)
            return True

    def get_firewall_groups_for_project(self, context, **kwargs):
        """Gets all firewall_groups and rules on a project."""
        LOG.debug("get_firewall_groups_for_project() called")
        fwg_list = []
        for fwg in self.plugin.get_firewall_groups(context):
            fwg_with_rules = self.plugin._make_firewall_group_dict_with_rules(
                context, fwg['id'])
            if fwg['status'] == nl_constants.PENDING_DELETE:
                fwg_with_rules['add-port-ids'] = []
                fwg_with_rules['del-port-ids'] = (
                    self.plugin._get_ports_in_firewall_group(context,
                        fwg['id']))
            else:
                fwg_with_rules['add-port-ids'] = (
                    self.plugin._get_ports_in_firewall_group(context,
                        fwg['id']))
                fwg_with_rules['del-port-ids'] = []
            fwg_list.append(fwg_with_rules)
        return fwg_list

    def get_projects_with_firewall_groups(self, context, **kwargs):
        """Get all projects that have firewall_groups."""
        LOG.debug("get_projects_with_firewall_groups() called")
        ctx = neutron_context.get_admin_context()
        fwg_list = self.plugin.get_firewall_groups(ctx)
        fwg_project_list = list(set(fwg['tenant_id'] for fwg in fwg_list))
        return fwg_project_list

    def get_firewall_group_for_port(self, context, **kwargs):
        """Get firewall_group is associated  with a port."""
        LOG.debug("get_firewall_group_for_port() called")
        ctx = context.elevated()
        return self.plugin.get_firewall_group_for_port(
            ctx, kwargs.get('port_id'))


@registry.has_registry_receivers
class FirewallPluginV2(
    firewall_db_v2.Firewall_db_mixin_v2):
    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db_v2.Firewall_db_mixin_v2.
    """
    supported_extension_aliases = ["fwaas_v2"]
    path_prefix = firewall_v2.API_PREFIX

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        add_provider_configuration(
            self.service_type_manager, plugin_const.FIREWALL)
        self.start_rpc_listeners()

        self.agent_rpc = FirewallAgentApi(
            fwaas_constants.FW_AGENT,
            cfg.CONF.host
        )

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    def start_rpc_listeners(self):
        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(
            fwaas_constants.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _rpc_update_firewall_group(self, context, fwg_id):
        status_update = {"firewall_group": {"status":
                         nl_constants.PENDING_UPDATE}}
        super(FirewallPluginV2, self).update_firewall_group(
            context, fwg_id, status_update)
        fwg_with_rules = self._make_firewall_group_dict_with_rules(context,
                                                            fwg_id)
        # this is triggered on an update to fwg rule or policy, no
        # change in associated ports.
        fwg_with_rules['add-port-ids'] = self._get_ports_in_firewall_group(
                context, fwg_id)
        fwg_with_rules['del-port-ids'] = []
        fwg_with_rules['port_details'] = self._get_fwg_port_details(
            context, fwg_with_rules['add-port-ids'])
        self.agent_rpc.update_firewall_group(context, fwg_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            ing_fwg_ids, eg_fwg_ids = self._get_fwgs_with_policy(context,
                firewall_policy_id)
            for fwg_id in list(set(ing_fwg_ids + eg_fwg_ids)):
                self._rpc_update_firewall_group(context, fwg_id)

    def _ensure_update_firewall_group(self, context, fwg_id):
        fwg = self.get_firewall_group(context, fwg_id)
        if fwg['status'] in [nl_constants.PENDING_CREATE,
                             nl_constants.PENDING_UPDATE,
                             nl_constants.PENDING_DELETE]:
            raise f_exc.FirewallGroupInPendingState(firewall_id=fwg_id,
                                                pending_state=fwg['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            ing_fwg_ids, eg_fwg_ids = self._get_fwgs_with_policy(
                context, firewall_policy_id)
            for fwg_id in list(set(ing_fwg_ids + eg_fwg_ids)):
                self._ensure_update_firewall_group(context, fwg_id)

    def _ensure_update_firewall_rule(self, context, fwr_id):
        fwp_ids = self._get_policies_with_rule(context, fwr_id)
        for fwp_id in fwp_ids:
            self._ensure_update_firewall_policy(context, fwp_id)

    def _validate_ports_for_firewall_group(self, context, tenant_id,
                                           fwg_ports):
        # TODO(sridar): elevated context and do we want to use public ?
        for port_id in fwg_ports:
            port_db = self._core_plugin._get_port(context, port_id)
            if port_db['tenant_id'] != tenant_id:
                raise f_exc.FirewallGroupPortInvalidProject(
                    port_id=port_id, project_id=port_db['tenant_id'])
            device_owner = port_db.get('device_owner', '')
            if (device_owner not in [nl_constants.DEVICE_OWNER_ROUTER_INTF] and
                not device_owner.startswith(
                    nl_constants.DEVICE_OWNER_COMPUTE_PREFIX)):
                raise f_exc.FirewallGroupPortInvalid(port_id=port_id)
            if (device_owner.startswith(
                    nl_constants.DEVICE_OWNER_COMPUTE_PREFIX) and not
                self._is_supported_by_fw_l2_driver(context, port_id)):
                raise exceptions.FirewallGroupPortNotSupported(port_id=port_id)

    def _is_supported_by_fw_l2_driver(self, context, port_id):
        """Whether this port is supported by firewall l2 driver"""

        # Re-fetch to get up-to-date data from db
        port = self._core_plugin.get_port(context, id=port_id)

        # Skip port binding is unbound or failed
        if port[pb_def.VIF_TYPE] in [pb_def.VIF_TYPE_UNBOUND,
                                     pb_def.VIF_TYPE_BINDING_FAILED]:
            return False

        if not port['port_security_enabled']:
            return True

        if port[pb_def.VIF_TYPE] == pb_def.VIF_TYPE_OVS:
            # TODO(annp): remove these lines after we fully support for hybrid
            # port
            if not port[pb_def.VIF_DETAILS][pb_def.OVS_HYBRID_PLUG]:
                return True
            LOG.warning("Doesn't support hybrid port at the moment")
        else:
            LOG.warning("Doesn't support vif type %s", port[pb_def.VIF_TYPE])
        return False

    def _check_no_need_pending(self, context, fwg_id, fwg_body):
        fwg_db = self._get_firewall_group(context, fwg_id)
        fwp_req_in = fwg_body.get('ingress_firewall_policy_id', None)
        fwp_req_eg = fwg_body.get('egress_firewall_policy_id', None)

        if ((not fwg_db.ingress_firewall_policy_id and
                fwp_req_in is fwg_db.ingress_firewall_policy_id) and
                (not fwg_db.egress_firewall_policy_id and
                    fwp_req_eg is fwg_db.ingress_firewall_policy_id)):
            return True
        return False

    def _get_fwg_port_details(self, context, fwg_ports):
        """Returns a dictionary list of port details. """
        port_details = {}
        for port_id in fwg_ports:
            port_db = self._core_plugin.get_port(context, port_id)
            # Add more parameters below based on requirement.
            device_owner = port_db['device_owner']
            port_details[port_id] = {
                'device_owner': device_owner,
                'device': port_db['id'],
                'network_id': port_db['network_id'],
                'fixed_ips': port_db['fixed_ips'],
                'allowed_address_pairs':
                    port_db.get('allowed_address_pairs', []),
                'port_security_enabled':
                    port_db.get('port_security_enabled', True),
                'id': port_db['id']
            }
            if device_owner.startswith(
                nl_constants.DEVICE_OWNER_COMPUTE_PREFIX):
                port_details[port_id].update(
                    {'host': port_db[pb_def.HOST_ID]})
        return port_details

    def get_project_id_from_port_id(self, context, port_id):
        """Returns an ID of project for specified port_id. """
        return self._core_plugin.get_port(context, port_id)['project_id']

    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def handle_update_port(self, resource, event, trigger, **kwargs):

        updated_port = kwargs['port']
        if not updated_port['device_owner'].startswith(
                nl_constants.DEVICE_OWNER_COMPUTE_PREFIX):
            return

        if (kwargs.get('original_port')[pb_def.VIF_TYPE] !=
                pb_def.VIF_TYPE_UNBOUND):
            # Checking newly vm port binding allows us to avoid call to DB
            # when a port update_event like restart, setting name, etc...
            # Moreover, that will help us in case of tenant admin wants to
            # only attach security group to vm port.
            return

        context = kwargs['context']
        port_id = updated_port['id']
        # Check port is supported by firewall l2 driver or not
        if not self._is_supported_by_fw_l2_driver(context, port_id):
            return

        project_id = updated_port['project_id']
        LOG.debug("Try to associate port %s at %s", port_id, project_id)
        self.set_port_for_default_firewall_group(context, port_id, project_id)

    def create_firewall_group(self, context, firewall_group):
        LOG.debug("create_firewall_group() called")
        fwgrp = firewall_group['firewall_group']
        fwg_ports = fwgrp['ports']

        if not fwg_ports:
            # no messaging to agent needed, and fw needs to go
            # to INACTIVE(no associated ports) state.
            status = nl_constants.INACTIVE
            fwg = super(FirewallPluginV2, self).create_firewall_group(
                context, firewall_group, status)
            fwg['ports'] = []
            return fwg
        else:
            # Validate ports
            self._validate_ports_for_firewall_group(context,
                firewall_group['firewall_group']['tenant_id'], fwg_ports)

            if (not fwgrp['ingress_firewall_policy_id'] and
                not fwgrp['egress_firewall_policy_id']):
                # No policy configured
                status = nl_constants.INACTIVE
                fwg = super(FirewallPluginV2, self).create_firewall_group(
                    context, firewall_group, status)
                return fwg

            fwg = super(FirewallPluginV2, self).create_firewall_group(
                context, firewall_group)
            fwg['ports'] = fwg_ports

        fwg_with_rules = (
            self._make_firewall_group_dict_with_rules(context, fwg['id']))

        fwg_with_rules['add-port-ids'] = fwg_ports
        fwg_with_rules['del-port-ids'] = []
        fwg_with_rules['port_details'] = self._get_fwg_port_details(
            context, fwg_ports)

        self.agent_rpc.create_firewall_group(context, fwg_with_rules)

        return fwg

    def update_firewall_group(self, context, id, firewall_group):
        LOG.debug("update_firewall_group() called on firewall_group %s", id)

        self._ensure_update_firewall_group(context, id)

        # TODO(sridar): need closure on status when no policy associated.
        fwg_current_ports = fwg_new_ports = self._get_ports_in_firewall_group(
            context, id)
        if 'ports' in firewall_group['firewall_group']:
            fwg_new_ports = firewall_group['firewall_group']['ports']
            if len(fwg_new_ports) > 0:
                self._validate_ports_for_firewall_group(
                    context, context.project_id, fwg_new_ports)

        if ((not fwg_new_ports and not fwg_current_ports) or
            self._check_no_need_pending(context,
                                        id, firewall_group['firewall_group'])):
            # no messaging to agent needed, and we need to continue
            # in INACTIVE state
            firewall_group['firewall_group']['status'] = nl_constants.INACTIVE
            fwg = super(FirewallPluginV2, self).update_firewall_group(
                context, id, firewall_group)
            if fwg_new_ports:
                fwg['ports'] = fwg_new_ports
            elif not fwg_new_ports and fwg_current_ports:
                fwg['ports'] = fwg_current_ports
            else:
                fwg['ports'] = []
            return fwg
        else:
            firewall_group['firewall_group']['status'] = (nl_constants.
                                                          PENDING_UPDATE)
            fwg = super(FirewallPluginV2, self).update_firewall_group(
                context, id, firewall_group)
            fwg['ports'] = fwg_new_ports

        fwg_with_rules = (
            self._make_firewall_group_dict_with_rules(context, fwg['id']))

        # determine ports to add fw to and del from
        fwg_with_rules['add-port-ids'] = fwg_new_ports
        fwg_with_rules['del-port-ids'] = list(
            set(fwg_current_ports).difference(set(fwg_new_ports)))

        # last-port drives agent to ack with status to set state to INACTIVE
        fwg_with_rules['last-port'] = not fwg_new_ports

        LOG.debug("update_firewall_group %s: Add Ports: %s, Del Ports: %s",
            fwg['id'],
            fwg_with_rules['add-port-ids'],
            fwg_with_rules['del-port-ids'])

        fwg_with_rules['port_details'] = self._get_fwg_port_details(
            context, fwg_with_rules['del-port-ids'])
        fwg_with_rules['port_details'].update(self._get_fwg_port_details(
            context, fwg_with_rules['add-port-ids']))
        self.agent_rpc.update_firewall_group(context, fwg_with_rules)

        return fwg

    def delete_db_firewall_group_object(self, context, id):
        super(FirewallPluginV2, self).delete_firewall_group(context, id)

    def delete_firewall_group(self, context, id):
        LOG.debug("delete_firewall_group() called on firewall_group %s", id)

        fwg_db = self._get_firewall_group(context, id)

        if fwg_db['status'] == nl_constants.ACTIVE:
            raise f_exc.FirewallGroupInUse(firewall_id=id)

        fwg_with_rules = (
            self._make_firewall_group_dict_with_rules(context, id))
        fwg_with_rules['del-port-ids'] = self._get_ports_in_firewall_group(
            context, id)
        fwg_with_rules['add-port-ids'] = []
        if not fwg_with_rules['del-port-ids']:
            # no ports, no need to talk to the agent
            self.delete_db_firewall_group_object(context, id)
        else:
            status = {"firewall_group": {"status":
                                         nl_constants.PENDING_DELETE}}
            super(FirewallPluginV2, self).update_firewall_group(
                context, id, status)
            # Reflect state change in fwg_with_rules
            fwg_with_rules['status'] = status['firewall_group']['status']
            fwg_with_rules['port_details'] = self._get_fwg_port_details(
                context, fwg_with_rules['del-port-ids'])
            self.agent_rpc.delete_firewall_group(context, fwg_with_rules)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug("update_firewall_policy() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPluginV2,
                    self).update_firewall_policy(context, id, firewall_policy)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("update_firewall_rule() called")
        self._ensure_update_firewall_rule(context, id)
        fwr = super(FirewallPluginV2,
                    self).update_firewall_rule(context, id, firewall_rule)
        fwp_ids = self._get_policies_with_rule(context, id)
        for fwp_id in fwp_ids:
            self._rpc_update_firewall_policy(context, fwp_id)
        return fwr

    def insert_rule(self, context, id, rule_info):
        LOG.debug("insert_rule() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPluginV2, self).insert_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def remove_rule(self, context, id, rule_info):
        LOG.debug("remove_rule() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPluginV2, self).remove_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        return fwp
