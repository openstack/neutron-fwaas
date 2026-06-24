# Copyright (c) 2013 OpenStack Foundation
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

from neutron_lib.api.definitions import portbindings as pb_def
from neutron_lib import constants as nl_constants
from neutron_lib import context as neutron_context
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas.common import fwaas_constants as constants
from neutron_fwaas.objects import register_objects
from neutron_fwaas.services.firewall.rpc import serialization as rpc_serial
from neutron_fwaas.services.firewall.service_drivers import driver_api
from neutron_fwaas.services.logapi.agents.drivers.iptables \
    import driver as logging_driver


LOG = logging.getLogger(__name__)


class FirewallAgentCallbacks:
    # API version history:
    #   1.0 - dict-based firewall_group payloads
    #   1.1 - OVO-based firewall_group payloads (FirewallGroup + rules)
    target = oslo_messaging.Target(version='1.1')

    def __init__(self, firewall_db):
        self.firewall_db = firewall_db

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def set_firewall_group_status(self, context, fwg_id, status, **kwargs):
        """Agent uses this to set a firewall_group's status."""
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
        updated = self.firewall_db.update_firewall_group_status(
            context, fwg_id, to_update, not_in=(nl_constants.PENDING_DELETE,))
        if updated:
            LOG.debug("firewall %s status set: %s", fwg_id, to_update)
        return updated and to_update != nl_constants.ERROR

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def firewall_group_deleted(self, context, fwg_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        try:
            fwg = self.firewall_db.get_firewall_group(context, fwg_id)
            # allow to delete firewalls in ERROR state
            if fwg.status in (nl_constants.PENDING_DELETE,
                              nl_constants.ERROR):
                self.firewall_db.delete_firewall_group(context, fwg_id)
                return True
            LOG.warning('Firewall %(fwg)s unexpectedly deleted by agent, '
                        'status was %(status)s',
                        {'fwg': fwg_id, 'status': fwg.status})
            self.firewall_db.update_firewall_group(
                context, fwg_id, {'status': nl_constants.ERROR})
            return False
        except f_exc.FirewallGroupNotFound:
            LOG.info('Firewall group %s already deleted', fwg_id)
            return True

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def get_firewall_groups_for_project(self, context, **kwargs):
        """Gets all firewall_groups and rules on a project."""
        rpc_version = kwargs.pop(
            'rpc_version', rpc_serial.FWAAS_RPC_VERSION_LEGACY)
        rpc_payload_list = []
        for fwg in self.firewall_db.get_firewall_groups(context):
            rpc_payload_list.append(
                rpc_serial.build_firewall_group_rpc_payload_for_sync(
                    context, self.firewall_db, fwg))
        return rpc_serial.serialize_firewall_group_list_for_rpc(
            rpc_payload_list, rpc_version)

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def get_projects_with_firewall_groups(self, context, **kwargs):
        """Get all projects that have firewall_groups."""
        ctx = neutron_context.get_admin_context()
        fwg_list = self.firewall_db.get_firewall_groups(ctx)
        fwg_project_list = list({fwg.project_id for fwg in fwg_list})
        return fwg_project_list

    @log_helpers.log_method_call
    @db_api.CONTEXT_WRITER
    def get_firewall_group_for_port(self, context, **kwargs):
        """Get firewall_group is associated with a port."""
        rpc_version = kwargs.pop(
            'rpc_version', rpc_serial.FWAAS_RPC_VERSION_LEGACY)
        ctx = context.elevated()
        # Only one Firewall Group can be associated to a port at a time
        fwg_port_binding = self.firewall_db.get_firewall_groups(
            ctx, filters={'ports': [kwargs.get('port_id')]})
        if len(fwg_port_binding) != 1:
            return
        rpc_payload = rpc_serial.build_firewall_group_rpc_payload_for_port(
            context, self.firewall_db, fwg_port_binding[0])
        return rpc_serial.serialize_firewall_group_for_rpc(
            rpc_payload, rpc_version)


class FirewallAgentApi:
    """Plugin side of plugin to agent RPC API"""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.1')
        self.client = n_rpc.get_client(target)

    def _cast_firewall_group(self, context, method_name, rpc_payload):
        # TODO(slaweq): Use FWAAS_RPC_VERSION_OVO once 1.0 agents
        # are no longer supported (after H+1 / I slurp).
        rpc_version = rpc_serial.FWAAS_RPC_VERSION_LEGACY
        payload = rpc_serial.serialize_firewall_group_for_rpc(
            rpc_payload, rpc_version)
        cctxt = self.client.prepare(fanout=True, version=rpc_version)
        cctxt.cast(context, method_name,
                   firewall_group=payload, host=self.host)

    def create_firewall_group(self, context, rpc_payload):
        self._cast_firewall_group(
            context, 'create_firewall_group', rpc_payload)

    def update_firewall_group(self, context, rpc_payload):
        self._cast_firewall_group(
            context, 'update_firewall_group', rpc_payload)

    def delete_firewall_group(self, context, rpc_payload):
        self._cast_firewall_group(
            context, 'delete_firewall_group', rpc_payload)


class FirewallAgentDriver(driver_api.FirewallDriverDB,
                          driver_api.FirewallDriverRPCMixin):
    """Firewall driver to implement agent messages and callback methods

    Implement RPC Firewall v2 API and callback methods for agents based on
    Neutron DB model.
    """

    def __init__(self, service_plugin):
        super().__init__(service_plugin)
        self.agent_rpc = FirewallAgentApi(constants.FW_AGENT, cfg.CONF.host)

    def register_logging_driver(self):
        log_plugin = directory.get_plugin(plugin_const.LOG_API)
        logging_driver.register()
        # If log_plugin was loaded before firewall plugin
        if log_plugin:
            # Register logging driver with LoggingServiceDriverManager again
            log_plugin.driver_manager.register_driver(logging_driver.DRIVER)

    def is_supported_l2_port(self, port):
        if port[pb_def.VIF_TYPE] == pb_def.VIF_TYPE_OVS:
            if not port['port_security_enabled']:
                return True

            # TODO(annp): remove these lines after we fully support for hybrid
            # port
            if not port[pb_def.VIF_DETAILS][pb_def.OVS_HYBRID_PLUG]:
                return True
            LOG.warning("Doesn't support hybrid port at the moment")
        else:
            LOG.warning("Doesn't support vif type %s", port[pb_def.VIF_TYPE])
        return False

    def is_supported_l3_port(self, port):
        return True

    def start_rpc_listener(self):
        register_objects()
        self.endpoints = [FirewallAgentCallbacks(self.firewall_db)]
        self.rpc_connection = n_rpc.Connection()
        self.rpc_connection.create_consumer(constants.FIREWALL_PLUGIN,
                                            self.endpoints, fanout=False)
        return self.rpc_connection.consume_in_threads()

    def _rpc_update_firewall_group(self, context, fwg_id):
        fw_ports = self.firewall_db.get_ports_in_firewall_group(
            context, fwg_id)
        if not fw_ports:
            return
        status_update = {"status": nl_constants.PENDING_UPDATE}
        self.update_firewall_group(context, fwg_id, status_update)
        rpc_payload = rpc_serial.build_firewall_group_rpc_payload(
            context, self.firewall_db, fwg_id,
            add_port_ids=fw_ports,
            del_port_ids=[],
            port_details=self._get_fwg_port_details(context, fw_ports))
        self.agent_rpc.update_firewall_group(context, rpc_payload)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            ing_fwg_ids, eg_fwg_ids = self.firewall_db.get_fwgs_with_policy(
                context, firewall_policy_id)
            for fwg_id in list(set(ing_fwg_ids + eg_fwg_ids)):
                self._rpc_update_firewall_group(context, fwg_id)

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
                'id': port_db['id'],
                'status': port_db['status'],
            }
            if device_owner.startswith(
                    nl_constants.DEVICE_OWNER_COMPUTE_PREFIX):
                port_details[port_id].update(
                    {'host': port_db[pb_def.HOST_ID]})
        return port_details

    def create_firewall_group_precommit(self, context, firewall_group):
        ports = firewall_group['ports']

        if (not ports or (
                not firewall_group.get('ingress_firewall_policy_id') and
                not firewall_group.get('egress_firewall_policy_id'))):
            # no messaging to agent needed and fw needs to go to INACTIVE state
            # as no associated ports and/or no policy configured.
            status = nl_constants.INACTIVE
        else:
            status = (nl_constants.CREATED if cfg.CONF.router_distributed
                      else nl_constants.PENDING_CREATE)
        firewall_group['status'] = status

    def create_firewall_group_postcommit(self, context, firewall_group):
        if firewall_group['status'] != nl_constants.INACTIVE:
            rpc_payload = rpc_serial.build_firewall_group_rpc_payload(
                context, self.firewall_db, firewall_group['id'],
                add_port_ids=firewall_group['ports'],
                del_port_ids=[],
                port_details=self._get_fwg_port_details(
                    context, firewall_group['ports']))
            self.agent_rpc.create_firewall_group(context, rpc_payload)

    def _need_pending_update(self, old_firewall_group, new_firewall_group):
        port_updated = (set(new_firewall_group['ports']) !=
                        set(old_firewall_group['ports']))
        policies_updated = (
            new_firewall_group.get('ingress_firewall_policy_id') !=
            old_firewall_group.get('ingress_firewall_policy_id') or
            new_firewall_group.get('egress_firewall_policy_id') !=
            old_firewall_group.get('egress_firewall_policy_id')
        )
        if (port_updated and
                (new_firewall_group.get('ingress_firewall_policy_id') or
                 new_firewall_group.get('egress_firewall_policy_id'))):
            return True
        if policies_updated and new_firewall_group['ports']:
            return True
        return False

    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        if self._need_pending_update(old_firewall_group, new_firewall_group):
            new_firewall_group['status'] = nl_constants.PENDING_UPDATE

    def update_firewall_group_postcommit(self, context, old_firewall_group,
                                         new_firewall_group):
        if not self._need_pending_update(old_firewall_group,
                                         new_firewall_group):
            return

        add_port_ids = list(
            set(new_firewall_group['ports']) - set(old_firewall_group['ports'])
        )
        del_port_ids = list(
            set(old_firewall_group['ports']) - set(new_firewall_group['ports'])
        )

        # last-port drives agent to ack with status to set state to INACTIVE
        # Set last-port to True if there are no ports in the new group and
        # the old group had the same number of ports that need to be deleted.
        last_port = (len(old_firewall_group['ports']) == len(del_port_ids) and
                     not new_firewall_group['ports'])

        LOG.debug("update_firewall_group %s: Add Ports: %s, Del Ports: %s",
                  new_firewall_group['id'],
                  add_port_ids,
                  del_port_ids)

        port_details = self._get_fwg_port_details(context, del_port_ids)
        port_details.update(self._get_fwg_port_details(context, add_port_ids))

        if (new_firewall_group['name'] == constants.DEFAULT_FWG and
                len(add_port_ids) == 1 and
                not del_port_ids):
            port_id = add_port_ids[0]
            if (port_details[port_id].get('status') !=
                    nl_constants.ACTIVE):
                # If port not yet active, just associate to default firewall
                # group. When agent will set it to UP, it'll found FG
                # association and enforce default policies
                return

        rpc_payload = rpc_serial.build_firewall_group_rpc_payload(
            context, self.firewall_db, new_firewall_group['id'],
            add_port_ids=add_port_ids,
            del_port_ids=del_port_ids,
            port_details=port_details,
            last_port=last_port)
        self.agent_rpc.update_firewall_group(context, rpc_payload)

    def update_firewall_policy_postcommit(self, context, old_firewall_policy,
                                          new_firewall_group):
        self._rpc_update_firewall_policy(context, new_firewall_group['id'])

    def update_firewall_rule_postcommit(self, context, old_firewall_rule,
                                        new_firewall_rule):
        firewall_policy_ids = self.firewall_db.get_policies_with_rule(
            context, new_firewall_rule['id'])
        for firewall_policy_id in firewall_policy_ids:
            self._rpc_update_firewall_policy(context, firewall_policy_id)

    def insert_rule_postcommit(self, context, policy_id, rule_info):
        self._rpc_update_firewall_policy(context, policy_id)

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        self._rpc_update_firewall_policy(context, policy_id)
