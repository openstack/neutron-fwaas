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

from neutron.common import rpc as neutron_rpc
from neutron_lib.api.definitions import portbindings as pb_def
from neutron_lib import constants as nl_constants
from neutron_lib import context as neutron_context
from neutron_lib.exceptions import firewall_v2 as f_exc
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas.common import fwaas_constants as constants
from neutron_fwaas.services.firewall.service_drivers import driver_api


LOG = logging.getLogger(__name__)


class FirewallAgentCallbacks(object):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, firewall_db):
        self.firewall_db = firewall_db

    @log_helpers.log_method_call
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
    def firewall_group_deleted(self, context, fwg_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        try:
            fwg = self.firewall_db.get_firewall_group(context, fwg_id)
            # allow to delete firewalls in ERROR state
            if fwg['status'] in (nl_constants.PENDING_DELETE,
                                 nl_constants.ERROR):
                self.firewall_db.delete_firewall_group(context, fwg_id)
                return True
            LOG.warning('Firewall %(fwg)s unexpectedly deleted by agent, '
                        'status was %(status)s',
                        {'fwg': fwg_id, 'status': fwg['status']})
            fwg['status'] = nl_constants.ERROR
            self.firewall_db.update_firewall_group(context, fwg_id, fwg)
            return False
        except f_exc.FirewallGroupNotFound:
            LOG.info('Firewall group %s already deleted', fwg_id)
            return True

    @log_helpers.log_method_call
    def get_firewall_groups_for_project(self, context, **kwargs):
        """Gets all firewall_groups and rules on a project."""
        fwg_list = []
        for fwg in self.firewall_db.get_firewall_groups(context):
            fwg_with_rules =\
                self.firewall_db.make_firewall_group_dict_with_rules(
                    context, fwg['id'])
            if fwg['status'] == nl_constants.PENDING_DELETE:
                fwg_with_rules['add-port-ids'] = []
                fwg_with_rules['del-port-ids'] = (
                    self.firewall_db.get_ports_in_firewall_group(
                        context, fwg['id']))
            else:
                fwg_with_rules['add-port-ids'] = (
                    self.firewall_db.get_ports_in_firewall_group(
                        context, fwg['id']))
                fwg_with_rules['del-port-ids'] = []
            fwg_list.append(fwg_with_rules)
        return fwg_list

    @log_helpers.log_method_call
    def get_projects_with_firewall_groups(self, context, **kwargs):
        """Get all projects that have firewall_groups."""
        ctx = neutron_context.get_admin_context()
        fwg_list = self.firewall_db.get_firewall_groups(ctx)
        fwg_project_list = list(set(fwg['tenant_id'] for fwg in fwg_list))
        return fwg_project_list

    @log_helpers.log_method_call
    def get_firewall_group_for_port(self, context, **kwargs):
        """Get firewall_group is associated with a port."""
        ctx = context.elevated()
        # Only one Firewall Group can be associated to a port at a time
        fwg_port_binding = self.firewall_db.get_firewall_groups(
            ctx, filters={'ports': [kwargs.get('port_id')]})
        if len(fwg_port_binding) != 1:
            return
        fwg = fwg_port_binding[0]

        fwg['ingress_rule_list'] = []
        for rule_id in self.firewall_db.get_firewall_policy(
                context, fwg['ingress_firewall_policy_id'],
                fields=['firewall_rules'])['firewall_rules']:
            fwg['ingress_rule_list'].append(
                self.firewall_db.get_firewall_rule(context, rule_id))
        fwg['egress_rule_list'] = []
        for rule_id in self.firewall_db.get_firewall_policy(
                context, fwg['egress_firewall_policy_id'],
                fields=['firewall_rules'])['firewall_rules']:
            fwg['egress_rule_list'].append(
                self.firewall_db.get_firewall_rule(context, rule_id))
        return fwg


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API"""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = neutron_rpc.get_client(target)

    def create_firewall_group(self, context, firewall_group):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_firewall_group',
                   firewall_group=firewall_group, host=self.host)

    def update_firewall_group(self, context, firewall_group):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_firewall_group',
                   firewall_group=firewall_group, host=self.host)

    def delete_firewall_group(self, context, firewall_group):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_firewall_group',
                   firewall_group=firewall_group, host=self.host)


class FirewallAgentDriver(driver_api.FirewallDriverDB,
                          driver_api.FirewallDriverRPCMixin):
    """Firewall driver to implement agent messages and callback methods

    Implement RPC Firewall v2 API and callback methods for agents based on
    Neutron DB model.
    """

    def __init__(self, service_plugin):
        super(FirewallAgentDriver, self).__init__(service_plugin)
        self.agent_rpc = FirewallAgentApi(constants.FW_AGENT, cfg.CONF.host)

    def start_rpc_listener(self):
        self.endpoints = [FirewallAgentCallbacks(self.firewall_db)]
        self.rpc_connection = neutron_rpc.Connection()
        self.rpc_connection.create_consumer(constants.FIREWALL_PLUGIN,
                                            self.endpoints, fanout=False)
        return self.rpc_connection.consume_in_threads()

    def _rpc_update_firewall_group(self, context, fwg_id):
        status_update = {"status": nl_constants.PENDING_UPDATE}
        self.update_firewall_group(context, fwg_id, status_update)
        fwg_with_rules = self.firewall_db.make_firewall_group_dict_with_rules(
            context, fwg_id)
        # this is triggered on an update to fwg rule or policy, no
        # change in associated ports.
        fwg_with_rules['add-port-ids'] = \
            self.firewall_db.get_ports_in_firewall_group(context, fwg_id)
        fwg_with_rules['del-port-ids'] = []
        fwg_with_rules['port_details'] = self._get_fwg_port_details(
            context, fwg_with_rules['add-port-ids'])
        self.agent_rpc.update_firewall_group(context, fwg_with_rules)

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

        if (not ports or (not firewall_group['ingress_firewall_policy_id'] and
                not firewall_group['egress_firewall_policy_id'])):
            # no messaging to agent needed and fw needs to go to INACTIVE state
            # as no associated ports and/or no policy configured.
            status = nl_constants.INACTIVE
        else:
            status = (nl_constants.CREATED if cfg.CONF.router_distributed
                      else nl_constants.PENDING_CREATE)
        firewall_group['status'] = status

    def create_firewall_group_postcommit(self, context, firewall_group):
        if firewall_group['status'] != nl_constants.INACTIVE:
            fwg_with_rules =\
                self.firewall_db.make_firewall_group_dict_with_rules(
                    context, firewall_group['id'])
            fwg_with_rules['add-port-ids'] = firewall_group['ports']
            fwg_with_rules['del-ports-id'] = []
            fwg_with_rules['port_details'] = self._get_fwg_port_details(
                context, firewall_group['ports'])
            self.agent_rpc.create_firewall_group(context, fwg_with_rules)

    def delete_firewall_group_precommit(self, context, firewall_group):
        if firewall_group['status'] == nl_constants.ACTIVE:
            raise f_exc.FirewallGroupInUse(firewall_id=firewall_group['id'])
        elif firewall_group['status'] != nl_constants.INACTIVE:
            # Firewall group is in inconsistent state, remove it
            return
        if not firewall_group['ports']:
            # No associated port, can safety remove it
            return

        # Need to prevent agent to delete the firewall group before delete it
        self.firewall_db.update_firewall_group_status(
            context, firewall_group['id'], nl_constants.PENDING_DELETE)
        firewall_group['status'] = nl_constants.PENDING_DELETE

        fwg_with_rules = self.firewall_db.make_firewall_group_dict_with_rules(
            context, firewall_group['id'])
        fwg_with_rules['del-port-ids'] = firewall_group['ports']
        fwg_with_rules['add-port-ids'] = []
        # Reflect state change in fwg_with_rules
        fwg_with_rules['status'] = nl_constants.PENDING_DELETE
        fwg_with_rules['port_details'] = self._get_fwg_port_details(
            context, fwg_with_rules['del-port-ids'])
        self.agent_rpc.delete_firewall_group(context, fwg_with_rules)

    def _need_pending_update(self, old_firewall_group, new_firewall_group):
        port_updated = (set(new_firewall_group['ports']) !=
                        set(old_firewall_group['ports']))
        policies_updated = (
            new_firewall_group['ingress_firewall_policy_id'] !=
            old_firewall_group['ingress_firewall_policy_id'] or
            new_firewall_group['egress_firewall_policy_id'] !=
            old_firewall_group['egress_firewall_policy_id']
        )
        if (port_updated and
                (new_firewall_group['ingress_firewall_policy_id'] or
                 new_firewall_group['egress_firewall_policy_id'])):
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

        fwg_with_rules = self.firewall_db.make_firewall_group_dict_with_rules(
            context, new_firewall_group['id'])

        # determine ports to add fw to and del from
        fwg_with_rules['add-port-ids'] = list(
            set(new_firewall_group['ports']) - set(old_firewall_group['ports'])
        )
        fwg_with_rules['del-port-ids'] = list(
            set(old_firewall_group['ports']) - set(new_firewall_group['ports'])
        )

        # last-port drives agent to ack with status to set state to INACTIVE
        fwg_with_rules['last-port'] = not (
            set(new_firewall_group['ports']) - set(old_firewall_group['ports'])
        )

        LOG.debug("update_firewall_group %s: Add Ports: %s, Del Ports: %s",
            new_firewall_group['id'],
            fwg_with_rules['add-port-ids'],
            fwg_with_rules['del-port-ids'])

        fwg_with_rules['port_details'] = self._get_fwg_port_details(
            context, fwg_with_rules['del-port-ids'])
        fwg_with_rules['port_details'].update(self._get_fwg_port_details(
            context, fwg_with_rules['add-port-ids']))

        if (new_firewall_group['name'] == constants.DEFAULT_FWG and
                len(fwg_with_rules['add-port-ids']) == 1 and
                not fwg_with_rules['del-port-ids']):
            port_id = fwg_with_rules['add-port-ids'][0]
            if (fwg_with_rules['port_details'][port_id].get('status') !=
                    nl_constants.ACTIVE):
                # If port not yet active, just associate to default firewall
                # group. When agent will set it to UP, it'll found FG
                # association and enforce default policies
                return
        # Warn agents Firewall Group port list updated
        self.agent_rpc.update_firewall_group(context, fwg_with_rules)

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
