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

from neutron_lib.plugins import directory

from neutron.common import rpc as n_rpc
from neutron import context as neutron_context
from neutron_lib import constants as nl_constants
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas._i18n import _LI
from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.db.firewall.v2 import firewall_db_v2
from neutron_fwaas.extensions import firewall_v2 as fw_ext


LOG = logging.getLogger(__name__)


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
        LOG.debug("Setting firewall_group %s to status: %s" % (
            fwg_id, status))
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
            LOG.debug("firewall %s status set: %s" % (fwg_id, to_update))
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
        except fw_ext.FirewallGroupNotFound:
            LOG.info(_LI('Firewall group %s already deleted'), fwg_id)
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


class FirewallPluginV2(
    firewall_db_v2.Firewall_db_mixin_v2):
    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db_v2.Firewall_db_mixin_v2.
    """
    supported_extension_aliases = ["fwaas_v2"]
    path_prefix = fw_ext.FIREWALL_PREFIX

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
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
            raise fw_ext.FirewallGroupInPendingState(firewall_id=fwg_id,
                                                pending_state=fwg['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            ing_fwg_ids, eg_fwg_ids = self._get_fwgs_with_policy(context,
                firewall_policy_id)
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
            if port_db['device_owner'] != "network:router_interface":
                raise fw_ext.FirewallGroupPortInvalid(port_id=port_id)
            if port_db['tenant_id'] != tenant_id:
                raise fw_ext.FirewallGroupPortInvalidProject(
                    port_id=port_id, tenant_id=port_db['tenant_id'])
        return

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
                firewall_group['firewall_group']['tenant_id'],
                fwg_ports)
            self._validate_if_firewall_group_on_ports(context, fwg_ports)

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
        fwg_with_rules['del-ports-ids'] = []

        self.agent_rpc.create_firewall_group(context, fwg_with_rules)

        return fwg

    def update_firewall_group(self, context, id, firewall_group):
        LOG.debug("update_firewall_group() called on firewall_group %s", id)

        self._ensure_update_firewall_group(context, id)

        # TODO(sridar): need closure on status when no policy associated.
        fwg_current_ports = self._get_ports_in_firewall_group(context, id)
        if 'ports' in firewall_group['firewall_group']:
            fwg_ports = firewall_group['firewall_group']['ports']
            if fwg_ports == []:
                # This indicates that user is indicating no ports.
                fwg_new_ports = []
            else:
                self._validate_ports_for_firewall_group(
                    context, context.tenant_id, fwg_ports)
                self._validate_if_firewall_group_on_ports(
                    context, fwg_ports, id)
                fwg_new_ports = fwg_ports
        else:
            # ports keyword not specified for update pick up
            # existing ports.
            fwg_new_ports = self._get_ports_in_firewall_group(context, id)

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

        self.agent_rpc.update_firewall_group(context, fwg_with_rules)

        return fwg

    def delete_db_firewall_group_object(self, context, id):
        super(FirewallPluginV2, self).delete_firewall_group(context, id)

    def delete_firewall_group(self, context, id):
        LOG.debug("delete_firewall_group() called on firewall_group %s", id)
        fw_with_rules = (
            self._make_firewall_group_dict_with_rules(context, id))
        fw_with_rules['del-port-ids'] = self._get_ports_in_firewall_group(
            context, id)
        fw_with_rules['add-port-ids'] = []
        if not fw_with_rules['del-port-ids']:
            # no ports, no need to talk to the agent
            self.delete_db_firewall_group_object(context, id)
        else:
            status = {"firewall_group":
                     {"status": nl_constants.PENDING_DELETE}}
            super(FirewallPluginV2, self).update_firewall_group(
                context, id, status)
            # Reflect state change in fw_with_rules
            fw_with_rules['status'] = status['firewall_group']['status']
            self.agent_rpc.delete_firewall_group(context, fw_with_rules)

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
