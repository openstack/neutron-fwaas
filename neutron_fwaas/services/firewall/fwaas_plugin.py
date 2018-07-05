# Copyright 2013 Big Switch Networks, Inc.
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
from neutron import service
from neutron_lib.api.definitions import firewall as fw_ext
from neutron_lib.api import extensions
from neutron_lib import constants as nl_constants
from neutron_lib import context as neutron_context
from neutron_lib.exceptions import firewall_v1 as f_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas.common import fwaas_constants as f_const
from neutron_fwaas.db.firewall import firewall_db
from neutron_fwaas.db.firewall import firewall_router_insertion_db


LOG = logging.getLogger(__name__)


class FirewallCallbacks(object):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    def set_firewall_status(self, context, firewall_id, status, **kwargs):
        """Agent uses this to set a firewall's status."""
        LOG.debug("Setting firewall %s to status: %s", firewall_id, status)
        # Sanitize status first
        if status in (nl_constants.ACTIVE, nl_constants.DOWN,
                      nl_constants.INACTIVE):
            to_update = status
        else:
            to_update = nl_constants.ERROR
        # ignore changing status if firewall expects to be deleted
        # That case means that while some pending operation has been
        # performed on the backend, neutron server received delete request
        # and changed firewall status to PENDING_DELETE
        updated = self.plugin.update_firewall_status(
            context, firewall_id, to_update,
            not_in=(nl_constants.PENDING_DELETE,))
        if updated:
            LOG.debug("firewall %s status set: %s", firewall_id, to_update)
        return updated and to_update != nl_constants.ERROR

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug("firewall_deleted() called")
        try:
            with context.session.begin(subtransactions=True):
                fw_db = self.plugin._get_firewall(context, firewall_id)
                # allow to delete firewalls in ERROR state
                if fw_db.status in (nl_constants.PENDING_DELETE,
                                    nl_constants.ERROR):
                    self.plugin.delete_db_firewall_object(context, firewall_id)
                    return True
                else:
                    LOG.warning('Firewall %(fw)s unexpectedly deleted by '
                                'agent, status was %(status)s',
                                {'fw': firewall_id, 'status': fw_db.status})
                    fw_db.update({"status": nl_constants.ERROR})
                    return False
        except f_exc.FirewallNotFound:
            LOG.info('Firewall %s already deleted', firewall_id)
            return True

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        LOG.debug("get_firewalls_for_tenant() called")
        fw_list = []
        for fw in self.plugin.get_firewalls(context):
            fw_with_rules = self.plugin._make_firewall_dict_with_rules(
                context, fw['id'])
            if fw['status'] == nl_constants.PENDING_DELETE:
                fw_with_rules['add-router-ids'] = []
                fw_with_rules['del-router-ids'] = fw['router_ids']
            else:
                fw_with_rules['add-router-ids'] = fw['router_ids']
                fw_with_rules['del-router-ids'] = []
            fw_list.append(fw_with_rules)
        return fw_list

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        LOG.debug("get_tenants_with_firewalls() called")
        host = kwargs['host']
        ctx = neutron_context.get_admin_context()
        tenant_ids = self.plugin.get_firewall_tenant_ids_on_host(ctx, host)
        return tenant_ids


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def _prepare_rpc_client(self, host=None):
        if host:
            return self.client.prepare(server=host)
        else:
            # historical behaviour (RPC broadcast)
            return self.client.prepare(fanout=True)

    def create_firewall(self, context, firewall, host=None):
        cctxt = self._prepare_rpc_client(host)
        # TODO(blallau) host param is not used on agent side (to be removed)
        cctxt.cast(context, 'create_firewall', firewall=firewall,
                   host=self.host)

    def update_firewall(self, context, firewall, host=None):
        cctxt = self._prepare_rpc_client(host)
        # TODO(blallau) host param is not used on agent side (to be removed)
        cctxt.cast(context, 'update_firewall', firewall=firewall,
                   host=self.host)

    def delete_firewall(self, context, firewall, host=None):
        cctxt = self._prepare_rpc_client(host)
        # TODO(blallau) host param is not used on agent side (to be removed)
        cctxt.cast(context, 'delete_firewall', firewall=firewall,
                   host=self.host)


class FirewallPlugin(
    firewall_db.Firewall_db_mixin,
    firewall_router_insertion_db.FirewallRouterInsertionDbMixin):

    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas", "fwaasrouterinsertion"]
    path_prefix = fw_ext.API_PREFIX

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""

        self.agent_rpc = FirewallAgentApi(
            f_const.FW_AGENT,
            cfg.CONF.host
        )
        firewall_db.subscribe()

        rpc_worker = service.RpcWorker([self], worker_process_count=0)
        self.add_worker(rpc_worker)

    def start_rpc_listeners(self):
        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.Connection()
        self.conn.create_consumer(
            f_const.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _get_hosts_to_notify(self, context, router_ids):
        """Returns all hosts to send notification about firewall update"""
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        no_broadcast = (
            extensions.is_extension_supported(
                l3_plugin, nl_constants.L3_AGENT_SCHEDULER_EXT_ALIAS) and
            getattr(l3_plugin, 'get_l3_agents_hosting_routers', False))
        if no_broadcast:
            agents = l3_plugin.get_l3_agents_hosting_routers(
                context, router_ids, admin_state_up=True, active=True)
            return [a.host for a in agents]

        # NOTE(blallau): default: FirewallAgentAPI performs RPC broadcast
        return [None]

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": nl_constants.PENDING_UPDATE}}
        super(FirewallPlugin, self).update_firewall(context, firewall_id,
                                                    status_update)
        fw_with_rules = self._make_firewall_dict_with_rules(context,
                                                            firewall_id)
        # this is triggered on an update to fw rule or policy, no
        # change in associated routers.
        fw_update_rtrs = self.get_firewall_routers(context, firewall_id)
        fw_with_rules['add-router-ids'] = fw_update_rtrs
        fw_with_rules['del-router-ids'] = []

        hosts = self._get_hosts_to_notify(context, fw_update_rtrs)
        for host in hosts:
            self.agent_rpc.update_firewall(context, fw_with_rules,
                                           host=host)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._rpc_update_firewall(context, firewall_id)

    def _ensure_update_firewall(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [nl_constants.PENDING_CREATE,
                               nl_constants.PENDING_UPDATE,
                               nl_constants.PENDING_DELETE]:
            raise f_exc.FirewallInPendingState(firewall_id=firewall_id,
                                               pending_state=fwall['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy and 'firewall_list' in firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._ensure_update_firewall(context, firewall_id)

    def _ensure_update_firewall_rule(self, context, firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if 'firewall_policy_id' in fw_rule and fw_rule['firewall_policy_id']:
            self._ensure_update_firewall_policy(context,
                                                fw_rule['firewall_policy_id'])

    def _get_routers_for_create_firewall(self, tenant_id, context, firewall):
        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        if router_ids == nl_constants.ATTR_NOT_SPECIFIED:
            # old semantics router-ids keyword not specified pick up
            # all routers on tenant.
            l3_plugin = directory.get_plugin(plugin_constants.L3)
            ctx = neutron_context.get_admin_context()
            routers = l3_plugin.get_routers(ctx)
            router_ids = [
                router['id']
                for router in routers
                if router['tenant_id'] == tenant_id]
            # validation can still fail this if there is another fw
            # which is associated with one of these routers.
            self.validate_firewall_routers_not_in_use(context, router_ids)
            return router_ids
        else:
            if not router_ids:
                # This indicates that user specifies no routers.
                return []
            else:
                # some router(s) provided.
                self.validate_firewall_routers_not_in_use(context, router_ids)
                return router_ids

    def create_firewall(self, context, firewall):
        LOG.debug("create_firewall() called")

        fw_new_rtrs = self._get_routers_for_create_firewall(
            firewall['firewall']['tenant_id'], context, firewall)

        if not fw_new_rtrs:
            # no messaging to agent needed, and fw needs to go
            # to INACTIVE(no associated rtrs) state.
            status = nl_constants.INACTIVE
            fw = super(FirewallPlugin, self).create_firewall(
                context, firewall, status)
            fw['router_ids'] = []
            return fw
        else:
            fw = super(FirewallPlugin, self).create_firewall(
                context, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        fw_with_rtrs = {'fw_id': fw['id'],
                        'router_ids': fw_new_rtrs}
        self.set_routers_for_firewall(context, fw_with_rtrs)
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = []

        hosts = self._get_hosts_to_notify(context, fw_new_rtrs)
        for host in hosts:
            self.agent_rpc.create_firewall(context, fw_with_rules,
                                           host=host)
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.debug("update_firewall() called on firewall %s", id)

        self._ensure_update_firewall(context, id)
        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        fw_current_rtrs = fw_new_rtrs = self.get_firewall_routers(
            context, id)
        if router_ids is not None:
            if router_ids == []:
                # This indicates that user is indicating no routers.
                fw_new_rtrs = []
            else:
                self.validate_firewall_routers_not_in_use(
                    context, router_ids, id)
                fw_new_rtrs = router_ids
            self.update_firewall_routers(context, {'fw_id': id,
                'router_ids': fw_new_rtrs})

        if not fw_new_rtrs and not fw_current_rtrs:
            # no messaging to agent needed, and we need to continue
            # in INACTIVE state
            firewall['firewall']['status'] = nl_constants.INACTIVE
            fw = super(FirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = []
            return fw
        else:
            firewall['firewall']['status'] = nl_constants.PENDING_UPDATE
            fw = super(FirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        # determine rtrs to add fw to and del from
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = list(
            set(fw_current_rtrs).difference(set(fw_new_rtrs)))

        # last-router drives agent to ack with status to set state to INACTIVE
        fw_with_rules['last-router'] = not fw_new_rtrs

        LOG.debug("update_firewall %s: Add Routers: %s, Del Routers: %s",
            fw['id'],
            fw_with_rules['add-router-ids'],
            fw_with_rules['del-router-ids'])

        hosts = self._get_hosts_to_notify(context, list(
            set(fw_new_rtrs).union(set(fw_current_rtrs))))
        for host in hosts:
            self.agent_rpc.update_firewall(context, fw_with_rules,
                                           host=host)
        return fw

    def delete_db_firewall_object(self, context, id):
        super(FirewallPlugin, self).delete_firewall(context, id)

    def delete_firewall(self, context, id):
        LOG.debug("delete_firewall() called on firewall %s", id)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, id))
        fw_delete_rtrs = self.get_firewall_routers(context, id)
        fw_with_rules['del-router-ids'] = fw_delete_rtrs
        fw_with_rules['add-router-ids'] = []
        if not fw_with_rules['del-router-ids']:
            # no routers to delete on the agent side
            self.delete_db_firewall_object(context, id)
        else:
            status = {"firewall": {"status": nl_constants.PENDING_DELETE}}
            super(FirewallPlugin, self).update_firewall(context, id, status)
            # Reflect state change in fw_with_rules
            fw_with_rules['status'] = status['firewall']['status']
            hosts = self._get_hosts_to_notify(context, fw_delete_rtrs)
            if hosts:
                for host in hosts:
                    self.agent_rpc.delete_firewall(context, fw_with_rules,
                                                   host=host)
            else:
                # NOTE(blallau): we directly delete the firewall
                # if router is not associated to an agent
                self.delete_db_firewall_object(context, id)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug("update_firewall_policy() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("update_firewall_rule() called")
        self._ensure_update_firewall_rule(context, id)
        fwr = super(FirewallPlugin,
                    self).update_firewall_rule(context, id, firewall_rule)
        firewall_policy_id = fwr['firewall_policy_id']
        if firewall_policy_id:
            self._rpc_update_firewall_policy(context, firewall_policy_id)
        return fwr

    def _notify_firewall_updates(self, context, resource, update_info):
        notifier = n_rpc.get_notifier('network')
        notifier.info(context, resource, update_info)

    def insert_rule(self, context, id, rule_info):
        LOG.debug("insert_rule() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).insert_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        resource = 'firewall_policy.update.insert_rule'
        self._notify_firewall_updates(context, resource, rule_info)
        return fwp

    def remove_rule(self, context, id, rule_info):
        LOG.debug("remove_rule() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).remove_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        resource = 'firewall_policy.update.remove_rule'
        self._notify_firewall_updates(context, resource, rule_info)
        return fwp

    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug("fwaas get_firewalls() called")
        has_id_field = not fields or 'id' in fields
        if not has_id_field:
            fields = fields + ['id']
        fw_list = super(FirewallPlugin, self).get_firewalls(
            context, filters, fields)
        if not fields or 'router_ids' in fields:
            for fw in fw_list:
                fw['router_ids'] = self.get_firewall_routers(context, fw['id'])
        if not has_id_field:
            for fw in fw_list:
                del fw['id']
        return fw_list

    def get_firewall(self, context, id, fields=None):
        LOG.debug("fwaas get_firewall() called")
        res = super(FirewallPlugin, self).get_firewall(
                        context, id, fields)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        res['router_ids'] = fw_current_rtrs
        return res
