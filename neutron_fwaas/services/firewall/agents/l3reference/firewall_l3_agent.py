# Copyright (c) 2013 OpenStack Foundation.
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
from neutron_lib.agent import l3_extension
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v1 as fw_ext
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.common import resources as f_resources
from neutron_fwaas.services.firewall.agents import firewall_agent_api as api
from neutron_fwaas.services.firewall.agents import firewall_service

LOG = logging.getLogger(__name__)

#TODO(njohnston): There needs to be some extrapolation of the common code
# between this module and firewall_l3_agent_v2.py.


class FWaaSL3PluginApi(api.FWaaSPluginApiMixin):
    """Agent side of the FWaaS agent to FWaaS Plugin RPC API."""
    def __init__(self, topic, host):
        super(FWaaSL3PluginApi, self).__init__(topic, host)

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Get the Firewalls with rules from the Plugin to send to driver."""
        LOG.debug("Retrieve Firewall with rules from Plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_firewalls_for_tenant', host=self.host)

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Get all Tenants that have Firewalls configured from plugin."""
        LOG.debug("Retrieve Tenants with Firewalls configured from Plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context,
                          'get_tenants_with_firewalls', host=self.host)


class FWaaSL3AgentExtension(l3_extension.L3AgentExtension):
    """FWaaS Agent support to be used by Neutron L3 agent."""

    SUPPORTED_RESOURCE_TYPES = [f_resources.FIREWALL_GROUP,
                                f_resources.FIREWALL_POLICY,
                                f_resources.FIREWALL_RULE]

    def initialize(self, connection, driver_type):
        self._register_rpc_consumers(connection)

    def consume_api(self, agent_api):
        LOG.debug("FWaaS consume_api call occurred with %s", agent_api)
        self.agent_api = agent_api

    def _register_rpc_consumers(self, connection):
        #TODO(njohnston): Add RPC consumer connection loading here.
        pass

    def start_rpc_listeners(self, conf):
        self.endpoints = [self]

        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(
            fwaas_constants.FW_AGENT, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def __init__(self, host, conf):
        LOG.debug("Initializing firewall agent")
        self.agent_api = None
        self.neutron_service_plugins = None
        self.conf = conf
        self.fwaas_enabled = cfg.CONF.fwaas.enabled
        self.start_rpc_listeners(conf)

        # None means l3-agent has no information on the server
        # configuration due to the lack of RPC support.
        if self.neutron_service_plugins is not None:
            fwaas_plugin_configured = (fwaas_constants.FIREWALL
                                       in self.neutron_service_plugins)
            if fwaas_plugin_configured and not self.fwaas_enabled:
                msg = ("FWaaS plugin is configured in the server side, but "
                       "FWaaS is disabled in L3-agent.")
                LOG.error(msg)
                raise SystemExit(1)
            self.fwaas_enabled = self.fwaas_enabled and fwaas_plugin_configured

        if self.fwaas_enabled:
            # NOTE: Temp location for creating service and loading driver
            self.fw_service = firewall_service.FirewallService()
            self.fwaas_driver = self.fw_service.load_device_drivers()
        self.services_sync_needed = False
        # setup RPC to msg fwaas plugin
        self.fwplugin_rpc = FWaaSL3PluginApi(fwaas_constants.FIREWALL_PLUGIN,
                                             host)

    def _has_router_insertion_fields(self, fw):
        return 'add-router-ids' in fw

    def _get_router_ids_for_fw(self, context, fw, to_delete=False):
        """Return the router_ids either from fw dict or tenant routers."""
        if self._has_router_insertion_fields(fw):
            # it is a new version of plugin
            return (fw['del-router-ids'] if to_delete
                    else fw['add-router-ids'])
        else:
            return [router['id'] for router in
                self.agent_api.get_routers_in_project(fw['tenant_id'])]

    def _get_routers_in_project(self, project_id):
        if self.agent_api is None:
            LOG.exception("FWaaS RPC call failed; L3 agent_api failure")
        return self.agent_api.get_routers_in_project(project_id)

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        return [ri for ri in self._get_routers_in_project(tenant_id)
                if ri.router_id in router_ids and
                self.agent_api.is_router_in_namespace(ri.router_id)]

    def _invoke_driver_for_sync_from_plugin(self, ctx, router_info_list, fw):
        """Invoke the delete driver method for status of PENDING_DELETE and
        update method for all other status to (re)apply on driver which is
        Idempotent.
        """
        if fw['status'] == nl_constants.PENDING_DELETE:
            try:
                self.fwaas_driver.delete_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                self.fwplugin_rpc.firewall_deleted(
                    ctx,
                    fw['id'])
            except fw_ext.FirewallInternalDriverError:
                LOG.error("Firewall Driver Error on fw state %(fwmsg)s "
                          "for fw: %(fwid)s",
                          {'fwmsg': fw['status'], 'fwid': fw['id']})
                self.fwplugin_rpc.set_firewall_status(
                    ctx,
                    fw['id'],
                    nl_constants.ERROR)
        else:
            # PENDING_UPDATE, PENDING_CREATE, ...
            try:
                self.fwaas_driver.update_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                if fw['admin_state_up']:
                    status = nl_constants.ACTIVE
                else:
                    status = nl_constants.DOWN
            except fw_ext.FirewallInternalDriverError:
                LOG.error("Firewall Driver Error on fw state %(fwmsg)s "
                          "for fw: %(fwid)s",
                          {'fwmsg': fw['status'], 'fwid': fw['id']})
                status = nl_constants.ERROR

            self.fwplugin_rpc.set_firewall_status(
                ctx,
                fw['id'],
                status)

    def _process_router_add(self, router):
        """On router add, get fw with rules from plugin and update driver."""
        LOG.debug("Process router add, router_id: '%s'", router['id'])
        router_ids = router['id']
        router_info_list = self._get_router_info_list_for_tenant(
            [router_ids],
            router['tenant_id'])
        if router_info_list:
            # Get the firewall with rules
            # for the tenant the router is on.
            ctx = context.Context('', router['tenant_id'])
            fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
            for fw in fw_list:
                if self._has_router_insertion_fields(fw):
                    # if router extension present apply only if router in fw
                    if (not (router_ids in fw['add-router-ids']) and
                        not (router_ids in fw['del-router-ids'])):
                        continue
                self._invoke_driver_for_sync_from_plugin(
                    ctx,
                    router_info_list,
                    fw)
                # router can be present only on one fw
                return

    def add_router(self, context, new_router):
        """On router add, get fw with rules from plugin and update driver.

        Handles agent restart, when a router is added, query the plugin to
        check if this router is in the router list for any firewall. If so
        install firewall rules on this router.
        """
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            self._process_router_add(new_router)
        except Exception:
            LOG.exception(
                "FWaaS RPC info call failed for '%s'.", new_router['id'])
            self.services_sync_needed = True

    def update_router(self, context, updated_router):
        """The update_router method is just a synonym for add_router"""
        self.add_router(context, updated_router)

    def delete_router(self, context, new_router):
        """Handles router deletion. There is basically nothing to do for this
        in the context of FWaaS with an IPTables driver; the namespace will
        already have been deleted, taking the IPTables rules with it.
        """
        #TODO(njohnston): When another firewall driver is implemented, look at
        # expanding this out so that the driver can handle deletion calls.
        pass

    def process_services_sync(self, ctx):
        if not self.services_sync_needed:
            return

        """On RPC issues sync with plugin and apply the sync data."""
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            # get the list of tenants with firewalls configured
            # from the plugin
            tenant_ids = self.fwplugin_rpc.get_tenants_with_firewalls(ctx)
            LOG.debug("Tenants with Firewalls: '%s'", tenant_ids)
            for tenant_id in tenant_ids:
                ctx = context.Context('', tenant_id)
                fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
                for fw in fw_list:
                    if fw['status'] == nl_constants.PENDING_DELETE:
                        self.delete_firewall(ctx, fw, self.host)
                    # no need to apply sync data for ACTIVE fw
                    elif fw['status'] != nl_constants.ACTIVE:
                        self.update_firewall(ctx, fw, self.host)
            self.services_sync_needed = False
        except Exception:
            LOG.exception("Failed fwaas process services sync")
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""

        router_ids = self._get_router_ids_for_fw(context, firewall)
        if not router_ids:
            return
        router_info_list = self._get_router_info_list_for_tenant(
            router_ids,
            firewall['tenant_id'])
        LOG.debug("Create: Add firewall on Router List: '%s'",
            [ri.router['id'] for ri in router_info_list])
        # call into the driver
        try:
            self.fwaas_driver.create_firewall(
                self.conf.agent_mode,
                router_info_list,
                firewall)
            if firewall['admin_state_up']:
                status = nl_constants.ACTIVE
            else:
                status = nl_constants.DOWN
        except fw_ext.FirewallInternalDriverError:
            LOG.error("Firewall Driver Error for create_firewall "
                      "for firewall: %s", firewall['id'])
            status = nl_constants.ERROR

        try:
            # send status back to plugin
            self.fwplugin_rpc.set_firewall_status(
                context,
                firewall['id'],
                status)
        except Exception:
            LOG.exception("FWaaS RPC failure in create_firewall "
                          "for firewall: %s", firewall['id'])
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def update_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to update a firewall."""

        status = ""
        if self._has_router_insertion_fields(firewall):
            # with the router_ids extension, we may need to delete and add
            # based on the list of routers. On the older version, we just
            # update (add) all routers on the tenant - delete not needed.
            router_ids = self._get_router_ids_for_fw(
                context, firewall, to_delete=True)
            if router_ids:
                router_info_list = self._get_router_info_list_for_tenant(
                    router_ids,
                    firewall['tenant_id'])
                # remove the firewall from this set of routers
                # but no ack sent yet, check if we need to add
                LOG.debug("Update: Delete firewall on Router List: '%s'",
                    [ri.router['id'] for ri in router_info_list])
                try:
                    self.fwaas_driver.delete_firewall(
                        self.conf.agent_mode,
                        router_info_list,
                        firewall)
                    if firewall['last-router']:
                        status = nl_constants.INACTIVE
                    elif firewall['admin_state_up']:
                        status = nl_constants.ACTIVE
                    else:
                        status = nl_constants.DOWN
                except fw_ext.FirewallInternalDriverError:
                    LOG.error(
                        "Firewall Driver Error for "
                        "update_firewall for firewall: %s", firewall['id'])
                    status = nl_constants.ERROR

        # handle the add router and/or rule, policy, firewall
        # attribute updates
        if status not in (nl_constants.ERROR, nl_constants.INACTIVE):
            router_ids = self._get_router_ids_for_fw(context, firewall)
            if router_ids or firewall['router_ids']:
                router_info_list = self._get_router_info_list_for_tenant(
                    router_ids + firewall['router_ids'],
                    firewall['tenant_id'])
                LOG.debug("Update: Add firewall on Router List: '%s'",
                    [ri.router['id'] for ri in router_info_list])
                # call into the driver
                try:
                    self.fwaas_driver.update_firewall(
                        self.conf.agent_mode,
                        router_info_list,
                        firewall)
                    if firewall['admin_state_up']:
                        status = nl_constants.ACTIVE
                    else:
                        status = nl_constants.DOWN
                except fw_ext.FirewallInternalDriverError:
                    LOG.error(
                        "Firewall Driver Error for "
                        "update_firewall for firewall: %s", firewall['id'])
                    status = nl_constants.ERROR
            else:
                status = nl_constants.INACTIVE
        try:
            # send status back to plugin
            self.fwplugin_rpc.set_firewall_status(
                context,
                firewall['id'],
                status)
        except Exception:
            LOG.exception("FWaaS RPC failure in update_firewall "
                          "for firewall: %s", firewall['id'])
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def delete_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to delete a firewall."""

        router_ids = self._get_router_ids_for_fw(
            context, firewall, to_delete=True)
        if router_ids:
            router_info_list = self._get_router_info_list_for_tenant(
                router_ids,
                firewall['tenant_id'])
            LOG.debug(
                "Delete firewall %(fw)s on routers: '%(routers)s'",
                {'fw': firewall['id'],
                 'routers': [ri.router['id'] for ri in router_info_list]})
            # call into the driver
            try:
                self.fwaas_driver.delete_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    firewall)
                if firewall['admin_state_up']:
                    status = nl_constants.ACTIVE
                else:
                    status = nl_constants.DOWN
            except fw_ext.FirewallInternalDriverError:
                LOG.error("Firewall Driver Error for delete_firewall "
                          "for firewall: %s", firewall['id'])
                status = nl_constants.ERROR

            try:
                # send status back to plugin
                if status in [nl_constants.ACTIVE, nl_constants.DOWN]:
                    self.fwplugin_rpc.firewall_deleted(context, firewall['id'])
                else:
                    self.fwplugin_rpc.set_firewall_status(
                        context,
                        firewall['id'],
                        status)
            except Exception:
                LOG.exception("FWaaS RPC failure in delete_firewall "
                              "for firewall: %s", firewall['id'])
                self.services_sync_needed = True

    def ha_state_change(self, context, data):
        pass


class L3WithFWaaS(FWaaSL3AgentExtension):

    def __init__(self, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        super(L3WithFWaaS, self).__init__(host=self.conf.host, conf=self.conf)
