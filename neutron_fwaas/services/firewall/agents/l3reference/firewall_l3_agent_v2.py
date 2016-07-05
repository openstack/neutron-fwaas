# Copyright (c) 2016
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

from neutron.agent.l3 import agent
from neutron.agent.linux import ip_lib
from neutron import context
from neutron.plugins.common import constants as n_const
from neutron_fwaas.common import fwaas_constants as f_const
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas._i18n import _, _LE
from neutron_fwaas.extensions import firewall as fw_ext
from neutron_fwaas.services.firewall.agents import firewall_agent_api as api
from neutron_fwaas.services.firewall.agents import firewall_service

LOG = logging.getLogger(__name__)


class FWaaSL3PluginApi(api.FWaaSPluginApiMixin):
    """Agent side of the FWaaS agent-to-plugin RPC API."""
    def __init__(self, topic, host):
        super(FWaaSL3PluginApi, self).__init__(topic, host)

    def get_firewall_groups_for_project(self, context, **kwargs):
        """Fetches a project's firewall groups from the plugin."""
        LOG.debug("Fetch firewall groups from plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_firewall_groups_for_project',
                host=self.host)

    def get_projects_with_firewall_groups(self, context, **kwargs):
        """Fetches from the plugin all projects that have firewall groups
           configured.
        """
        LOG.debug("Fetch from plugin projects that have firewall groups "
                  "configured")
        cctxt = self.client.prepare()
        return cctxt.call(context,
                          'get_projects_with_firewall_groups', host=self.host)

    def firewall_group_deleted(self, context, fwg_id, **kwargs):
        """Notifies the plugin that a firewall group has been deleted."""
        LOG.debug("Notify plugin that firewall group has been deleted")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'firewall_group_deleted', fwg_id=fwg_id,
                host=self.host)

    def set_firewall_group_status(self, context, fwg_id, status, **kwargs):
        """Sets firewall group's status on the plugin."""
        LOG.debug("Set firewall groups from plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_firewall_group_status',
                fwg_id=fwg_id, status=status, host=self.host)


class FWaaSL3AgentRpcCallback(api.FWaaSAgentRpcCallbackMixin):
    """FWaaS agent support to be used by neutron's L3 agent."""

    def __init__(self, host, conf):
        LOG.debug("Initializing firewall group agent")
        self.neutron_service_plugins = None
        self.conf = conf
        self.fwaas_enabled = cfg.CONF.fwaas.enabled

        # None means l3-agent has no information on the server
        # configuration due to the lack of RPC support.
        if self.neutron_service_plugins is not None:
            fwaas_plugin_configured = (n_const.FIREWALL
                                       in self.neutron_service_plugins)
            if fwaas_plugin_configured and not self.fwaas_enabled:
                msg = _("FWaaS plugin is configured in the server side, but "
                        "FWaaS is disabled in L3-agent.")
                LOG.error(msg)
                raise SystemExit(1)
            self.fwaas_enabled = self.fwaas_enabled and fwaas_plugin_configured

        if self.fwaas_enabled:
            # NOTE: Temp location for creating service and loading driver
            self.fw_service = firewall_service.FirewallService()
            self.fwaas_driver = self.fw_service.load_device_drivers()

        self.services_sync_needed = False
        self.fwplugin_rpc = FWaaSL3PluginApi(f_const.FIREWALL_PLUGIN,
                                             host)
        super(FWaaSL3AgentRpcCallback, self).__init__(host=host)

    @property
    def _local_namespaces(self):
        root_ip = ip_lib.IPWrapper()
        local_ns_list = root_ip.get_namespaces()
        return local_ns_list

    def _has_port_insertion_fields(self, firewall_group):
        """The presence of the 'add-port-ids' key in the firewall group dict
           shows we are using the current version of the plugin. If this key
           is absent, we are in an upgrade and message is from an older
           version of the plugin.
        """
        return 'add-port-ids' in firewall_group

    def _get_firewall_group_ports(self, context, firewall_group,
            to_delete=False, require_new_plugin=False):
        """Returns in-namespace ports, either from firewall group dict if newer
           version of plugin or from project routers otherwise.

           NOTE: Vernacular move from "tenant" to "project" doesn't yet appear
           as a key in router or firewall group objects.
        """
        fwg_port_ids = []
        if self._has_port_insertion_fields(firewall_group):
            if to_delete:
                fwg_port_ids = firewall_group['del-port-ids']
            else:
                fwg_port_ids = firewall_group['add-port-ids']
        elif not require_new_plugin:
            routers = [self.router_info[rid] for rid in self.router_info]
            for router in routers:
                if router.router['tenant_id'] == firewall_group['tenant_id']:
                    fwg_port_ids.extend([p['id'] for p in
                            router.internal_ports])

        # Return in-namespace port objects.
        return self._get_in_ns_ports(fwg_port_ids)

    def _get_in_ns_ports(self, port_ids):
        """Returns port objects in the local namespace, along with their
           router_info.
        """
        in_ns_ports = []
        if port_ids:
            for router_id in self.router_info:
                # For routers without an interface - get_routers returns
                # the router - but this is not yet populated in router_info
                router_info = self.router_info[router_id]
                if router_info.ns_name not in self._local_namespaces:
                    continue
                in_ns_router_port_ids = []
                for port in router_info.internal_ports:
                    if port['id'] in port_ids:
                        in_ns_router_port_ids.append(port['id'])
                if in_ns_router_port_ids:
                    in_ns_ports.append((router_info, in_ns_router_port_ids))
        return in_ns_ports

    def _invoke_driver_for_sync_from_plugin(self, ctx, port, firewall_group):
        """Calls the FWaaS driver's delete_firewall_group method if firewall
           group has status of PENDING_DELETE; calls driver's
           update_firewall_group method for all other statuses. Both of these
           methods are idempotent.
        """
        if firewall_group['status'] == n_const.PENDING_DELETE:
            try:
                self.fwaas_driver.delete_firewall_group(
                        self.conf.agent_mode, [port], firewall_group)
                self.fwplugin_rpc.firewall_group_deleted(
                    ctx, firewall_group['id'])
            except fw_ext.FirewallInternalDriverError:
                msg = _LE("FWaaS driver error on %(status)s "
                          "for firewall group: %(fwg_id)s")
                LOG.exception(msg, {'status': firewall_group['status'],
                                    'fwg_id': firewall_group['id']})
                self.fwplugin_rpc.set_firewall_group_status(
                        ctx, firewall_group['id'], n_const.ERROR)
        else:  # PENDING_UPDATE, PENDING_CREATE, ...

            # Prepare firewall group status to return to plugin; may be
            # overwritten if call to driver fails.
            if firewall_group['admin_state_up']:
                status = n_const.ACTIVE
            else:
                status = n_const.DOWN

            # Call the driver.
            try:
                self.fwaas_driver.update_firewall_group(
                    self.conf.agent_mode, [port], firewall_group)
            except fw_ext.FirewallInternalDriverError:
                msg = _LE("FWaaS driver error on %(status)s for firewall "
                          "group: "
                      "%(fwg_id)s")
                LOG.exception(msg, {'status': firewall_group['status'],
                                    'fwg_id': firewall_group['id']})
                status = n_const.ERROR

            # Notify the plugin of firewall group's status.
            self.fwplugin_rpc.set_firewall_group_status(
                ctx, firewall_group['id'], status)

    def _process_router_add(self, new_router):
        """If the new router is in the local namespace, queries the plugin to
           get the firewall groups for the project in question and then sees if
           the router has any ports for any firewall group that is configured
           for that project. If so, installs firewall group rules on the
           requested ports on this router.
        """
        LOG.debug("Process router add, router_id: %s.",
                  new_router.router['id'])
        router_id = new_router.router['id']
        if router_id not in self.router_info or \
                self.router_info[router_id].ns_name not in \
                self._local_namespaces:
            return

        # Get the firewall groups for the new router's project.
        # NOTE: Vernacular move from "tenant" to "project" doesn't yet appear
        # as a key in router or firewall group objects.
        ctx = context.Context('', new_router.router['tenant_id'])
        fwg_list = self.fwplugin_rpc.get_firewall_groups_for_project(ctx)

        # Apply a firewall group, as requested, to ports on the new router.
        for port in new_router.router.internal_ports:
            for firewall_group in fwg_list:
                if (self._has_port_insertion_fields(firewall_group) and
                        (port['id'] in firewall_group['add-port-ids'] or
                        port['id'] in firewall_group['del-port-ids'])):
                    self._invoke_driver_for_sync_from_plugin(ctx, port,
                            firewall_group)
                    # A port can have at most one firewall group.
                    break

    def process_router_add(self, new_router):
        """Handles agent restart and router add. Fetches firewall groups from
        plugin and updates driver.
        """
        if not self.fwaas_enabled:
            return

        try:
            self._process_router_add(new_router)
        except Exception:
            LOG.exception(_LE("FWaaS RPC info call failed for %s"),
                    new_router.router['id'])
            self.services_sync_needed = True

    def process_services_sync(self, ctx):
        """Syncs with plugin and applies the sync data.
        """

        if not self.services_sync_needed or not self.fwaas_enabled:
            return

        try:
            # Fetch from the plugin the list of projects with firewall groups.
            project_ids = \
                    self.fwplugin_rpc.get_projects_with_firewall_groups(ctx)
            LOG.debug("Projects with firewall groups: %s",
                      ', '.join(project_ids))
            for project_id in project_ids:
                ctx = context.Context('', project_id)
                fwg_list = \
                    self.fwplugin_rpc.get_firewall_groups_for_project(ctx)
                for firewall_group in fwg_list:
                    if firewall_group['status'] == n_const.PENDING_DELETE:
                        self.delete_firewall_group(ctx, firewall_group,
                                                   self.host)
                    # No need to apply sync data for ACTIVE firewall group.
                    elif firewall_group['status'] != n_const.ACTIVE:
                        self.update_firewall_group(ctx, firewall_group,
                                                   self.host)
            self.services_sync_needed = False
        except Exception:
            LOG.exception(_LE("Failed FWaaS process services sync."))
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def create_firewall_group(self, context, firewall_group, host):
        """Handles RPC from plugin to create a firewall group.
        """

        # Get the in-namespace ports to which to add the firewall group.
        ports_for_fwg = self._get_firewall_group_ports(context, firewall_group)

        if not ports_for_fwg:
            return

        LOG.debug("Create firewall group %(fwg_id)s on ports: %(ports)s"
                % {'fwg_id': firewall_group['id'],
                   'ports': ', '.join([p for ri_ports in ports_for_fwg
                            for p in ri_ports[1]])})

        # Set firewall group status; will be overwritten if call to driver
        # fails.
        if firewall_group['admin_state_up']:
            status = n_const.ACTIVE
        else:
            status = n_const.DOWN

        # Call the driver.
        try:
            self.fwaas_driver.create_firewall_group(self.conf.agent_mode,
                                                    ports_for_fwg,
                                                    firewall_group)
        except fw_ext.FirewallInternalDriverError:
            msg = _LE("FWaaS driver error in create_firewall_group "
                      "for firewall group: %(fwg_id)s")
            LOG.exception(msg, {'fwg_id': firewall_group['id']})
            status = n_const.ERROR

        # Send firewall group's status to plugin.
        try:
            self.fwplugin_rpc.set_firewall_group_status(context,
                    firewall_group['id'], status)
        except Exception:
            msg = _LE("FWaaS RPC failure in create_firewall_group "
                      "for firewall group: %(fwg_id)s")
            LOG.exception(msg, {'fwg_id': firewall_group['id']})
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def update_firewall_group(self, context, firewall_group, host):
        """Handles RPC from plugin to update a firewall group.
        """

        # Initialize firewall group status.
        status = ""

        # Get the list of in-namespace ports from which to delete the firewall
        # group.
        ports_for_fwg = self._get_firewall_group_ports(context, firewall_group,
                to_delete=True, require_new_plugin=True)

        # Remove firewall group from ports if requested.
        if ports_for_fwg:
            fw_ports = [p for ri_ports in ports_for_fwg for p in ri_ports[1]]
            LOG.debug("Update (delete) firewall group %(fwg_id)s on ports: "
                    "%(ports)s" % {'fwg_id': firewall_group['id'],
                    'ports': ', '.join(fw_ports)})

            # Set firewall group's status; will be overwritten if call to
            # driver fails.

            if firewall_group['admin_state_up']:
                status = n_const.ACTIVE
                if firewall_group['last-port']:
                    status = n_const.INACTIVE
            else:
                status = n_const.DOWN

            # Call the driver.
            try:
                self.fwaas_driver.delete_firewall_group(self.conf.agent_mode,
                                                        ports_for_fwg,
                                                        firewall_group)
            except fw_ext.FirewallInternalDriverError:
                msg = _LE("FWaaS driver error in update_firewall_group "
                          "(add) for firewall group: %s")
                LOG.exception(msg, firewall_group['id'])
                status = n_const.ERROR

        # Handle the add router and/or rule, policy, firewall group attribute
        # updates.
        if status not in (n_const.ERROR, n_const.INACTIVE):
            ports_for_fwg = self._get_firewall_group_ports(context,
                    firewall_group)
            if ports_for_fwg:

                LOG.debug("Update (create) firewall group %(fwg_id)s on "
                          "ports: %(ports)s" % {'fwg_id': firewall_group['id'],
                                       'ports': ', '.join(fw_ports)})

                # Set firewall group status, which will be overwritten if call
                # to driver fails.
                if firewall_group['admin_state_up']:
                    status = n_const.ACTIVE
                else:
                    status = n_const.DOWN

                # Call the driver.
                try:
                    self.fwaas_driver.update_firewall_group(
                            self.conf.agent_mode, ports_for_fwg,
                            firewall_group)
                except fw_ext.FirewallInternalDriverError:
                    msg = _LE("FWaaS driver error in update_firewall_group "
                              "for firewall group: %s")
                    LOG.exception(msg, firewall_group['id'])
                    status = n_const.ERROR
            else:
                status = n_const.INACTIVE

        # Return status to plugin.
        try:
            self.fwplugin_rpc.set_firewall_group_status(context,
                    firewall_group['id'], status)
        except Exception:
            LOG.exception(_LE("FWaaS RPC failure in update_firewall_group "
                              "for firewall group: %(fwg_id)s"),
                    {'fwg_id': firewall_group['id']})
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def delete_firewall_group(self, context, firewall_group, host):
        """Handles RPC from plugin to delete a firewall group.
        """

        ports_for_fwg = self._get_firewall_group_ports(context, firewall_group,
                                                       to_delete=True)

        if not ports_for_fwg:
            return

        fw_ports = [p for ri_ports in ports_for_fwg for p in ri_ports[1]]
        LOG.debug("Delete firewall group %(fwg_id)s on ports: %(ports)s"
                % {'fwg_id': firewall_group['id'],
                   'ports': ', '.join(fw_ports)})

        # Set the firewall group's status to return to plugin; status may be
        # overwritten if call to driver fails.
        if firewall_group['admin_state_up']:
            status = n_const.ACTIVE
        else:
            status = n_const.DOWN
        try:
            self.fwaas_driver.delete_firewall_group(self.conf.agent_mode,
                                                    ports_for_fwg,
                                                    firewall_group)
        # Call the driver.
        except fw_ext.FirewallInternalDriverError:
            LOG.exception(_LE("FWaaS driver error in delete_firewall_group "
                          "for firewall group: %(fwg_id)s"),
                      {'fwg_id': firewall_group['id']})
            status = n_const.ERROR

        # Notify plugin of deletion or return firewall group's status to
        # plugin, as appopriate.
        try:
            if status in [n_const.ACTIVE, n_const.DOWN]:
                self.fwplugin_rpc.firewall_group_deleted(context,
                                                         firewall_group['id'])
            else:
                self.fwplugin_rpc.set_firewall_group_status(context,
                        firewall_group['id'], status)
        except Exception:
            LOG.exception(_LE("FWaaS RPC failure in delete_firewall_group "
                              "for firewall group: %(fwg_id)s"),
                    {'fwg_id': firewall_group['id']})
            self.services_sync_needed = True


class L3WithFWaaS(FWaaSL3AgentRpcCallback, agent.L3NATAgentWithStateReport):

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        super(L3WithFWaaS, self).__init__(host=self.conf.host, conf=self.conf)
