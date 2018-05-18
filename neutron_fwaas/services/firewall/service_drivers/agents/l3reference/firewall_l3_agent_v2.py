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

from neutron.agent.linux import ip_lib
from neutron.common import rpc as n_rpc
from neutron_lib.agent import l3_extension
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v2 as fw_ext
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.common import resources as f_resources
from neutron_fwaas.services.firewall.service_drivers.agents import\
    firewall_agent_api as api
from neutron_fwaas.services.firewall.service_drivers.agents import\
    firewall_service


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


class FWaaSL3AgentExtension(l3_extension.L3AgentExtension):
    """FWaaS agent extension."""

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

    def start_rpc_listeners(self, host, conf):
        self.endpoints = [self]

        self.conn = n_rpc.Connection()
        self.conn.create_consumer(
            fwaas_constants.FW_AGENT, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def __init__(self, host, conf):
        LOG.debug("Initializing firewall group agent")
        self.agent_api = None
        self.neutron_service_plugins = None
        self.conf = conf
        self.fwaas_enabled = cfg.CONF.fwaas.enabled

        self.start_rpc_listeners(host, conf)
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
        self.fwplugin_rpc = FWaaSL3PluginApi(fwaas_constants.FIREWALL_PLUGIN,
                                             host)
        super(FWaaSL3AgentExtension, self).__init__()

    @property
    def _local_namespaces(self):
        local_ns_list = ip_lib.list_network_namespaces()
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
            routers = self.agent_api.get_routers_in_project(
                    firewall_group['tenant_id'])
            for router in routers:
                if router.router['tenant_id'] == firewall_group['tenant_id']:
                    fwg_port_ids.extend([p['id'] for p in
                            router.internal_ports])

        # Return in-namespace port objects.
        return self._get_in_ns_ports(fwg_port_ids)

    def _get_in_ns_ports(self, port_ids):
        """Get ports in namespace by their IDs.

        Returns port objects in the local namespace, along with their
        router_info.

        :param port_ids: IDs of router ports (set, list or tuple)
        """
        in_ns_ports = {}  # This will be converted to a list later.
        if port_ids and self.agent_api:
            for port_id in port_ids:
                # This fetched router_info is guaranteed to be in_namespace.
                router_info = self.agent_api.get_router_hosting_port(port_id)
                if router_info:
                    if router_info in in_ns_ports:
                        in_ns_ports[router_info].append(port_id)
                    else:
                        in_ns_ports[router_info] = [port_id]
        return list(in_ns_ports.items())

    def _invoke_driver_for_sync_from_plugin(self, ctx, ports, firewall_group):
        """Call driver to sync firewall group.

        Calls the FWaaS driver's delete_firewall_group method if firewall
        group has status of PENDING_DELETE; calls driver's
        update_firewall_group method for all other statuses. Both of these
        methods are idempotent.

        :param ctx: RPC context
        :param ports: IDs of ports associated with a firewall group
                      (set, list or tuple)
        :param firewall_group: Dictionary describing the firewall group object

        """
        port_list = self._get_in_ns_ports(ports)
        if firewall_group['status'] == nl_constants.PENDING_DELETE:
            try:
                self.fwaas_driver.delete_firewall_group(
                    self.conf.agent_mode, port_list, firewall_group)
                self.fwplugin_rpc.firewall_group_deleted(
                    ctx, firewall_group['id'])
            except fw_ext.FirewallInternalDriverError:
                msg = ("FWaaS driver error on %(status)s "
                       "for firewall group: %(fwg_id)s")
                LOG.exception(msg, {'status': firewall_group['status'],
                                    'fwg_id': firewall_group['id']})
                self.fwplugin_rpc.set_firewall_group_status(
                    ctx, firewall_group['id'], nl_constants.ERROR)
        else:  # PENDING_UPDATE, PENDING_CREATE, ...

            # Prepare firewall group status to return to plugin; may be
            # overwritten if call to driver fails.
            if firewall_group['admin_state_up']:
                status = nl_constants.ACTIVE
            else:
                status = nl_constants.DOWN

            # Call the driver.
            try:
                self.fwaas_driver.update_firewall_group(
                    self.conf.agent_mode, port_list, firewall_group)
            except fw_ext.FirewallInternalDriverError:
                msg = ("FWaaS driver error on %(status)s for firewall "
                       "group: %(fwg_id)s")
                LOG.exception(msg, {'status': firewall_group['status'],
                                    'fwg_id': firewall_group['id']})
                status = nl_constants.ERROR

            # Notify the plugin of firewall group's status.
            self.fwplugin_rpc.set_firewall_group_status(
                ctx, firewall_group['id'], status)

    def _process_router_update(self, updated_router):
        """If a new or existing router in the local namespace is updated,
        queries the plugin to get the firewall groups for the project in
        question and then sees if the router has any ports for any firewall
        group that is configured for that project. If so, installs firewall
        group rules on the requested ports on this router.
        """
        LOG.debug("Process router update, router_id: %s  tenant: %s.",
                  updated_router['id'], updated_router['tenant_id'])
        router_id = updated_router['id']
        if not self.agent_api.is_router_in_namespace(router_id):
            return

        # Get the firewall groups for the new router's project.
        # NOTE: Vernacular move from "tenant" to "project" doesn't yet appear
        # as a key in router or firewall group objects.
        ctx = context.Context('', updated_router['tenant_id'])
        fwg_list = self.fwplugin_rpc.get_firewall_groups_for_project(ctx)

        if nl_constants.INTERFACE_KEY not in updated_router:
            return

        # Apply a firewall group, as requested, to ports on the new router.
        all_router_ports = set(
            p['id'] for p in updated_router[nl_constants.INTERFACE_KEY]
        )
        processed_ports = set()
        for firewall_group in fwg_list:
            if not self._has_port_insertion_fields(firewall_group):
                continue

            ports_to_process = (set(firewall_group['add-port-ids'] +
                                    firewall_group['del-port-ids']) &
                                all_router_ports)
            # A port can have at most one firewall group.
            port_ids_to_exclude = ports_to_process & processed_ports
            if port_ids_to_exclude:
                LOG.warning("Port(s) %s is associated with "
                            "more than one firewall group(s).",
                            port_ids_to_exclude)
                ports_to_process -= port_ids_to_exclude
            self._invoke_driver_for_sync_from_plugin(
                ctx, ports_to_process, firewall_group)
            processed_ports |= ports_to_process

    def add_router(self, context, new_router):
        """Handles agent restart and router add. Fetches firewall groups from
        plugin and updates driver.
        """
        if not self.fwaas_enabled:
            return

        try:
            self._process_router_update(new_router)
        except Exception:
            LOG.exception("FWaaS router add RPC info call failed for %s",
                          new_router['id'])
            self.services_sync_needed = True

    def update_router(self, context, updated_router):
        """Handles agent restart and router add. Fetches firewall groups from
        plugin and updates driver.
        """
        if not self.fwaas_enabled:
            return

        try:
            self._process_router_update(updated_router)
        except Exception:
            #TODO(njohnston): This repr should be replaced.
            LOG.exception(
                "FWaaS router update RPC info call failed for %s",
                repr(updated_router))
            self.services_sync_needed = True

    def delete_router(self, context, new_router):
        """Handles router deletion. There is basically nothing to do for this
        in the context of FWaaS with an IPTables driver; the namespace will
        already have been deleted, taking the IPTables rules with it.
        """
        #TODO(njohnston): When another firewall driver is implemented, look at
        # expanding this out so that the driver can handle deletion calls.
        pass

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
                    if firewall_group['status'] == nl_constants.PENDING_DELETE:
                        self.delete_firewall_group(ctx, firewall_group,
                                                   self.host)
                    # No need to apply sync data for ACTIVE firewall group.
                    elif firewall_group['status'] != nl_constants.ACTIVE:
                        self.update_firewall_group(ctx, firewall_group,
                                                   self.host)
            self.services_sync_needed = False
        except Exception:
            LOG.exception("Failed FWaaS process services sync.")
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def create_firewall_group(self, context, firewall_group, host):
        """Handles RPC from plugin to create a firewall group.
        """

        # Get the in-namespace ports to which to add the firewall group.
        ports_for_fwg = self._get_firewall_group_ports(context, firewall_group)
        if not ports_for_fwg:
            return

        LOG.debug("Create firewall group %(fwg_id)s on ports: %(ports)s",
                 {'fwg_id': firewall_group['id'],
                  'ports': ', '.join([p for ri_ports in ports_for_fwg
                                      for p in ri_ports[1]])})

        # Set firewall group status; will be overwritten if call to driver
        # fails.
        if firewall_group['admin_state_up']:
            status = nl_constants.ACTIVE
        else:
            status = nl_constants.DOWN

        # Call the driver.
        try:
            self.fwaas_driver.create_firewall_group(self.conf.agent_mode,
                                                    ports_for_fwg,
                                                    firewall_group)
        except fw_ext.FirewallInternalDriverError:
            msg = ("FWaaS driver error in create_firewall_group "
                   "for firewall group: %(fwg_id)s")
            LOG.exception(msg, {'fwg_id': firewall_group['id']})
            status = nl_constants.ERROR

        # Send firewall group's status to plugin.
        try:
            self.fwplugin_rpc.set_firewall_group_status(context,
                    firewall_group['id'], status)
        except Exception:
            msg = ("FWaaS RPC failure in create_firewall_group "
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
        del_fwg_ports = self._get_firewall_group_ports(
            context, firewall_group, to_delete=True, require_new_plugin=True)
        add_fwg_ports = self._get_firewall_group_ports(context, firewall_group)

        port_ids = (firewall_group.get('del-port-ids') +
                    firewall_group.get('add-port-ids'))

        if port_ids and not (del_fwg_ports or add_fwg_ports):
            LOG.debug("All ports are not router port."
                      "No need to update firewall driver.")
            return

        # Remove firewall group from ports if requested.
        if del_fwg_ports:
            fw_ports = [p for ri_port in del_fwg_ports for p in ri_port[1]]
            LOG.debug("Update (delete) firewall group %(fwg_id)s on ports: "
                      "%(ports)s",
                      {'fwg_id': firewall_group['id'],
                       'ports': ', '.join(fw_ports)})

            # Set firewall group's status; will be overwritten if call to
            # driver fails.

            if firewall_group['admin_state_up']:
                status = nl_constants.ACTIVE
                if firewall_group['last-port']:
                    status = nl_constants.INACTIVE
            else:
                status = nl_constants.DOWN

            # Call the driver.
            try:
                self.fwaas_driver.delete_firewall_group(self.conf.agent_mode,
                                                        del_fwg_ports,
                                                        firewall_group)
            except fw_ext.FirewallInternalDriverError:
                msg = ("FWaaS driver error in update_firewall_group "
                       "(add) for firewall group: %s")
                LOG.exception(msg, firewall_group['id'])
                status = nl_constants.ERROR

        # Handle the add router and/or rule, policy, firewall group attribute
        # updates.
        if status not in (nl_constants.ERROR, nl_constants.INACTIVE):
            if add_fwg_ports:
                fw_ports = [p for ri_port in add_fwg_ports
                            for p in ri_port[1]]
                LOG.debug("Update (create) firewall group %(fwg_id)s on "
                          "ports: %(ports)s",
                          {'fwg_id': firewall_group['id'],
                           'ports': ', '.join(fw_ports)})

                # Set firewall group status, which will be overwritten if call
                # to driver fails.
                if firewall_group['admin_state_up']:
                    status = nl_constants.ACTIVE
                else:
                    status = nl_constants.DOWN

                # Call the driver.
                try:
                    self.fwaas_driver.update_firewall_group(
                            self.conf.agent_mode, add_fwg_ports,
                            firewall_group)
                except fw_ext.FirewallInternalDriverError:
                    msg = ("FWaaS driver error in update_firewall_group "
                           "for firewall group: %s")
                    LOG.exception(msg, firewall_group['id'])
                    status = nl_constants.ERROR
            else:
                status = nl_constants.INACTIVE

        # Return status to plugin.
        try:
            self.fwplugin_rpc.set_firewall_group_status(context,
                    firewall_group['id'], status)
        except Exception:
            LOG.exception("FWaaS RPC failure in update_firewall_group "
                          "for firewall group: %s", firewall_group['id'])
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
        LOG.debug("Delete firewall group %(fwg_id)s on ports: %(ports)s",
                  {'fwg_id': firewall_group['id'],
                   'ports': ', '.join(fw_ports)})

        # Set the firewall group's status to return to plugin; status may be
        # overwritten if call to driver fails.
        if firewall_group['admin_state_up']:
            status = nl_constants.ACTIVE
        else:
            status = nl_constants.DOWN
        try:
            self.fwaas_driver.delete_firewall_group(self.conf.agent_mode,
                                                    ports_for_fwg,
                                                    firewall_group)
        # Call the driver.
        except fw_ext.FirewallInternalDriverError:
            LOG.exception("FWaaS driver error in delete_firewall_group "
                          "for firewall group: %s", firewall_group['id'])
            status = nl_constants.ERROR

        # Notify plugin of deletion or return firewall group's status to
        # plugin, as appropriate.
        try:
            if status in [nl_constants.ACTIVE, nl_constants.DOWN]:
                self.fwplugin_rpc.firewall_group_deleted(context,
                                                         firewall_group['id'])
            else:
                self.fwplugin_rpc.set_firewall_group_status(context,
                        firewall_group['id'], status)
        except Exception:
            LOG.exception("FWaaS RPC failure in delete_firewall_group "
                          "for firewall group: %s", firewall_group['id'])
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
