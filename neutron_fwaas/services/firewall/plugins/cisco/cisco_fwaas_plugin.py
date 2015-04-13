# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
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
#

from neutron.api.v2 import attributes as attr
from neutron.common import constants as l3_const
from neutron.common import rpc as n_rpc
from neutron import context as neutron_context
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants as const
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas.db.cisco import cisco_fwaas_db as csrfw_db
import neutron_fwaas.extensions
from neutron_fwaas.extensions.cisco import csr_firewall_insertion as csr_ext
from neutron_fwaas.services.firewall import fwaas_plugin as ref_fw_plugin

LOG = logging.getLogger(__name__)


class FirewallCallbacks(object):

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    @log_helpers.log_method_call
    def set_firewall_status(self, context, firewall_id, status,
                            status_data=None, **kwargs):
        """Agent uses this to set a firewall's status."""
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # ignore changing status if firewall expects to be deleted
            # That case means that while some pending operation has been
            # performed on the backend, neutron server received delete request
            # and changed firewall status to const.PENDING_DELETE
            if status == const.ERROR:
                fw_db.status = const.ERROR
                return False
            if fw_db.status == const.PENDING_DELETE:
                LOG.debug("Firewall %(fw_id)s in PENDING_DELETE state, "
                          "not changing to %(status)s",
                          {'fw_id': firewall_id, 'status': status})
                return False
            if status in (const.ACTIVE, const.INACTIVE):
                fw_db.status = status
                csrfw = self.plugin.lookup_firewall_csr_association(context,
                    firewall_id)
                _fw = {'id': csrfw['fw_id'], 'port_id': csrfw['port_id'],
                       'direction': csrfw['direction'],
                       'acl_id': status_data['acl_id']}
                self.plugin.update_firewall_csr_association(context,
                    firewall_id, _fw)
            else:
                fw_db.status = const.ERROR

    @log_helpers.log_method_call
    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # allow to delete firewalls in ERROR state
            if fw_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_firewall_object(context, firewall_id)
                return True
            LOG.warn(_LW('Firewall %(fw)s unexpectedly deleted by agent, '
                         'status was %(status)s'),
                {'fw': firewall_id, 'status': fw_db.status})
            fw_db.status = const.ERROR
        return False

    @log_helpers.log_method_call
    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        fw_list = []
        for fw in self.plugin.get_firewalls(context):
            fw_with_rules = (
                self.plugin._make_firewall_dict_with_rules(context, fw['id']))
            csrfw = self.plugin.lookup_firewall_csr_association(context,
                fw['id'])
            router_id = csrfw['router_id']
            fw_with_rules['vendor_ext'] = self.plugin._get_hosting_info(
                context, csrfw['port_id'], router_id, csrfw['direction'])
            fw_with_rules['vendor_ext']['acl_id'] = csrfw['acl_id']
            fw_list.append(fw_with_rules)
        return fw_list

    @log_helpers.log_method_call
    def get_firewalls_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all firewalls for a tenant."""
        return [fw for fw in self.plugin.get_firewalls(context)]

    @log_helpers.log_method_call
    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        ctx = neutron_context.get_admin_context()
        fw_list = self.plugin.get_firewalls(ctx)
        return list(set(fw['tenant_id'] for fw in fw_list))


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def create_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_firewall', firewall=firewall,
                   host=self.host)

    def update_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_firewall', firewall=firewall,
                   host=self.host)

    def delete_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_firewall', firewall=firewall,
                   host=self.host)


class CSRFirewallPlugin(ref_fw_plugin.FirewallPlugin,
                        csrfw_db.CiscoFirewall_db_mixin):

    """Implementation of the Neutron Firewall Service Plugin.

    This class implements the Cisco CSR FWaaS Service Plugin,
    inherits from the fwaas ref plugin as no changes are made
    to handling fwaas policy and rules. The CRUD methods are
    overridden to provide for the specific implementation. The
    basic fwaas db is managed thru the firewall_db.Firewall_db_mixin.
    The backend specific associations are captured in the new table,
    csrfw_db.CiscoFirewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas", "csrfirewallinsertion"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""

        ext_path = neutron_fwaas.extensions.__path__[0] + '/cisco'
        if ext_path not in cfg.CONF.api_extensions_path.split(':'):
            cfg.CONF.set_override('api_extensions_path',
                              cfg.CONF.api_extensions_path + ':' + ext_path)

        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            'CISCO_FW_PLUGIN', self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = FirewallAgentApi(
            'CISCO_FW',
            cfg.CONF.host
        )

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        fw = super(ref_fw_plugin.FirewallPlugin, self).update_firewall(
            context, firewall_id, status_update)
        if fw:
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context,
                                                    firewall_id))
            csrfw = self.lookup_firewall_csr_association(context, firewall_id)
            fw_with_rules['vendor_ext'] = self._get_hosting_info(context,
                csrfw['port_id'], csrfw['router_id'], csrfw['direction'])
            fw_with_rules['vendor_ext']['acl_id'] = csrfw['acl_id']
            LOG.debug("Update of Rule or policy: fw_with_rules: %s",
                fw_with_rules)
            self.agent_rpc.update_firewall(context, fw_with_rules)

    @log_helpers.log_method_call
    def _validate_fw_port_and_get_router_id(self, context, tenant_id, port_id):
        # port validation with router plugin
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        ctx = neutron_context.get_admin_context()
        routers = l3_plugin.get_routers(ctx)
        router_ids = [
            router['id']
            for router in routers
            if router['tenant_id'] == tenant_id]
        port_db = self._core_plugin._get_port(context, port_id)
        if not (port_db['device_id'] in router_ids and
                port_db['device_owner'] == l3_const.DEVICE_OWNER_ROUTER_INTF):
            raise csr_ext.InvalidInterfaceForCSRFW(port_id=port_id)
        return port_db['device_id']

    def _map_csr_device_info_for_agent(self, hosting_device):
        return {'host_mngt_ip': hosting_device['management_ip_address'],
                'host_usr_nm': hosting_device['credentials']['username'],
                'host_usr_pw': hosting_device['credentials']['password']}

    def _get_service_insertion_points(self, context, interfaces, port_id,
            direction):
        insertion_point = dict()
        hosting_info = dict()
        for interface in interfaces:
            if interface['id'] == port_id:
                hosting_info = interface['hosting_info']
        if not hosting_info:
            raise csr_ext.InvalidRouterHostingInfoForCSRFW(port_id=port_id)
        insertion_point['port'] = {'id': port_id,
            'hosting_info': hosting_info}
        insertion_point['direction'] = direction
        return [insertion_point]

    def _get_hosting_info(self, context, port_id, router_id, direction):
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        ctx = neutron_context.get_admin_context()
        routers = l3_plugin.get_sync_data_ext(ctx)
        for router in routers:
            if router['id'] == router_id:
                vendor_ext = self._map_csr_device_info_for_agent(
                    router['hosting_device'])
                vendor_ext['if_list'] = self._get_service_insertion_points(
                    context, router['_interfaces'], port_id, direction)
                return vendor_ext
        # TODO(sridar): we may need to raise an excp - check backlogging

    @log_helpers.log_method_call
    def create_firewall(self, context, firewall):
        tenant_id = self._get_tenant_id_for_create(context,
                                                   firewall['firewall'])
        port_id = firewall['firewall'].pop('port_id', None)
        direction = firewall['firewall'].pop('direction', None)

        if port_id == attr.ATTR_NOT_SPECIFIED:
            LOG.debug("create_firewall() called")
            port_id = None
            router_id = None
        else:
            # TODO(sridar): add check to see if the new port-id does not have
            # any associated firewall.
            router_id = self._validate_fw_port_and_get_router_id(context,
                tenant_id, port_id)

        if direction == attr.ATTR_NOT_SPECIFIED:
            direction = None

        firewall['firewall']['status'] = const.PENDING_CREATE
        fw = super(ref_fw_plugin.FirewallPlugin, self).create_firewall(
            context, firewall)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        if not port_id and not direction:
            return fw

        # Add entry into firewall associations table
        _fw = {'id': fw['id'], 'port_id': port_id,
            'direction': direction, 'router_id': router_id, 'acl_id': None}
        self.add_firewall_csr_association(context, _fw)

        if port_id and direction:
            fw_with_rules['vendor_ext'] = self._get_hosting_info(context,
                port_id, router_id, direction)
            fw_with_rules['vendor_ext']['acl_id'] = None

            self.agent_rpc.create_firewall(context, fw_with_rules)
        return fw

    @log_helpers.log_method_call
    def update_firewall(self, context, fwid, firewall):
        self._ensure_update_firewall(context, fwid)
        tenant_id = self._get_tenant_id_for_create(context,
                                                   firewall['firewall'])
        csrfw = self.lookup_firewall_csr_association(context, fwid)

        port_id = firewall['firewall'].pop('port_id', None)
        direction = firewall['firewall'].pop('direction', None)

        _fw = {'id': fwid}

        if port_id:
            router_id = self._validate_fw_port_and_get_router_id(context,
                tenant_id, port_id)
            if csrfw and csrfw['port_id']:
                # TODO(sridar): add check to see if the new port_id does not
                # have any associated firewall.

                # we only support a different port if associated
                # with the same router
                if router_id != csrfw['router_id']:
                    raise csr_ext.InvalidRouterAssociationForCSRFW(
                        port_id=port_id)
            _fw['port_id'] = port_id
            _fw['router_id'] = router_id
        else:
            _fw['port_id'] = csrfw['port_id'] if csrfw else None
            _fw['router_id'] = csrfw['router_id'] if csrfw else None

        if direction:
            _fw['direction'] = direction
        else:
            _fw['direction'] = csrfw['direction'] if csrfw else None

        _fw['acl_id'] = csrfw['acl_id'] if csrfw else None

        self.update_firewall_csr_association(context, fwid, _fw)

        firewall['firewall']['status'] = const.PENDING_UPDATE

        fw = super(ref_fw_plugin.FirewallPlugin, self).update_firewall(
            context, fwid, firewall)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        if _fw['port_id'] and _fw['direction']:

            fw_with_rules['vendor_ext'] = self._get_hosting_info(context,
                port_id, csrfw['router_id'], direction)
            fw_with_rules['vendor_ext']['acl_id'] = csrfw['acl_id']
            LOG.debug("CSR Plugin update: fw_with_rules: %s", fw_with_rules)
            self.agent_rpc.update_firewall(context, fw_with_rules)
        return fw

    @log_helpers.log_method_call
    def delete_firewall(self, context, fwid):
        self._ensure_update_firewall(context, fwid)

        status_update = {"firewall": {"status": const.PENDING_DELETE}}
        fw = super(ref_fw_plugin.FirewallPlugin, self).update_firewall(
            context, fwid, status_update)

        # given that we are not in a PENDING_CREATE we should have
        # an acl_id - since it is not present something bad has happened
        # on the backend and no sense in sending a msg to the agent.
        # Clean up ...
        csrfw = self.lookup_firewall_csr_association(context, fwid)
        if not csrfw or not csrfw['acl_id']:
            self.delete_db_firewall_object(context, fwid)
            return

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        fw_with_rules['vendor_ext'] = self._get_hosting_info(context,
            csrfw['port_id'], csrfw['router_id'], csrfw['direction'])
        fw_with_rules['vendor_ext']['acl_id'] = csrfw['acl_id']

        self.agent_rpc.delete_firewall(context, fw_with_rules)

    @log_helpers.log_method_call
    def get_firewall(self, context, fwid, fields=None):
        res = super(ref_fw_plugin.FirewallPlugin, self).get_firewall(
                        context, fwid, fields)
        csrfw = self.lookup_firewall_csr_association(context, res['id'])
        if not csrfw:
            return res
        res['port_id'] = csrfw['port_id']
        res['direction'] = csrfw['direction']
        res['router_id'] = csrfw['router_id']
        return res
