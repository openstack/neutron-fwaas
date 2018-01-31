# Copyright 2017-2018 FUJITSU LIMITED
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
#    under the License.

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.agent import securitygroups_rpc
from neutron.common import rpc as n_rpc
from neutron import manager
from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager
from neutron_lib.agent import l2_extension
from neutron_lib import constants as nl_const
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.utils import net as nl_net

from neutron_fwaas._i18n import _
from neutron_fwaas.common import fwaas_constants as consts
from neutron_fwaas.services.firewall.agents import firewall_agent_api as api

LOG = logging.getLogger(__name__)

FWAAS_L2_DRIVER = 'neutron.agent.l2.firewall_drivers'
SG_OVS_DRIVER = 'openvswitch'


class FWaaSL2PluginApi(api.FWaaSPluginApiMixin):
    """L2 agent side of FWaaS agent-to-plugin RPC API"""

    def get_firewall_group_for_port(self, context, port_id):
        """Get firewall group is associated with a port"""

        LOG.debug("Get firewall group is associated with port %s", port_id)
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_firewall_group_for_port',
                          port_id=port_id)

    def set_firewall_group_status(self, context, fwg_id, status, host):
        """Set the status of a group operation."""

        LOG.debug("Fetch firewall group changing status")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_firewall_group_status',
                          fwg_id=fwg_id, status=status, host=host)

    def firewall_group_deleted(self, context, fwg_id, host):
        """Notifies the plugin that a firewall group has been deleted."""

        LOG.debug("Notify to the plugin that firewall group has been deleted")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'firewall_group_deleted',
                          fwg_id=fwg_id, host=host)


class FWaaSV2AgentExtension(l2_extension.L2AgentExtension):

    def initialize(self, connection, driver_type):
        """Perform Agent Extension initialization"""

        self.conf = cfg.CONF
        int_br = self.agent_api.request_int_br()
        self.vlan_manager = vlanmanager.LocalVlanManager()
        fw_l2_driver_cls = self._load_l2_driver_class(driver_type)
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        sg_firewall_driver = self.conf.SECURITYGROUP.firewall_driver
        sg_with_ovs = sg_enabled and (sg_firewall_driver == SG_OVS_DRIVER)
        self.driver = manager.NeutronManager.load_class_for_provider(
            FWAAS_L2_DRIVER, fw_l2_driver_cls)(int_br, sg_with_ovs)
        self.plugin_rpc = FWaaSL2PluginApi(
            consts.FIREWALL_PLUGIN, self.conf.host)
        self.start_rpc_listeners()
        self.fwg_map = PortFirewallGroupMap()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def start_rpc_listeners(self):
        self.conn = n_rpc.create_connection()
        endpoints = [self]
        self.conn.create_consumer(consts.FW_AGENT, endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _load_l2_driver_class(self, driver_type):
        driver = self.conf.fwaas.firewall_l2_driver or 'noop'
        if driver == api.FW_L2_NOOP_DRIVER:
            return driver

        if driver != driver_type:
            raise Exception(
                _("Firewall l2 driver: %s is not compatible"), driver_type)
        return driver

    def _is_port_layer2(self, port):
        """This function checks if a port belongs to a L2 case.

        Currently both DHCP and router ports are eliminated.
        """

        return port and port.get('device_owner', '').startswith(
            nl_const.DEVICE_OWNER_COMPUTE_PREFIX)

    def _get_firewall_group_ports(self, fwg, host, to_delete=False):
        port_list = []
        port_ids = fwg['del-port-ids'] if to_delete else fwg['add-port-ids']

        LOG.debug("_get_fwg fwg=%(fwg)s ports=%(port)s to_delete=%(delete)s",
                  {'fwg': fwg, 'port': port_ids, 'delete': to_delete})
        for fw_port in port_ids:
            port_detail = fwg['port_details'].get(fw_port)
            if (self._is_port_layer2(port_detail) and
                    port_detail.get('host') == host):
                port_list.append(port_detail)
        return port_list

    @staticmethod
    def _has_ports(fwg, event):
        """Verifying fwg has ports or not

         This function verify applying firewall group on ports
         :param fwg: a fwg object
         :param event: create/update firewall group or
                       create/update/delete port
         :return: True if applying firewall group is fine. Otherwise is False
        """
        if event == consts.UPDATE_FWG and 'last-port' in fwg:
            return not fwg['last-port']
        else:
            return bool(fwg['ports'])

    @staticmethod
    def _has_policy(fwg):
        """Verifying fwg has policy or not"""
        return bool(fwg['ingress_firewall_policy_id'] or
                    fwg['egress_firewall_policy_id'])

    def _compute_status(self, fwg, result, event=consts.CREATE_FWG):
        """Compute a status of specified firewall group for update

        Validates 'ACTIVE', 'DOWN', 'INACTIVE', 'ERROR' and None as follows:
            - "ERROR"    : if result is not True
            - "ACTIVE"   : admin_state_up is True and exists ports
            - "INACTIVE" : admin_state_up is True and with no ports
            - "DOWN"     : admin_state_up is False
            - None       : In case of 'delete_firewall_group'
        """
        if not result:
            return nl_const.ERROR

        if not fwg['admin_state_up']:
            return nl_const.DOWN

        if event == consts.DELETE_FWG:
            # This firewall_group will be deleted. No need to update status.
            return

        if (self._has_ports(fwg, event) and self._has_policy(fwg)):
            return nl_const.ACTIVE

        return nl_const.INACTIVE

    def _get_network_id(self, fwg_port):
        port_id = fwg_port.get('port_id', fwg_port.get('id'))
        port_details = fwg_port.get('port_details')

        if port_details:
            target = port_details.get(port_id)
            if target:
                return target.get('network_id')
            return

        return fwg_port.get('network_id')

    def _add_local_vlan_to_ports(self, fwg_ports):
        """Add local VLAN to ports if found

        This function tries to add local VLAN related to ports.
        """

        ports_with_lvlan = []
        for fwg_port in fwg_ports:
            try:
                network_id = self._get_network_id(fwg_port)
                l_vlan = self.vlan_manager.get(network_id).vlan
                fwg_port['lvlan'] = int(l_vlan)
            except vlanmanager.MappingNotFound:
                LOG.warning("No Local VLAN found in network %s", network_id)
            # NOTE(yushiro): We ignore this exception because we should send
            # all selected ports to driver layer.  It depends on driver's
            # behavior whether it occurs an error with no local VLAN or not.
            ports_with_lvlan.append(fwg_port)

        return ports_with_lvlan

    def _apply_fwg_rules(self, fwg, ports, event=consts.UPDATE_FWG):
        """This function invokes the driver create/update routine. """
        # Set firewall group status; will be overwritten if call to driver
        # fails.
        if event in [consts.CREATE_FWG, consts.UPDATE_FWG]:
            ports_for_driver = self._add_local_vlan_to_ports(ports)
        else:
            ports_for_driver = ports

        # apply firewall group to driver
        try:
            if event == consts.UPDATE_FWG:
                self.driver.update_firewall_group(ports_for_driver, fwg)
            elif event == consts.DELETE_FWG:
                self.driver.delete_firewall_group(ports_for_driver, fwg)
            elif event == consts.CREATE_FWG:
                self.driver.create_firewall_group(ports_for_driver, fwg)
        except f_exc.FirewallInternalDriverError:
            msg = _("FWaaS driver error in %(event)s_firewall_group "
                    "for firewall group: %(fwg_id)s")
            LOG.exception(msg, {'event': event, 'fwg_id': fwg['id']})
            return False
        return True

    def _send_fwg_status(self, context, fwg_id, status, host):
        """Send firewall group's status to plugin.

        :returns: True if no exception occurred otherwise False
        :rtype: boolean
        """
        try:
            self.plugin_rpc.set_firewall_group_status(
                context, fwg_id, status, host)
            LOG.debug("Successfully sent status(%s) for firewall_group(%s)",
                      status, fwg_id)
        except Exception:
            msg = _("Failed to send status for firewall_group(%s)")
            LOG.exception(msg, fwg_id)

    def _create_firewall_group(self, context, fwg, host,
                               event=consts.CREATE_FWG):
        """Handles RPC from plugin to create a firewall group. """

        add_ports = self._get_firewall_group_ports(fwg, host)
        if not add_ports:
            status = nl_const.INACTIVE
        else:
            ret = self._apply_fwg_rules(fwg, add_ports, event)

            # cleanup port_map
            for port in add_ports:
                self.fwg_map.remove_port(port)

            status = self._compute_status(fwg, ret, event)
            for port in add_ports:
                self.fwg_map.set_port_fwg(port, fwg)
        # Update status of firewall group which is associated with ports
        # after updating.
        self._send_fwg_status(context, fwg['id'], status, host)

    def _delete_firewall_group(self, context, fwg, host,
                               event=consts.DELETE_FWG):
        """Handles RPC from plugin to delete a firewall group. """

        del_ports = self._get_firewall_group_ports(fwg, host, to_delete=True)
        if not del_ports:
            return

        # cleanup all flows of del_ports
        ret = self._apply_fwg_rules(fwg, del_ports, event=consts.DELETE_FWG)
        del_port_ids = []
        for port in del_ports:
            del_port_ids.append(port['id'])
            self.fwg_map.remove_port(port)

        if event == consts.DELETE_FWG:
            self.fwg_map.remove_fwg(fwg)
            self.plugin_rpc.firewall_group_deleted(
                context, fwg['id'], host=self.conf.host)
        else:
            status = self._compute_status(fwg, ret, event)
            self._send_fwg_status(context, fwg['id'], status, self.conf.host)

    @lockutils.synchronized('fwg')
    def create_firewall_group(self, context, firewall_group, host):
        """Handles create firewall group event"""

        # TODO(chandanc): Fix agent RPC endpoint to remove host arg
        host = cfg.CONF.host
        with self.driver.defer_apply():
            try:
                self._create_firewall_group(context, firewall_group, host)
            except Exception as exc:
                LOG.exception(
                    "Exception caught in create_firewall_group %s", exc)
                self._send_fwg_status(context, firewall_group['id'],
                                      status=nl_const.ERROR, host=host)

    @lockutils.synchronized('fwg')
    def delete_firewall_group(self, context, firewall_group, host):
        """Handles delete firewall group event"""

        # TODO(chandanc): Fix agent RPC endpoint to remove host arg
        host = cfg.CONF.host
        with self.driver.defer_apply():
            try:
                self._delete_firewall_group(context, firewall_group, host)
            except Exception as exc:
                LOG.exception(
                    "Exception caught in delete_firewall_group %s", exc)
                self._send_fwg_status(context, firewall_group['id'],
                                      status=nl_const.ERROR, host=host)

    @lockutils.synchronized('fwg')
    def update_firewall_group(self, context, firewall_group, host):
        """Handles update firewall group event"""

        # TODO(chandanc): Fix agent RPC endpoint to remove host arg
        host = cfg.CONF.host
        with self.driver.defer_apply():
            try:
                self._delete_firewall_group(
                    context, firewall_group, host, event=consts.UPDATE_FWG)
                self._create_firewall_group(
                    context, firewall_group, host, event=consts.UPDATE_FWG)
            except Exception as exc:
                LOG.exception(
                    "Exception caught in update_firewall_group %s", exc)
                self._send_fwg_status(context, firewall_group['id'],
                                      status=nl_const.ERROR, host=host)

    @lockutils.synchronized('fwg-port')
    def handle_port(self, context, port):
        """Handle port update event"""

        # Check if port is trusted and called at once.
        if nl_net.is_port_trusted(port) and not self.fwg_map.get_port(port):
            self._add_rule_for_trusted_port(port)
            self.fwg_map.set_port(port)
            return

        if not self._is_port_layer2(port):
            return

        # check if port is already assigned to a fwg
        if self.fwg_map.get_port_fwg(port):
            return

        fwg = self.plugin_rpc.get_firewall_group_for_port(
            context, port.get('port_id'))
        if not fwg:
            LOG.info("Firewall group applied to port %s is "
                     "not available on server.", port['port_id'])
            return

        ret = self._apply_fwg_rules(fwg, [port])
        status = self._compute_status(fwg, ret, event=consts.HANDLE_PORT)
        self.fwg_map.set_port_fwg(port, fwg)
        self._send_fwg_status(
            context, fwg_id=fwg['id'], status=status, host=self.conf.host)

    def _add_rule_for_trusted_port(self, port):
        self._add_local_vlan_to_ports([port])
        self.driver.process_trusted_ports([port])

    def _delete_rule_for_trusted_port(self, port):
        self.driver.remove_trusted_ports([port['port_id']])

    def delete_port(self, context, port):
        """This is being called when a port is deleted by the agent. """

        # delete_port should be handled only unbound timing for a port.
        # If 'vif_port' is included in the port dict, this is called after
        # deleted the port and should be ignored.
        if 'vif_port' in port:
            return

        port = self.fwg_map.get_port(port)

        if port and nl_net.is_port_trusted(port):
            self._delete_rule_for_trusted_port(port)
            self.fwg_map.remove_port(port)
            return

        if not self._is_port_layer2(port):
            return

        fwg = self.fwg_map.get_port_fwg(port)
        if not fwg:
            LOG.info("Firewall group associated to port %(port_id)s is "
                     "not available on server.", {'port_id': port['port_id']})
            return

        ret = self._apply_fwg_rules(fwg, [port], event=consts.DELETE_FWG)

        port_id = self.fwg_map.port_id(port)
        if port_id in fwg['ports']:
            fwg['ports'].remove(port_id)

        # update the fwg dict to known_fwgs
        self.fwg_map.set_fwg(fwg)
        self.fwg_map.remove_port(port)
        status = self._compute_status(fwg, ret, event=consts.DELETE_PORT)
        self._send_fwg_status(context, fwg['id'], status, self.conf.host)


class PortFirewallGroupMap(object):
    """Store relations between Port and Firewall Group and trusted port

    This map is used in deleting firewall_group because the firewall_group has
    been deleted at that time.  Therefore, it is impossible to refer 'ports'.
    This map enables to refer 'ports' for specified firewall_group.
    Furthermore, it is necessary to check 'device_owner' for trusted port, this
    Map also stores trusted port data.
    """
    def __init__(self):
        self.known_fwgs = {}
        self.port_fwg = {}
        self.port_detail = {}
        # TODO(yushiro): If agent is restarted, this map doesn't have any
        # information. Need to consider map initialization in __init__()

    def port_id(self, port):
        return (port if isinstance(port, six.string_types)
                else port.get('port_id', port.get('id')))

    def get_fwg(self, fwg_id):
        return self.known_fwgs.get(fwg_id)

    def set_fwg(self, fwg):
        self.known_fwgs[fwg['id']] = fwg

    def get_port(self, port):
        return self.port_detail.get(self.port_id(port))

    def get_port_fwg(self, port):
        fwg_id = self.port_fwg.get(self.port_id(port))
        if fwg_id:
            return self.get_fwg(fwg_id)

    def set_port(self, port):
        """Add a new port into port_detail"""
        port_id = self.port_id(port)
        self.port_detail[port_id] = port

    def set_port_fwg(self, port, fwg):
        """Add a new port into fwg['ports']"""
        port_id = self.port_id(port)
        # Update fwg['ports'] data
        fwg['ports'] = list(set(fwg['ports'] + [port_id]))
        # Update fwg_id -> firewall_group data
        self.known_fwgs[fwg['id']] = fwg
        # Update port_id -> port data
        self.port_detail[port_id] = port
        # Update port_id -> firewall_group_id relation
        self.port_fwg[port_id] = fwg['id']

    def remove_port(self, port):
        """Remove port from fwg['ports'] and port_fwg dictionary

        When removing 'port' from several cases, the port should be removed
        from this map.
        """
        port_id = self.port_id(port)
        # Check if 'port_id' has registered in port_fwg dictionary.
        # Update firewall_group
        if port_id in self.port_fwg:
            fwg_id = self.port_fwg.get(port_id)
            if not fwg_id:
                # This case is trusted port. Try to delete port_detail dict
                try:
                    del self.port_detail[port_id]
                except KeyError:
                    pass
                return
            new_fwg = self.known_fwgs[fwg_id]
            new_fwg['ports'] = [p for p in new_fwg['ports'] if p != port_id]
            self.known_fwgs[fwg_id] = new_fwg
            del self.port_fwg[port_id]
            del self.port_detail[port_id]

    def remove_fwg(self, fwg):
        """Remove firewall_group from known_fwgs dictionary

        When removing firewall_group, it should be removed from this map
        """
        if fwg['id'] in self.known_fwgs:
            del self.known_fwgs[fwg['id']]
