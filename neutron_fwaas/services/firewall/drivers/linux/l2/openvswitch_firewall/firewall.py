# Copyright 2015
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

import netaddr

from neutron_lib import constants as lib_const
from oslo_log import log as logging
from oslo_utils import netutils

from neutron.agent import firewall
from neutron.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
    as ovs_consts

from neutron_fwaas.services.firewall.drivers.linux.l2 import driver_base
from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import constants as fwaas_ovs_consts
from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import exceptions
from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import rules

LOG = logging.getLogger(__name__)

ACTION_ALLOW = 'allow'


# NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver.
def _replace_register(flow_params, register_number, register_value):
    """Replace value from flows to given register number

    'register_value' key in dictionary will be replaced by register number
    given by 'register_number'

    :param flow_params: Dictionary containing defined flows
    :param register_number: The number of register where value will be stored
    :param register_value: Key to be replaced by register number

    """
    try:
        reg_port = flow_params[register_value]
        del flow_params[register_value]
        flow_params['reg{:d}'.format(register_number)] = reg_port
    except KeyError:
        pass


# NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver that
# differs only in constants REG_PORT/REG_NET.
def create_reg_numbers(flow_params):
    """Replace reg_(port|net) values with defined register numbers"""
    _replace_register(flow_params, fwaas_ovs_consts.REG_PORT, 'reg_port')
    _replace_register(flow_params, fwaas_ovs_consts.REG_NET, 'reg_net')


class FirewallGroup(object):
    def __init__(self, id_):
        self.id = id_
        self.ingress_rules = []
        self.egress_rules = []
        self.members = {}
        self.ports = set()

    def update_rules(self, ingress_rules, egress_rules):
        """Update firewall group with ingress/egress rules.

        If a rule has a protocol field, it is normalized to a number
        here in order to ease later processing.
        """
        def _translate_protocol_to_number(rule):
            protocol = rule.get('protocol')
            if protocol is not None:
                if protocol.isdigit():
                    rule['protocol'] = int(protocol)
                elif (rule.get('ethertype') == lib_const.IPv6 and
                        protocol == lib_const.PROTO_NAME_ICMP):
                    rule['protocol'] = lib_const.PROTO_NUM_IPV6_ICMP
                else:
                    rule['protocol'] = lib_const.IP_PROTOCOL_MAP.get(
                        protocol, protocol)
            return rule

        self.ingress_rules = [_translate_protocol_to_number(ir)
                              for ir in ingress_rules]
        self.egress_rules = [_translate_protocol_to_number(er)
                             for er in egress_rules]

    def get_ethertype_filtered_addresses(self, ethertype,
                                         exclude_addresses=None):
        exclude_addresses = set(exclude_addresses if exclude_addresses else [])
        group_addresses = set(self.members.get(ethertype, []))
        return list(group_addresses - exclude_addresses)


# NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver that
# differs only in firewall groups list field name
class OFPort(object):
    def __init__(self, port_dict, ovs_port, vlan_tag):
        self.id = port_dict['device']
        self.vlan_tag = vlan_tag
        self.mac = ovs_port.vif_mac
        self.lla_address = str(netutils.get_ipv6_addr_by_EUI64(
            lib_const.IPv6_LLA_PREFIX, self.mac))
        self.ofport = ovs_port.ofport
        self.fw_group = None
        self.fixed_ips = port_dict.get('fixed_ips', [])
        self.neutron_port_dict = port_dict.copy()
        self.allowed_pairs_v4 = self._get_allowed_pairs(port_dict, version=4)
        self.allowed_pairs_v6 = self._get_allowed_pairs(port_dict, version=6)

    @staticmethod
    def _get_allowed_pairs(port_dict, version):
        aap_dict = port_dict.get('allowed_address_pairs', set())
        return {(aap['mac_address'], aap['ip_address']) for aap in aap_dict
                if netaddr.IPNetwork(aap['ip_address']).version == version}

    @property
    def all_allowed_macs(self):
        macs = {item[0] for item in self.allowed_pairs_v4.union(
            self.allowed_pairs_v6)}
        macs.add(self.mac)
        return macs

    @property
    def ipv4_addresses(self):
        return [ip_addr for ip_addr in
                [fixed_ip['ip_address'] for fixed_ip in self.fixed_ips]
                if netaddr.IPAddress(ip_addr).version == 4]

    @property
    def ipv6_addresses(self):
        return [ip_addr for ip_addr in
                [fixed_ip['ip_address'] for fixed_ip in self.fixed_ips]
                if netaddr.IPAddress(ip_addr).version == 6]

    def update(self, port_dict):
        self.allowed_pairs_v4 = self._get_allowed_pairs(port_dict,
                                                        version=4)
        self.allowed_pairs_v6 = self._get_allowed_pairs(port_dict,
                                                        version=6)
        # Neighbour discovery uses LLA
        self.allowed_pairs_v6.add((self.mac, self.lla_address))
        self.fixed_ips = port_dict.get('fixed_ips', [])
        self.neutron_port_dict = port_dict.copy()


# NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver that
# differs in methods name [s/sg/fwg] and update_rules method.
class FWGPortMap(object):
    def __init__(self):
        self.ports = {}
        self.fw_groups = {}
        # Maps port_id to ofport number
        self.unfiltered = {}

    def get_fwg(self, fwg_id):
        return self.fw_groups.get(fwg_id, None)

    def get_or_create_fwg(self, fwg_id):
        fw_group = self.get_fwg(fwg_id)
        if not fw_group:
            fw_group = FirewallGroup(fwg_id)
            self.fw_groups[fwg_id] = fw_group
        return fw_group

    def delete_fwg(self, fwg_id):
        del self.fw_groups[fwg_id]

    # XXX NOTE(ivasilevskaya) couldn't find any logical definition why
    # firewall_group should come as 3rd argument instead of adding fwg_id
    # to port_dict. Removed in favor of SG api
    def create_port(self, port, port_dict):
        self.ports[port.id] = port
        self.update_port(port, port_dict)

    # XXX NOTE(ivasilevskaya) couldn't find any logical definition why
    # firewall_group should come as 3rd argument instead of adding fwg_id
    # to port_dict. Removed in favor of SG api
    def update_port(self, port, port_dict):
        for fw_group in self.fw_groups.values():
            fw_group.ports.discard(port)

        fw_group = self.get_or_create_fwg(port_dict['firewall_group'])
        port.fw_group = fw_group
        fw_group.ports.add(port)
        port.update(port_dict)

    def remove_port(self, port):
        if port.fw_group:
            port.fw_group.ports.discard(port)
        del self.ports[port.id]

    def update_rules(self, fwg_id, ingress_rules, egress_rules):
        fw_group = self.get_or_create_fwg(fwg_id)
        fw_group.update_rules(ingress_rules, egress_rules)

    def update_members(self, fwg_id, members):
        fw_group = self.get_or_create_fwg(fwg_id)
        fw_group.members = members


# NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver that
# doesn't have a conjunction manager because no remote_group_id concept is
# applicable to firewall groups
class OVSFirewallDriver(driver_base.FirewallL2DriverBase):
    REQUIRED_PROTOCOLS = [
        ovs_consts.OPENFLOW10,
        ovs_consts.OPENFLOW11,
        ovs_consts.OPENFLOW12,
        ovs_consts.OPENFLOW13,
        ovs_consts.OPENFLOW14,
    ]

    provides_arp_spoofing_protection = True

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver.
    # This driver won't have any conj_manager logic because there is no concept
    # of remote_group_id for firewall groups (that I know of at least)
    def __init__(self, integration_bridge, sg_with_ovs=False):
        """Initialize object

        :param integration_bridge: Bridge on which openflow rules will be
                                   applied

        """
        self.int_br = self.initialize_bridge(integration_bridge)
        self.fwg_port_map = FWGPortMap()
        self.fwg_to_delete = set()
        self._deferred = False
        self.sg_with_ovs = sg_with_ovs
        self._drop_all_unmatched_flows()
        self._initialize_third_party_tables()

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def _accept_flow(self, **flow):
        for f in rules.create_accept_flows(flow, self.sg_with_ovs):
            self._add_flow(**f)

    def _drop_flow(self, **flow):
        for f in rules.create_drop_flows(flow):
            self._add_flow(**f)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def _add_flow(self, **kwargs):
        dl_type = kwargs.get('dl_type')
        create_reg_numbers(kwargs)
        if isinstance(dl_type, int):
            kwargs['dl_type'] = "0x{:04x}".format(dl_type)
        if self._deferred:
            self.int_br.add_flow(**kwargs)
        else:
            self.int_br.br.add_flow(**kwargs)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def _delete_flows(self, **kwargs):
        create_reg_numbers(kwargs)
        if self._deferred:
            self.int_br.delete_flows(**kwargs)
        else:
            self.int_br.br.delete_flows(**kwargs)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def _strict_delete_flow(self, **kwargs):
        """Delete given flow right away even if bridge is deferred.

        Delete command will use strict delete.
        """
        create_reg_numbers(kwargs)
        self.int_br.br.delete_flows(strict=True, **kwargs)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    @staticmethod
    def initialize_bridge(int_br):
        int_br.add_protocols(*OVSFirewallDriver.REQUIRED_PROTOCOLS)
        return int_br.deferred(full_ordered=True)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver,
    # differs in constants
    def _drop_all_unmatched_flows(self):
        for table in fwaas_ovs_consts.OVS_FIREWALL_TABLES:
            if (table == fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE and
                self.sg_with_ovs):
                continue
            self.int_br.br.add_flow(table=table, priority=0, actions='drop')

    def _initialize_third_party_tables(self):
        self.int_br.br.add_flow(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
            priority=1,
            actions='normal')
        for table in (ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                      ovs_consts.DROPPED_TRAFFIC_TABLE):
            self.int_br.br.add_flow(
                table=table, priority=0, actions='drop')

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def get_ovs_port(self, port_id):
        ovs_port = self.int_br.br.get_vif_port_by_id(port_id)
        if not ovs_port:
            raise exceptions.OVSFWaaSPortNotFound(port_id=port_id)
        return ovs_port

    def _get_port_vlan_tag(self, port):
        vlan_tag = port.get('lvlan', None)
        if not vlan_tag:
            raise exceptions.OVSFWaaSTagNotFound(port_id=port['device'])
        return vlan_tag

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def get_ofport(self, port):
        port_id = port['device']
        return self.fwg_port_map.ports.get(port_id)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver,
    # self.sg_port_map -> self.fwg_port_map
    def get_or_create_ofport(self, port):
        """Get ofport specified by port['device'], checking and reflecting
        ofport changes.
        If ofport is nonexistent, create and return one.
        """
        port_id = port['device']
        ovs_port = self.get_ovs_port(port_id)
        try:
            of_port = self.fwg_port_map.ports[port_id]
        except KeyError:
            port_vlan_id = self._get_port_vlan_tag(port)
            of_port = OFPort(port, ovs_port, port_vlan_id)
            self.fwg_port_map.create_port(of_port, port)
        else:
            if of_port.ofport != ovs_port.ofport:
                self.fwg_port_map.remove_port(of_port)
                of_port = OFPort(port, ovs_port, of_port.vlan_tag)
            self.fwg_port_map.update_port(of_port, port)

        return of_port

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def is_port_managed(self, port):
        return port['device'] in self.fwg_port_map.ports

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def prepare_port_filter(self, port):
        # NOTE(annp): port no security should be handled by security group in
        # co-existence mode, otherwise(standalone mode) fwg will handle it.
        if not firewall.port_sec_enabled(port) and not self.sg_with_ovs:
            self._initialize_egress_no_port_security(port)
            return
        old_of_port = self.get_ofport(port)
        # Make sure delete old allow_address_pair MACs because
        # allow_address_pair MACs will be updated in
        # self.get_or_create_ofport(port)
        if old_of_port:
            LOG.error("Initializing port %s that was already "
                      "initialized.",
                      port['device'])
            self.delete_all_port_flows(old_of_port)
        of_port = self.get_or_create_ofport(port)
        self.initialize_port_flows(of_port)
        self.add_flows_from_rules(of_port)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def update_port_filter(self, port):
        """Update rules for given port

        Current existing filtering rules are removed and new ones are generated
        based on current loaded firewall group rules and members.

        Note: port no security should be handled by security group in
        co-existence mode, otherwise fwg will handle it.

        """
        if not firewall.port_sec_enabled(port) and not self.sg_with_ovs:
            self.remove_port_filter(port)
            self._initialize_egress_no_port_security(port)
            return
        elif not self.is_port_managed(port):
            if not self.sg_with_ovs:
                self._remove_egress_no_port_security(port['device'])
            self.prepare_port_filter(port)
            return

        old_of_port = self.get_ofport(port)
        of_port = self.get_or_create_ofport(port)
        # TODO(jlibosva): Handle firewall blink
        self.delete_all_port_flows(old_of_port)
        self.initialize_port_flows(of_port)
        self.add_flows_from_rules(of_port)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver,
    # sg_port_map -> fwg_port_map
    def remove_port_filter(self, port):
        """Remove port from firewall

        All flows related to this port are removed from ovs. Port is also
        removed from ports managed by this firewall.

        """
        if self.is_port_managed(port):
            of_port = self.get_ofport(port)
            self.delete_all_port_flows(of_port)
            self.fwg_port_map.remove_port(of_port)
            self._schedule_fwg_deletion_maybe(of_port.fw_group.id)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # with ingress\egress rules arguments instead of single rules
    def update_firewall_group_rules(self, fwg_id, ingress_rules, egress_rules):
        self.fwg_port_map.update_rules(fwg_id, ingress_rules, egress_rules)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # with sg_port_map -> fwg_port_map
    def _schedule_fwg_deletion_maybe(self, fwg_id):
        """Schedule possible deletion of the given firewall group.

        This function must be called when the number of ports
        associated to fwg_id drops to zero, as it isn't possible
        to know FWG deletions from agents due to RPC API design.
        """
        fwg_group = self.fwg_port_map.get_or_create_fwg(fwg_id)
        if not fwg_group.members or not fwg_group.ports:
            self.fwg_to_delete.add(fwg_id)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # with sg_port_map -> fwg_port_map
    def _cleanup_stale_fwg(self):
        fwg_to_delete = self.fwg_to_delete
        self.fwg_to_delete = set()

        for fwg_id in fwg_to_delete:
            fw_group = self.fwg_port_map.get_fwg(fwg_id)
            if fw_group.members and fw_group.ports:
                # firewall group is still in use
                continue

            self.fwg_port_map.delete_fwg(fwg_id)

    def process_trusted_ports(self, ports):
        """Pass packets from these ports directly to ingress pipeline."""
        if self.sg_with_ovs:
            return

        for port in ports:
            self._initialize_egress_no_port_security(port)

    def remove_trusted_ports(self, port_ids):
        if self.sg_with_ovs:
            return

        for port_id in port_ids:
            self._remove_egress_no_port_security(port_id)

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def filter_defer_apply_on(self):
        self._deferred = True

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    def filter_defer_apply_off(self):
        if self._deferred:
            self._cleanup_stale_fwg()
            self.int_br.apply_flows()
            self._deferred = False

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # with sg_port_map -> fwg_port_map
    @property
    def ports(self):
        return {id_: port.neutron_port_dict
                for id_, port in self.fwg_port_map.ports.items()}

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def initialize_port_flows(self, port):
        """Set base flows for port

        :param port: OFPort instance

        """
        # Identify egress flow
        self._add_flow(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=105,
            in_port=port.ofport,
            actions='set_field:{:d}->reg{:d},'
                    'set_field:{:d}->reg{:d},'
                    'resubmit(,{:d})'.format(
                        port.ofport,
                        fwaas_ovs_consts.REG_PORT,
                        port.vlan_tag,
                        fwaas_ovs_consts.REG_NET,
                        fwaas_ovs_consts.FW_BASE_EGRESS_TABLE)
        )

        # Identify ingress flows after egress filtering
        for mac_addr in port.all_allowed_macs:
            self._add_flow(
                table=ovs_consts.TRANSIENT_TABLE,
                priority=95,
                dl_dst=mac_addr,
                dl_vlan='0x%x' % port.vlan_tag,
                actions='set_field:{:d}->reg{:d},'
                        'set_field:{:d}->reg{:d},'
                        'strip_vlan,resubmit(,{:d})'.format(
                            port.ofport,
                            fwaas_ovs_consts.REG_PORT,
                            port.vlan_tag,
                            fwaas_ovs_consts.REG_NET,
                            fwaas_ovs_consts.FW_BASE_INGRESS_TABLE),
            )

        self._initialize_egress(port)
        self._initialize_ingress(port)

    def _fwaas_process_colocated_ingress(self, port):
        for mac_addr in port.all_allowed_macs:
            self._add_flow(
                table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
                priority=105,
                dl_dst=mac_addr,
                reg_net=port.vlan_tag,
                actions='set_field:{:d}->reg{:d},resubmit(,{:d})'.format(
                    port.ofport,
                    fwaas_ovs_consts.REG_PORT,
                    fwaas_ovs_consts.FW_BASE_INGRESS_TABLE),
            )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _initialize_egress_ipv6_icmp(self, port):
        for icmp_type in firewall.ICMPV6_ALLOWED_EGRESS_TYPES:
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
                priority=95,
                in_port=port.ofport,
                reg_port=port.ofport,
                dl_type=constants.ETHERTYPE_IPV6,
                nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
                icmp_type=icmp_type,
                actions='normal')

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers) and exception classes
    def _initialize_egress_no_port_security(self, port):
        port_id = port['device']
        try:
            ovs_port = self.get_ovs_port(port_id)
            vlan_tag = self._get_port_vlan_tag(port)
        except exceptions.OVSFWaaSTagNotFound:
            # It's a patch port, don't set anything
            return
        except exceptions.OVSFWaaSPortNotFound as not_found_e:
            LOG.error("Initializing unfiltered port %(port_id)s that does not "
                      "exist in ovsdb: %(err)s.",
                      {'port_id': port_id,
                       'err': not_found_e})
            return
        self.fwg_port_map.unfiltered[port_id] = ovs_port.ofport
        self._add_flow(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=100,
            in_port=ovs_port.ofport,
            actions='set_field:%d->reg%d,'
                    'set_field:%d->reg%d,'
                    'resubmit(,%d)' % (
                        ovs_port.ofport,
                        fwaas_ovs_consts.REG_PORT,
                        vlan_tag,
                        fwaas_ovs_consts.REG_NET,
                        fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE)
        )
        self._add_flow(
            table=fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE,
            priority=80,
            reg_port=ovs_port.ofport,
            actions='normal',
        )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _remove_egress_no_port_security(self, port_id):
        try:
            ofport = self.fwg_port_map.unfiltered[port_id]
        except KeyError:
            LOG.debug("Port %s is not handled by the firewall.", port_id)
            return
        self._delete_flows(
            table=ovs_consts.TRANSIENT_TABLE,
            in_port=ofport
        )
        self._delete_flows(
            table=fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE,
            reg_port=ofport
        )
        del self.fwg_port_map.unfiltered[port_id]

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _initialize_egress(self, port):
        """Identify egress traffic and send it to egress base"""
        self._initialize_egress_ipv6_icmp(port)

        # Apply mac/ip pairs for IPv4
        allowed_pairs = port.allowed_pairs_v4.union(
            {(port.mac, ip_addr) for ip_addr in port.ipv4_addresses})
        for mac_addr, ip_addr in allowed_pairs:
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
                priority=95,
                in_port=port.ofport,
                reg_port=port.ofport,
                dl_src=mac_addr,
                dl_type=constants.ETHERTYPE_ARP,
                arp_spa=ip_addr,
                actions='normal'
            )
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
                priority=65,
                reg_port=port.ofport,
                ct_state=fwaas_ovs_consts.OF_STATE_NOT_TRACKED,
                dl_type=constants.ETHERTYPE_IP,
                in_port=port.ofport,
                dl_src=mac_addr,
                nw_src=ip_addr,
                actions='ct(table={:d},zone=NXM_NX_REG{:d}[0..15])'.format(
                    fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
                    fwaas_ovs_consts.REG_NET)
            )

        # Apply mac/ip pairs for IPv6
        allowed_pairs = port.allowed_pairs_v6.union(
            {(port.mac, ip_addr) for ip_addr in port.ipv6_addresses})
        for mac_addr, ip_addr in allowed_pairs:
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
                priority=65,
                reg_port=port.ofport,
                in_port=port.ofport,
                ct_state=fwaas_ovs_consts.OF_STATE_NOT_TRACKED,
                dl_type=constants.ETHERTYPE_IPV6,
                dl_src=mac_addr,
                ipv6_src=ip_addr,
                actions='ct(table={:d},zone=NXM_NX_REG{:d}[0..15])'.format(
                    fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
                    fwaas_ovs_consts.REG_NET)
            )

        # DHCP discovery
        accept_or_ingress = fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE
        if self.sg_with_ovs:
            accept_or_ingress = ovs_consts.ACCEPT_OR_INGRESS_TABLE
        for dl_type, src_port, dst_port in (
                (constants.ETHERTYPE_IP, 68, 67),
                (constants.ETHERTYPE_IPV6, 546, 547)):
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
                priority=80,
                reg_port=port.ofport,
                in_port=port.ofport,
                dl_type=dl_type,
                nw_proto=lib_const.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='resubmit(,{:d})'.format(accept_or_ingress)
            )
        # Ban dhcp service running on an instance
        for dl_type, src_port, dst_port in (
                (constants.ETHERTYPE_IP, 67, 68),
                (constants.ETHERTYPE_IPV6, 547, 546)):
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
                priority=70,
                in_port=port.ofport,
                reg_port=port.ofport,
                dl_type=dl_type,
                nw_proto=lib_const.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
            )

        # Drop Router Advertisements from instances
        self._add_flow(
            table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
            priority=70,
            in_port=port.ofport,
            reg_port=port.ofport,
            dl_type=constants.ETHERTYPE_IPV6,
            nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
            icmp_type=lib_const.ICMPV6_TYPE_RA,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        # Drop all remaining not tracked egress connections
        self._add_flow(
            table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE,
            priority=10,
            ct_state=fwaas_ovs_consts.OF_STATE_NOT_TRACKED,
            in_port=port.ofport,
            reg_port=port.ofport,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        # Fill in accept_or_ingress table by checking that traffic is ingress
        # and if not, accept it
        if self.sg_with_ovs:
            self._fwaas_process_colocated_ingress(port)
        else:
            for mac_addr in port.all_allowed_macs:
                self._add_flow(
                    table=fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE,
                    priority=100,
                    dl_dst=mac_addr,
                    reg_net=port.vlan_tag,
                    actions='set_field:{:d}->reg{:d},resubmit(,{:d})'.format(
                        port.ofport,
                        fwaas_ovs_consts.REG_PORT,
                        fwaas_ovs_consts.FW_BASE_INGRESS_TABLE),
                )
            for ethertype in [constants.ETHERTYPE_IP,
                    constants.ETHERTYPE_IPV6]:
                self._add_flow(
                    table=fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE,
                    priority=90,
                    dl_type=ethertype,
                    reg_port=port.ofport,
                    ct_state=fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED,
                    actions='ct(commit,zone=NXM_NX_REG{:d}[0..15]),'
                            'resubmit(,{:d})'.format(
                                fwaas_ovs_consts.REG_NET,
                                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE)
                )
            self._add_flow(
                table=fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE,
                priority=80,
                reg_port=port.ofport,
                actions='normal'
            )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _initialize_tracked_egress(self, port):
        # Drop invalid packets
        self._add_flow(
            table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
            priority=50,
            ct_state=fwaas_ovs_consts.OF_STATE_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        # Drop traffic for removed fwg rules
        self._add_flow(
            table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
            priority=50,
            reg_port=port.ofport,
            ct_mark=fwaas_ovs_consts.CT_MARK_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        for state in (
            fwaas_ovs_consts.OF_STATE_ESTABLISHED_REPLY,
            fwaas_ovs_consts.OF_STATE_RELATED,
        ):
            self._add_flow(
                table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
                priority=50,
                ct_state=state,
                ct_mark=fwaas_ovs_consts.CT_MARK_NORMAL,
                reg_port=port.ofport,
                ct_zone=port.vlan_tag,
                actions='normal'
            )
        self._add_flow(
            table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
            priority=40,
            reg_port=port.ofport,
            ct_state=fwaas_ovs_consts.OF_STATE_NOT_ESTABLISHED,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        for ethertype in [constants.ETHERTYPE_IP, constants.ETHERTYPE_IPV6]:
            self._add_flow(
                table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE,
                priority=40,
                dl_type=ethertype,
                reg_port=port.ofport,
                ct_state=fwaas_ovs_consts.OF_STATE_ESTABLISHED,
                actions="ct(commit,zone=NXM_NX_REG{:d}[0..15],"
                        "exec(set_field:{:s}->ct_mark))".format(
                            fwaas_ovs_consts.REG_NET,
                            fwaas_ovs_consts.CT_MARK_INVALID)
            )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _initialize_ingress_ipv6_icmp(self, port):
        for icmp_type in firewall.ICMPV6_ALLOWED_INGRESS_TYPES:
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_INGRESS_TABLE,
                priority=100,
                reg_port=port.ofport,
                dl_dst=port.mac,
                dl_type=constants.ETHERTYPE_IPV6,
                nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
                icmp_type=icmp_type,
                actions='output:{:d}'.format(port.ofport)
            )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _initialize_ingress(self, port):
        # Allow incoming ARPs
        self._add_flow(
            table=fwaas_ovs_consts.FW_BASE_INGRESS_TABLE,
            priority=100,
            dl_type=constants.ETHERTYPE_ARP,
            reg_port=port.ofport,
            actions='output:{:d}'.format(port.ofport)
        )
        self._initialize_ingress_ipv6_icmp(port)

        # DHCP offers
        for dl_type, src_port, dst_port in (
                (constants.ETHERTYPE_IP, 67, 68),
                (constants.ETHERTYPE_IPV6, 547, 546)):
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_INGRESS_TABLE,
                priority=95,
                reg_port=port.ofport,
                dl_type=dl_type,
                nw_proto=lib_const.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='output:{:d}'.format(port.ofport)
            )

        # Track untracked
        for dl_type in (constants.ETHERTYPE_IP, constants.ETHERTYPE_IPV6):
            self._add_flow(
                table=fwaas_ovs_consts.FW_BASE_INGRESS_TABLE,
                priority=90,
                reg_port=port.ofport,
                dl_type=dl_type,
                ct_state=fwaas_ovs_consts.OF_STATE_NOT_TRACKED,
                actions='ct(table={:d},zone=NXM_NX_REG{:d}[0..15])'.format(
                    fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
                    fwaas_ovs_consts.REG_NET)
            )
        self._add_flow(
            table=fwaas_ovs_consts.FW_BASE_INGRESS_TABLE,
            ct_state=fwaas_ovs_consts.OF_STATE_TRACKED,
            priority=80,
            reg_port=port.ofport,
            actions='resubmit(,{:d})'.format(
                fwaas_ovs_consts.FW_RULES_INGRESS_TABLE)
        )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def _initialize_tracked_ingress(self, port):
        # Drop invalid packets
        self._add_flow(
            table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
            priority=50,
            ct_state=fwaas_ovs_consts.OF_STATE_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        # Drop traffic for removed fwg rules
        self._add_flow(
            table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
            priority=50,
            reg_port=port.ofport,
            ct_mark=fwaas_ovs_consts.CT_MARK_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        # Allow established and related connections
        for state in (fwaas_ovs_consts.OF_STATE_ESTABLISHED_REPLY,
                      fwaas_ovs_consts.OF_STATE_RELATED):
            self._add_flow(
                table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
                priority=50,
                reg_port=port.ofport,
                ct_state=state,
                ct_mark=fwaas_ovs_consts.CT_MARK_NORMAL,
                ct_zone=port.vlan_tag,
                actions='output:{:d}'.format(port.ofport)
            )
        self._add_flow(
            table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
            priority=40,
            reg_port=port.ofport,
            ct_state=fwaas_ovs_consts.OF_STATE_NOT_ESTABLISHED,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        for ethertype in [constants.ETHERTYPE_IP, constants.ETHERTYPE_IPV6]:
            self._add_flow(
                table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
                priority=40,
                dl_type=ethertype,
                reg_port=port.ofport,
                ct_state=fwaas_ovs_consts.OF_STATE_ESTABLISHED,
                actions="ct(commit,zone=NXM_NX_REG{:d}[0..15],"
                        "exec(set_field:{:s}->ct_mark))".format(
                            fwaas_ovs_consts.REG_NET,
                            fwaas_ovs_consts.CT_MARK_INVALID)
            )

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers) and rules_generator method
    def add_flows_from_rules(self, port):
        self._initialize_tracked_ingress(port)
        self._initialize_tracked_egress(port)
        LOG.debug('Creating flow rules for port %s that is port %d in OVS',
                  port.id, port.ofport)
        for rule in self.create_rules_generator_for_port(port):
            flows = rules.create_flows_from_rule_and_port(rule, port)
            LOG.debug("RULGEN: Rules generated for flow %s are %s",
                      rule, flows)
            for flow in flows:
                if rule.get('action') == ACTION_ALLOW:
                    self._accept_flow(**flow)
                else:
                    self._drop_flow(**flow)

    def create_rules_generator_for_port(self, port):
        """Returns a generator emitting rules valid for further processing

        Injects necessary fields to feed one-by-one to rules module to
        transform into valid openflow rules.
        """

        def inject_fields(rule, direction, offset=0):
            """Add fields to rule dict to be able to utilize rules module

            Currently such fields are added:
            'offset', 'direction', 'ethertype', 'source_port_range_min',
            'source_port_range_max', 'port_range_min', 'port_range_max'
            """
            # XXX NOTE(ivasilevskaya) maybe there's a clever way to do that
            version_ethertype_map = {lib_const.IP_VERSION_4: lib_const.IPv4,
                                     lib_const.IP_VERSION_6: lib_const.IPv6}

            rule['direction'] = direction
            rule['ethertype'] = version_ethertype_map[rule['ip_version']]
            rule['offset'] = offset

            # transfer destination_port into port_range_min/port_range_max
            def add_range(range_key, key_min, key_max):
                range_str = rule.get(range_key)
                if not range_str:
                    return
                ports = range_str.split(':', 1)
                rule[key_min] = int(ports[0])
                rule['port_range_max'] = (
                    int(ports[1]) if len(ports) == 2 else int(ports[0]))

            add_range('destination_port', 'port_range_min', 'port_range_max')
            add_range('source_port', 'source_port_range_min',
                      'source_port_range_max')

        # add direction field
        offset = len(port.fw_group.ingress_rules) - 1
        for rule in port.fw_group.ingress_rules:
            inject_fields(rule, lib_const.INGRESS_DIRECTION, offset)
            offset -= 1
            yield rule

        offset = len(port.fw_group.egress_rules) - 1
        for rule in port.fw_group.egress_rules:
            inject_fields(rule, lib_const.EGRESS_DIRECTION, offset)
            offset -= 1
            yield rule

    # NOTE(ivasilevskaya) That's a copy-paste from neutron ovsfw driver
    # which differs in constants (table numbers)
    def delete_all_port_flows(self, port):
        """Delete all flows for given port"""
        accept_or_ingress = fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE
        if self.sg_with_ovs:
            accept_or_ingress = ovs_consts.ACCEPT_OR_INGRESS_TABLE

        for mac_addr in port.all_allowed_macs:
            self._strict_delete_flow(priority=95,
                                     table=ovs_consts.TRANSIENT_TABLE,
                                     dl_dst=mac_addr,
                                     dl_vlan=port.vlan_tag)
            self._delete_flows(
                table=accept_or_ingress,
                dl_dst=mac_addr, reg_net=port.vlan_tag)
        self._strict_delete_flow(priority=105,
                                 table=ovs_consts.TRANSIENT_TABLE,
                                 in_port=port.ofport)
        self._delete_flows(reg_port=port.ofport)

    def create_firewall_group(self, ports_for_fwg, firewall_group):
        egress_rules = firewall_group['egress_rule_list']
        ingress_rules = firewall_group['ingress_rule_list']
        fwg_id = firewall_group['id']

        self.update_firewall_group_rules(fwg_id, ingress_rules, egress_rules)
        for port in ports_for_fwg:
            port['firewall_group'] = fwg_id
            self.update_port_filter(port)

    def update_firewall_group(self, ports_for_fwg, firewall_group):
        self.create_firewall_group(ports_for_fwg, firewall_group)

    def delete_firewall_group(self, ports_for_fwg, firewall_group):
        for port in ports_for_fwg:
            port['firewall_group'] = firewall_group['id']
            self.remove_port_filter(port)
