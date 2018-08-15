# Copyright 2015 Red Hat, Inc.
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
from neutron_lib import constants as n_consts
from oslo_log import log as logging

from neutron.common import utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
    as ovs_consts
from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import constants as fwaas_ovs_consts


LOG = logging.getLogger(__name__)

# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver, differs in
# constants
CT_STATES = [
    fwaas_ovs_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
    fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED]

# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver
FLOW_FIELD_FOR_IPVER_AND_DIRECTION = {
    (n_consts.IP_VERSION_4, n_consts.EGRESS_DIRECTION): 'nw_dst',
    (n_consts.IP_VERSION_6, n_consts.EGRESS_DIRECTION): 'ipv6_dst',
    (n_consts.IP_VERSION_4, n_consts.INGRESS_DIRECTION): 'nw_src',
    (n_consts.IP_VERSION_6, n_consts.INGRESS_DIRECTION): 'ipv6_src',
}

# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver
FORBIDDEN_PREFIXES = (n_consts.IPv4_ANY, n_consts.IPv6_ANY)


# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver
def is_valid_prefix(ip_prefix):
    # IPv6 have multiple ways how to describe ::/0 network, converting to
    # IPNetwork and back to string unifies it
    return (ip_prefix and
            str(netaddr.IPNetwork(ip_prefix)) not in FORBIDDEN_PREFIXES)


# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver
def create_flows_from_rule_and_port(rule, port):
    ethertype = rule['ethertype']
    direction = rule['direction']
    dst_ip_prefix = rule.get('dest_ip_prefix')
    src_ip_prefix = rule.get('source_ip_prefix')
    offset = int(rule.get('offset', 0))

    flow_template = {
        'priority': 70 + offset,
        'dl_type': fwaas_ovs_consts.ethertype_to_dl_type_map[ethertype],
        'reg_port': port.ofport,
    }

    if is_valid_prefix(dst_ip_prefix):
        flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
            utils.get_ip_version(dst_ip_prefix), n_consts.EGRESS_DIRECTION)]
        ] = dst_ip_prefix

    if is_valid_prefix(src_ip_prefix):
        flow_template[FLOW_FIELD_FOR_IPVER_AND_DIRECTION[(
            utils.get_ip_version(src_ip_prefix), n_consts.INGRESS_DIRECTION)]
        ] = src_ip_prefix

    flows = create_protocol_flows(direction, flow_template, port, rule)

    return flows


# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver, differs in
# constants
def populate_flow_common(direction, flow_template, port):
    """Initialize common flow fields."""
    if direction == n_consts.INGRESS_DIRECTION:
        flow_template['table'] = fwaas_ovs_consts.FW_RULES_INGRESS_TABLE
        flow_template['actions'] = "output:{:d}".format(port.ofport)
    elif direction == n_consts.EGRESS_DIRECTION:
        flow_template['table'] = fwaas_ovs_consts.FW_RULES_EGRESS_TABLE
        # Traffic can be both ingress and egress, check that no ingress rules
        # should be applied
        flow_template['actions'] = 'resubmit(,{:d})'.format(
            fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE)
    return flow_template


# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver
def create_protocol_flows(direction, flow_template, port, rule):
    flow_template = populate_flow_common(direction,
                                         flow_template.copy(),
                                         port)
    protocol = rule.get('protocol')
    if protocol is not None:
        flow_template['nw_proto'] = protocol

    if protocol in [n_consts.PROTO_NUM_ICMP, n_consts.PROTO_NUM_IPV6_ICMP]:
        flows = create_icmp_flows(flow_template, rule)
    else:
        flows = create_port_range_flows(flow_template, rule)
    return flows or [flow_template]


# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver, differs only in
# constant
def create_port_range_flows(flow_template, rule):
    protocol = fwaas_ovs_consts.REVERSE_IP_PROTOCOL_MAP_WITH_PORTS.get(
        rule.get('protocol'))
    if protocol is None:
        return []
    flows = []
    src_port_match = '{:s}_src'.format(protocol)
    src_port_min = rule.get('source_port_range_min')
    src_port_max = rule.get('source_port_range_max')
    dst_port_match = '{:s}_dst'.format(protocol)
    dst_port_min = rule.get('port_range_min')
    dst_port_max = rule.get('port_range_max')

    dst_port_range = []
    if dst_port_min and dst_port_max:
        dst_port_range = utils.port_rule_masking(dst_port_min, dst_port_max)

    src_port_range = []
    if src_port_min and src_port_max:
        src_port_range = utils.port_rule_masking(src_port_min, src_port_max)
        for port in src_port_range:
            flow = flow_template.copy()
            flow[src_port_match] = port
            if dst_port_range:
                for port in dst_port_range:
                    dst_flow = flow.copy()
                    dst_flow[dst_port_match] = port
                    flows.append(dst_flow)
            else:
                flows.append(flow)
    else:
        for port in dst_port_range:
            flow = flow_template.copy()
            flow[dst_port_match] = port
            flows.append(flow)

    return flows


# NOTE(ivasilevskaya) copy-paste from neutron ovsfw driver
def create_icmp_flows(flow_template, rule):
    icmp_type = rule.get('port_range_min')
    if icmp_type is None:
        return
    flow = flow_template.copy()
    flow['icmp_type'] = icmp_type

    icmp_code = rule.get('port_range_max')
    if icmp_code is not None:
        flow['icmp_code'] = icmp_code
    return [flow]


def resubmit_to_sg(flow):
    if flow['table'] == fwaas_ovs_consts.FW_RULES_EGRESS_TABLE:
        flow['actions'] = 'resubmit(,{:d})'.format(
            ovs_consts.RULES_EGRESS_TABLE)
    if flow['table'] == fwaas_ovs_consts.FW_RULES_INGRESS_TABLE:
        flow['actions'] = 'resubmit(,{:d})'.format(
            ovs_consts.RULES_INGRESS_TABLE)


def create_accept_flows(flow, sg_enabled=False):
    flow['ct_state'] = CT_STATES[0]
    if sg_enabled:
        resubmit_to_sg(flow)
    result = [flow.copy()]
    flow['ct_state'] = CT_STATES[1]
    if sg_enabled:
        resubmit_to_sg(flow)
    elif flow['table'] == fwaas_ovs_consts.FW_RULES_INGRESS_TABLE:
        flow['actions'] = (
            'ct(commit,zone=NXM_NX_REG{:d}[0..15]),{:s},'
            'resubmit(,{:d})'.format(
                fwaas_ovs_consts.REG_NET, flow['actions'],
                ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE)
        )
    result.append(flow)
    return result


def create_drop_flows(flow):
    if flow['table'] in [fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
                         fwaas_ovs_consts.FW_RULES_EGRESS_TABLE]:
        flow['actions'] = 'resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        flow['ct_state'] = fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED
        result = [flow.copy()]
        flow['ct_state'] = fwaas_ovs_consts.OF_STATE_ESTABLISHED_NOT_REPLY
        result.append(flow)
    return result
