# Copyright 2022 EasyStack, Inc.
# All rights reserved.
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

from neutron.common.ovn import utils as ovn_utils
from neutron_lib import constants as const

from neutron_fwaas.services.firewall.service_drivers.ovn import \
    constants as ovn_const
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    exceptions as ovn_fw_exc


def acl_direction(direction, port_group=None):
    if direction == const.INGRESS_DIRECTION:
        portdir = 'inport'
    else:
        portdir = 'outport'
    return '%s == @%s' % (portdir, port_group)


def acl_ethertype(rule):
    match = ''
    ip_version = None
    icmp = None
    if rule['ip_version'] == const.IP_VERSION_4:
        match = ' && ip4'
        ip_version = 'ip4'
        icmp = 'icmp4'
    elif rule['ip_version'] == const.IP_VERSION_6:
        match = ' && ip6'
        ip_version = 'ip6'
        icmp = 'icmp6'
    return match, ip_version, icmp


def acl_ip(rule, ip_version):
    src_ip = rule.get('source_ip_address')
    dst_ip = rule.get('destination_ip_address')
    src = ' && %s.src == %s' % (ip_version, src_ip) if src_ip else ''
    dst = ' && %s.dst == %s' % (ip_version, dst_ip) if dst_ip else ''
    return src + dst


def get_min_max_ports_from_range(port_range):
    if not port_range:
        return [None, None]
    min_port, sep, max_port = port_range.partition(":")
    if not max_port:
        max_port = min_port
    return [int(min_port), int(max_port)]


def acl_protocol_ports(protocol, port_range, is_dst=True):
    match = ''
    min_port, max_port = get_min_max_ports_from_range(port_range)
    dir = 'dst' if is_dst else 'src'
    if protocol in ovn_const.TRANSPORT_PROTOCOLS:
        if min_port is not None and min_port == max_port:
            match += ' && %s.%s == %d' % (protocol, dir, min_port)
        else:
            if min_port is not None:
                match += ' && %s.%s >= %d' % (protocol, dir, min_port)
            if max_port is not None:
                match += ' && %s.%s <= %d' % (protocol, dir, max_port)
    return match


def acl_protocol_and_ports(rule, icmp):
    match = ''
    protocol = rule.get('protocol')
    if protocol is None:
        return match
    src_port = rule.get('source_port')
    dst_port = rule.get('destination_port')
    if protocol in ovn_const.TRANSPORT_PROTOCOLS:
        match += ' && %s' % protocol
        match += acl_protocol_ports(protocol, src_port, is_dst=False)
        match += acl_protocol_ports(protocol, dst_port)
    elif protocol in ovn_const.ICMP_PROTOCOLS:
        protocol = icmp
        match += ' && %s' % protocol
    return match


def acl_action_and_priority(rule, direction):
    action = rule['action']
    pos = rule.get('position', 0)
    if action == 'deny' and rule.get(ovn_const.DEFAULT_RULE, False):
        return (ovn_const.ACL_ACTION_DROP,
                ovn_const.ACL_PRIORITY_DEFAULT)
    if direction == const.INGRESS_DIRECTION:
        priority = ovn_const.ACL_PRIORITY_INGRESS
    else:
        priority = ovn_const.ACL_PRIORITY_EGRESS
    if action == 'allow':
        return (ovn_const.ACL_ACTION_ALLOW_STATELESS,
                priority - pos)
    elif action == 'deny':
        return (ovn_const.ACL_ACTION_DROP,
                priority - pos)
    elif action == 'reject':
        return (ovn_const.ACL_ACTION_REJECT,
                priority - pos)


def acl_entry_for_port_group(port_group, rule, direction, match):
    dir_map = {const.INGRESS_DIRECTION: 'from-lport',
               const.EGRESS_DIRECTION: 'to-lport'}
    action, priority = acl_action_and_priority(rule, direction)

    acl = {"port_group": port_group,
           "priority": priority,
           "action": action,
           "log": False,
           "name": [],
           "severity": [],
           "direction": dir_map[direction],
           "match": match,
           ovn_const.OVN_FWR_EXT_ID_KEY: rule['id']}
    return acl


def get_rule_acl_for_port_group(port_group, rule, direction):
    match = acl_direction(direction, port_group=port_group)
    ip_match, ip_version, icmp = acl_ethertype(rule)
    match += ip_match
    match += acl_ip(rule, ip_version)
    match += acl_protocol_and_ports(rule, icmp)
    return acl_entry_for_port_group(port_group, rule, direction, match)


def update_ports_for_pg(nb_idl, txn, pg_name, ports_add=None,
                        ports_delete=None):
    if ports_add is None:
        ports_add = []
    if ports_delete is None:
        ports_delete = []
    # Add ports to port_group
    for port_id in ports_add:
        txn.add(nb_idl.pg_add_ports(
            pg_name, port_id))
    for port_id in ports_delete:
        txn.add(nb_idl.pg_del_ports(
            pg_name, port_id, if_exists=True))


def get_default_acls_for_pg(nb_idl, pg_name):
    nb_acls = nb_idl.pg_acl_list(pg_name).execute(check_error=True)
    default_acl_list = []
    for nb_acl in nb_acls:
        # Get acl whose external_ids has firewall_rule_id, then
        # append it to list if its value equal to default_rule_id
        ext_ids = getattr(nb_acl, 'external_ids', {})
        if (ext_ids.get(ovn_const.OVN_FWR_EXT_ID_KEY) ==
                ovn_const.DEFAULT_RULE_ID):
            default_acl_list.append(nb_acl.uuid)
    return default_acl_list


def process_rule_for_pg(nb_idl, txn, pg_name, rule, direction,
                        op=ovn_const.OP_ADD):
    dir_map = {const.INGRESS_DIRECTION: 'from-lport',
               const.EGRESS_DIRECTION: 'to-lport'}
    supported_ops = [ovn_const.OP_ADD, ovn_const.OP_DEL,
                     ovn_const.OP_MOD]
    if op not in supported_ops:
        raise ovn_fw_exc.OperatorNotSupported(
            operator=op, valid_operators=supported_ops)

    acl = get_rule_acl_for_port_group(
        pg_name, rule, direction)

    # Add acl
    if op == ovn_const.OP_ADD:
        txn.add(nb_idl.pg_acl_add(**acl, may_exist=True))
    # Modify/Delete acl
    else:
        nb_acls = nb_idl.pg_acl_list(pg_name).execute(check_error=True)
        for nb_acl in nb_acls:
            # Get acl whose external_ids has firewall_rule_id,
            # then change it if its value equal to rule's
            ext_ids = getattr(nb_acl, 'external_ids', {})
            if (ext_ids.get(ovn_const.OVN_FWR_EXT_ID_KEY) ==
                    rule['id'] and dir_map[direction] == nb_acl.direction):
                if op == ovn_const.OP_MOD:
                    txn.add(nb_idl.db_set(
                        'ACL', nb_acl.uuid,
                        ('match', acl['match']),
                        ('action', acl['action'])))
                elif op == ovn_const.OP_DEL:
                    txn.add(nb_idl.pg_acl_del(
                        acl['port_group'],
                        acl['direction'],
                        nb_acl.priority,
                        acl['match']))
                break


def create_pg_for_fwg(nb_idl, fwg_id):
    pg_name = ovn_utils.ovn_port_group_name(fwg_id)
    # Add port_group
    with nb_idl.transaction(check_error=True) as txn:
        ext_ids = {ovn_const.OVN_FWG_EXT_ID_KEY: fwg_id}
        txn.add(nb_idl.pg_add(name=pg_name, acls=[],
                              external_ids=ext_ids))


def add_default_acls_for_pg(nb_idl, txn, pg_name):
    # Traffic is default denied, ipv4 or ipv6 with two directions,
    # so number of default acls is 4
    default_rule_v4 = {'action': 'deny', 'ip_version': 4,
                       'id': ovn_const.DEFAULT_RULE_ID,
                       ovn_const.DEFAULT_RULE: True}
    default_rule_v6 = {'action': 'deny', 'ip_version': 6,
                       'id': ovn_const.DEFAULT_RULE_ID,
                       ovn_const.DEFAULT_RULE: True}
    for dir in [const.EGRESS_DIRECTION, const.INGRESS_DIRECTION]:
        process_rule_for_pg(nb_idl, txn, pg_name,
                            default_rule_v4,
                            dir,
                            op=ovn_const.OP_ADD)
        process_rule_for_pg(nb_idl, txn, pg_name,
                            default_rule_v6,
                            dir,
                            op=ovn_const.OP_ADD)
