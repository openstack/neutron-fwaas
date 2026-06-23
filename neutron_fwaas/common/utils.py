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

import netaddr

from neutron_lib import constants as nl_constants
from neutron_lib.exceptions import firewall_v2 as f_exc


def validate_fwr_protocol_parameters(fwr):
    protocol = fwr.get('protocol')
    source_port = fwr.get('source_port')
    dest_port = fwr.get('destination_port')

    if protocol and protocol not in (nl_constants.PROTO_NAME_TCP,
                                     nl_constants.PROTO_NAME_UDP):
        if source_port or dest_port:
            raise f_exc.FirewallRuleInvalidICMPParameter(
                param="Source, destination port")

    if not protocol and (source_port or dest_port):
        raise f_exc.FirewallRuleWithPortWithoutProtocolInvalid()


def validate_fwr_src_dst_ip_version(fwr, fwr_db=None):
    src_version = dst_version = None
    if fwr.get('source_ip_address', None):
        src_version = netaddr.IPNetwork(fwr['source_ip_address']).version
    if fwr.get('destination_ip_address', None):
        dst_version = netaddr.IPNetwork(
            fwr['destination_ip_address']).version
    rule_ip_version = fwr.get('ip_version', None)
    if not rule_ip_version and fwr_db:
        rule_ip_version = fwr_db.ip_version
    if ((src_version and src_version != rule_ip_version) or
            (dst_version and dst_version != rule_ip_version)):
        raise f_exc.FirewallIpAddressConflict()


def validate_fwr_port_range(min_port, max_port):
    if int(min_port) > int(max_port):
        port_range = '{}:{}'.format(min_port, max_port)
        raise f_exc.FirewallRuleInvalidPortValue(port=port_range)


def get_min_max_ports_from_range(port_range):
    if not port_range:
        return [None, None]
    min_port, sep, max_port = port_range.partition(":")
    if not max_port:
        max_port = min_port
    validate_fwr_port_range(min_port, max_port)
    return [int(min_port), int(max_port)]


def get_port_range_from_min_max_ports(min_port, max_port):
    if not min_port:
        return None
    if min_port == max_port:
        return str(min_port)
    validate_fwr_port_range(min_port, max_port)
    return '{}:{}'.format(min_port, max_port)
