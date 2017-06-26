# Copyright (c) 2017 Fujitsu Limited
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

from neutron_lib import constants
from oslo_log import log as logging

from neutron_fwaas.privileged import netlink_lib as nl_lib
from neutron_fwaas.services.firewall.service_drivers.agents.drivers import\
    conntrack_base

LOG = logging.getLogger(__name__)


class ConntrackNetlink(conntrack_base.ConntrackDriverBase):
    def initialize(self, *args, **kwargs):
        LOG.debug('Conntrack Netlink loaded')

    def flush_entries(self, namespace):
        """Flush all conntrack entries within the namespace

        :param namespace: namespace to flush
        :return: None
        """
        nl_lib.flush_entries(namespace)

    def delete_entries(self, rules, namespace):
        rule_filters = (self._get_filter_from_rule(r) for r in rules)
        rule_filters = sorted(rule_filters)
        entries = nl_lib.list_entries(namespace)
        delete_entries = self._get_entries_to_delete(rule_filters, entries)
        if delete_entries:
            nl_lib.delete_entries(delete_entries, namespace)

    def _get_entries_to_delete(self, rule_filters, entries):
        """Specify conntrack entries to delete

        :param rule_filters: List of filters parsed from firewall rules
        :param entries: all entries within namespace
        :return: conntrack entries to delete
        """
        # List all entries from namespace, they are already parsed
        # to a list of tuples:
        # [(4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 1234),
        #  (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')]
        delete_entries = []
        entry_index = 0
        entry_number = len(entries)
        for rule_filter in rule_filters:
            while entry_index < entry_number:
                # Compare entry with rule
                comp = self._compare_entry_and_rule(rule_filter,
                                                    entries[entry_index])
                # Increase entry_index when entry is under rule
                if comp < 0:
                    entry_index += 1
                # Append entry to delete_entry if it matches with rule
                elif comp == 0:
                    delete_entries.append(entries[entry_index])
                    entry_index += 1
                # Switch to new higher rule
                else:
                    break
        return delete_entries

    @staticmethod
    def _get_filter_from_rule(rule):
        """Parse the firewall rule to a tuple

        :param rule: firewall rule
        :return: a tuple of parsed information
        """
        rule_filter = []
        keys = ['ip_version', 'protocol',
                'source_port', 'destination_port',
                'source_ip_address', 'destination_ip_address']
        for key in keys:
            if key in ['source_port', 'destination_port']:
                port_range = rule.get(key, [])
                if port_range:
                    port_lower, sep, port_upper = port_range.partition(':')
                    port_upper = port_upper if sep else port_lower
                    port_range = [port_lower, port_upper]
                rule_filter.append(port_range or [])
            else:
                rule_filter.append(rule.get(key, []))
        return tuple(rule_filter)

    @staticmethod
    def _compare_entry_and_rule(rule_filter, entry):
        """Define that the entry should be deleted or not

        :param rule_filter: filter that is parsed from a firewall rule
        ex: (4, 'tcp', 1, 2)
        :param entry: parsed conntrack entry,
        ex: (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
        :return: -1 if entry is lower than rule, 0 if entry matches rule,
        1 if entry is higher than rule
        """
        ENTRY_IS_LOWER = -1
        ENTRY_MATCHES = 0
        ENTRY_IS_HIGHER = 1
        rule_ipversion = rule_filter[0]

        if entry[0] < rule_ipversion:
            return ENTRY_IS_LOWER
        elif entry[0] > rule_ipversion:
            return ENTRY_IS_HIGHER
        rule_protocol = rule_filter[1]

        if rule_protocol:
            if rule_protocol == constants.PROTO_NAME_IPV6_ICMP:
                rule_protocol = constants.PROTO_NAME_IPV6_ICMP_LEGACY
            if entry[1] < rule_protocol:
                return ENTRY_IS_LOWER
            elif entry[1] > rule_protocol:
                return ENTRY_IS_HIGHER

        sport_range = rule_filter[2]
        if sport_range:
            sport_range = [int(port) for port in sport_range]
            if entry[2] < min(sport_range[0], sport_range[-1]):
                return ENTRY_IS_LOWER
            elif entry[2] > max(sport_range[0], sport_range[-1]):
                return ENTRY_IS_HIGHER
        dport_range = rule_filter[3]
        if dport_range:
            dport_range = [int(port) for port in dport_range]
            if entry[3] < min(dport_range[0], dport_range[-1]):
                return ENTRY_IS_LOWER
            elif entry[3] > max(dport_range[0], dport_range[-1]):
                return ENTRY_IS_HIGHER
        return ENTRY_MATCHES
