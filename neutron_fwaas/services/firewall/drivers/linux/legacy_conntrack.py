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

from neutron.agent.linux import utils as linux_utils
from neutron_lib import constants
from oslo_log import log as logging

from neutron_fwaas.services.firewall.drivers import conntrack_base


LOG = logging.getLogger(__name__)

IP_VERSIONS = [constants.IP_VERSION_4, constants.IP_VERSION_6]

ATTR_POSITIONS = {
    'icmp': (('type', 5), ('code', 6), ('src', 3), ('dst', 4), ('id', 7)),
    'icmpv6': (('type', 5), ('code', 6), ('src', 3), ('dst', 4), ('id', 7)),
    'tcp': (('sport', 6), ('dport', 7), ('src', 4), ('dst', 5)),
    'udp': (('sport', 5), ('dport', 6), ('src', 3), ('dst', 4))
}


class ConntrackLegacy(conntrack_base.ConntrackDriverBase):
    def initialize(self, execute=None):
        LOG.debug('Initialize Conntrack Legacy')
        self.execute = execute or linux_utils.execute

    def flush_entries(self, namespace):
        prefixcmd = ['ip', 'netns', 'exec', namespace] if namespace else []
        cmd = prefixcmd + ['conntrack', '-D']
        self._execute_command(cmd)

    def delete_entries(self, rules, namespace):
        rule_filters = sorted(self._get_filter_from_rule(r) for r in rules)
        delete_entries = self._get_entries_to_delete(
            rule_filters, self.list_entries(namespace))
        for delete_entry in delete_entries:
            cmd = self._get_conntrack_cmd_from_entry(delete_entry, namespace)
            self._execute_command(cmd)

    def _execute_command(self, cmd):
        try:
            output = self.execute(cmd,
                                  run_as_root=True,
                                  check_exit_code=True,
                                  extra_ok_codes=[1])
        except RuntimeError:
            msg = "Failed execute conntrack command %s" % cmd
            raise RuntimeError(msg)
        return output

    def list_entries(self, namespace):
        """List and parse all conntrack entries

        :param namespace: namespace to get conntrack entries
        :returns: sorted list of conntrack entries in Python tuple
            for example: [(4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 1234),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')]
        """
        parsed_entries = []
        prefixcmd = ['ip', 'netns', 'exec', namespace] if namespace else []
        for ip_version in IP_VERSIONS:
            cmd = prefixcmd + ['conntrack', '-L',
                               '-f', 'ipv' + str(ip_version)]
            raw_entries = self._execute_command(cmd).splitlines()
            for raw_entry in raw_entries:
                parsed_entry = self._parse_entry(raw_entry.split(), ip_version)
                if parsed_entry is not None:
                    parsed_entries.append(parsed_entry)
        return sorted(parsed_entries)

    def _get_conntrack_cmd_from_entry(self, entry, namespace):
        prefixcmd = ['ip', 'netns', 'exec', namespace] if namespace else []
        cmd = ['conntrack', '-D']
        contrack_filter = ['-f', 'ipv' + str(entry[0]), '-p', entry[1]]
        if entry[1] in ['icmp', 'icmpv6']:
            contrack_filter.extend(['--icmp-type', entry[2],
                                    '--icmp-code', entry[3],
                                    '-s', entry[4],
                                    '-d', entry[5],
                                    '--icmp-id', entry[6]])
        else:
            contrack_filter.extend(['--sport', entry[2],
                                    '--dport', entry[3],
                                    '-s', entry[4],
                                    '-d', entry[5]])
        exec_cmd = prefixcmd + cmd + contrack_filter
        return exec_cmd

    def _parse_entry(self, entry, ip_version):
        """Parse entry from text to Python tuple

        :param entry: conntrack entry as a list of string
        :param ip_version: ip version 4 or 6
        :returns: conntrack entry in Python tuple
        for example: (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
        The attributes are ordered to be easy to compare with other entries
        and compare with firewall rule
        """
        protocol = entry[0]
        if protocol not in ATTR_POSITIONS:
            LOG.warning(
                'Skipping conntrack entry %s with unsupported protocol', entry)
            return None

        parsed_entry = [ip_version, protocol]
        for attr, position in ATTR_POSITIONS[protocol]:
            val = entry[position].partition('=')[2]
            parsed_entry.append(int(val) if attr in ['sport', 'dport', 'type',
                                                     'code', 'id'] else val)
        return tuple(parsed_entry)

    def _get_entries_to_delete(self, rule_filters, entries):
        """Specify conntrack entries to delete

        :param rule_filters: List of filters parsed from firewall rules
        :param entries: all entries within namespace
        :returns: conntrack entries to delete
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
                comp = self._compare_entry_and_rule_filter(
                    rule_filter, entries[entry_index])
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
        :returns: a tuple of parsed information
        """
        rule_filter = []
        keys = ('ip_version', 'protocol',
                'source_port', 'destination_port',
                'source_ip_address', 'destination_ip_address')
        for key in keys:
            if key in ('source_port', 'destination_port'):
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
    def _compare_entry_and_rule_filter(rule_filter, entry):
        """Define that the entry should be deleted or not

        :param rule_filter: filter that is parsed from a firewall rule
        for example: (4, 'tcp', ['22', '33'], ['44', '55'])
        :param entry: parsed conntrack entry,
        for example: (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
        :returns: -1 if entry is lower than rule
                   0 if entry matches rule,
                   1 if entry is higher than rule
        """
        ENTRY_IS_LOWER = -1
        ENTRY_MATCHES = 0
        ENTRY_IS_HIGHER = 1
        rule_ip_version = rule_filter[0]
        if entry[0] < rule_ip_version:
            return ENTRY_IS_LOWER
        elif entry[0] > rule_ip_version:
            return ENTRY_IS_HIGHER
        rule_protocol = rule_filter[1]
        if rule_protocol == constants.PROTO_NAME_IPV6_ICMP:
            rule_protocol = constants.PROTO_NAME_IPV6_ICMP_LEGACY
        if rule_protocol:
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
