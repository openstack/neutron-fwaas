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

from unittest import mock

from neutron_fwaas.services.firewall.service_drivers.agents.drivers.linux \
    import netlink_conntrack
from neutron_fwaas.tests import base

FW_RULES = [
    {'position': '1',
     'protocol': 'icmp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule1'},
    {'source_port': '0:10',
     'destination_port': '0:10',
     'position': '2',
     'protocol': 'tcp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule2'},
    {'source_port': '0:10',
     'destination_port': '0:20',
     'position': '3',
     'protocol': 'udp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule3'},
    {'source_port': None,
     'destination_port': '0:10',
     'position': '2',
     'protocol': 'tcp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule5'},
    {'source_port': '0:10',
     'destination_port': None,
     'position': '3',
     'protocol': 'udp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule5'},
]

ICMP_ENTRY = (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', '1234')
TCP_ENTRY = (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
UDP_ENTRY = (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')

ROUTER_NAMESPACE = 'qrouter-fake-namespace'


class ConntrackNetlinkTestCase(base.BaseTestCase):
    def setUp(self):
        super(ConntrackNetlinkTestCase, self).setUp()
        self.conntrack_driver = netlink_conntrack.ConntrackNetlink()
        self.conntrack_driver.initialize()
        nl_flush_entries = mock.patch('neutron_fwaas.privileged.'
                                      'netlink_lib.flush_entries')
        self.flush_entries = nl_flush_entries.start()
        nl_list_entries = mock.patch('neutron_fwaas.privileged.'
                                     'netlink_lib.list_entries')
        self.list_entries = nl_list_entries.start()
        nl_delete_entries = mock.patch('neutron_fwaas.privileged.'
                                     'netlink_lib.delete_entries')
        self.delete_entries = nl_delete_entries.start()

    def test_flush_entries(self):
        self.conntrack_driver.flush_entries(ROUTER_NAMESPACE)
        self.flush_entries.assert_called_with(ROUTER_NAMESPACE)

    def test_delete_with_empty_conntrack_entries(self):
        self.list_entries.return_value = []
        self.conntrack_driver.delete_entries([], ROUTER_NAMESPACE)
        self.list_entries.assert_called_with(ROUTER_NAMESPACE)
        self.delete_entries.assert_not_called()

    def test_delete_icmp_entry(self):
        """Testing delete an icmp entry

        The icmp entry can be deleted if there is an icmp conntrack entry
        matched with an icmp firewall rule.
        The information passing to nl_lib.kill_entry will include:
        (ipversion, protocol, icmp_type, icmp_code, src_address, dst_addres,
        icmp_ip)
        """
        self.list_entries.return_value = [ICMP_ENTRY]
        self.conntrack_driver.delete_entries(FW_RULES, ROUTER_NAMESPACE)
        self.list_entries.assert_called_with(ROUTER_NAMESPACE)
        self.delete_entries.assert_called_with([(4, 'icmp', 8, 0,
                                                 '1.1.1.1', '2.2.2.2',
                                                 '1234')], ROUTER_NAMESPACE)

    def test_delete_tcp_entry(self):
        """Testing delete a tcp entry

        The tcp entry can be deleted if there is a tcp conntrack entry
        matched with a tcp firewall rule.
        The information passing to nl_lib.kill_entry will include:
        (ipversion, protocol, src_port, dst_port, src_address, dst_addres)
        """
        self.list_entries.return_value = [TCP_ENTRY]
        self.conntrack_driver.delete_entries(FW_RULES, ROUTER_NAMESPACE)
        self.list_entries.assert_called_with(ROUTER_NAMESPACE)
        self.delete_entries.assert_called_with(
                [(4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')], ROUTER_NAMESPACE)

    def test_delete_udp_entry(self):
        """Testing delete an udp entry

        The udp entry can be deleted if there is an udp conntrack entry
        matched with an udp firewall rule.
        The information passing to nl_lib.kill_entry will include:
        (ipversion, protocol, src_port, dst_port, src_address, dst_addres)
        """
        self.list_entries.return_value = [UDP_ENTRY]
        self.conntrack_driver.delete_entries(FW_RULES, ROUTER_NAMESPACE)
        self.list_entries.assert_called_with(ROUTER_NAMESPACE)
        self.delete_entries.assert_called_with(
                [(4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')], ROUTER_NAMESPACE)

    def test_delete_multiple_entries(self):
        self.list_entries.return_value = [ICMP_ENTRY, TCP_ENTRY, UDP_ENTRY]
        self.conntrack_driver.delete_entries(FW_RULES, ROUTER_NAMESPACE)
        self.list_entries.assert_called_with(ROUTER_NAMESPACE)
        self.delete_entries.assert_called_with(
                [(4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', '1234'),
                 (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2'),
                 (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')], ROUTER_NAMESPACE)

    def _test_entry_to_delete(self, rule_filter, entry, expect_result):
        is_entry_to_delete = (
            self.conntrack_driver._compare_entry_and_rule(rule_filter, entry))
        self.assertEqual(expect_result, is_entry_to_delete)

    def test_icmp_entry_match_rule(self):
        entry = (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', '1234')
        rule_filter = (4, 'icmp', None, None)
        self._test_entry_to_delete(rule_filter, entry, 0)

    def test_tcp_entry_match_rule(self):
        entry = (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
        rule_filters = [(4, 'tcp', None, None),
                        (4, 'tcp', [1], None),
                        (4, 'tcp', None, [2]),
                        (4, 'tcp', [1], [2]),
                        (4, 'tcp', ['0', '10'], ['0', '10']), ]
        for rule_filter in rule_filters:
            self._test_entry_to_delete(rule_filter, entry, 0)

    def test_udp_entry_match_rule(self):
        entry = (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')
        rule_filters = [(4, 'udp', None, None),
                        (4, 'udp', [1], None),
                        (4, 'udp', None, [2]),
                        (4, 'udp', [1], [2]),
                        (4, 'udp', ['0', '10'], ['0', '10']), ]
        for rule_filter in rule_filters:
            self._test_entry_to_delete(rule_filter, entry, 0)

    def test_entry_unmatch_rule(self):
        wrong_ipv = [(4, 'tcp', '1', '2', '1.1.1.1', '2.2.2.2'),
                     (6, 'tcp', None, None), -1]
        wrong_proto = [(4, 'tcp', '1', '2', '1.1.1.1', '2.2.2.2'),
                       (4, 'udp', None, None), -1]
        not_in_sport_range = [(4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2'),
                              (4, 'tcp', ['2', '100'], [2]), -1]
        not_in_dport_range = [(4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2'),
                              (4, 'tcp', [1], ['3', '100']), -1]
        for entry, rule_filter, expect in [
            wrong_ipv, wrong_proto, not_in_sport_range, not_in_dport_range]:
            self._test_entry_to_delete(rule_filter, entry, expect)

    def test_get_filter_from_rules(self):
        fw_rule_icmp = FW_RULES[0]
        fw_rule_port_range = FW_RULES[1]
        fw_rule_dest_port = FW_RULES[3]
        fw_rule_source_port = FW_RULES[4]

        # filter format:
        # ('ip_version', 'protocol', 'source_port', 'destination_port',
        #        'source_ip_address', 'destination_ip_address')

        expected_icmp_filter = (4, 'icmp', [], [], [], [])
        expected_port_range_filter = (4, 'tcp', ['0', '10'], ['0', '10'],
                                      [], [])
        expected_dest_port_filter = (4, 'tcp', [], ['0', '10'], [], [])
        expected_source_port_filter = (4, 'udp', ['0', '10'], [], [], [])

        actual_icmp_filter = self.conntrack_driver._get_filter_from_rule(
            fw_rule_icmp)
        actual_port_range_filter = \
            self.conntrack_driver._get_filter_from_rule(fw_rule_port_range)
        actual_dest_port_filter = \
            self.conntrack_driver._get_filter_from_rule(fw_rule_dest_port)
        actual_source_port_filter = \
            self.conntrack_driver._get_filter_from_rule(fw_rule_source_port)

        self.assertEqual(expected_icmp_filter, actual_icmp_filter)
        self.assertEqual(expected_port_range_filter, actual_port_range_filter)
        self.assertEqual(expected_dest_port_filter, actual_dest_port_filter)
        self.assertEqual(expected_source_port_filter,
                         actual_source_port_filter)

    def test_get_entries_to_delete(self):
        rule_filters = sorted(
                [(4, 'tcp', ['0', '10'], ['1', '10']),
                 (4, 'udp', ['0', '10'], ['0', '10']),
                 (4, 'icmp', None, None)])
        TCP_ENTRY_IN_RANGE = (4, 'tcp', 2, 3, '1.1.1.1', '2.2.2.2')
        TCP_ENTRY_OUT_RANGE = (4, 'tcp', 22, 100, '1.1.1.1', '2.2.2.2')
        UDP_ENTRY_IN_RANGE = (4, 'udp', 3, 4, '1.1.1.1', '2.2.2.2')
        UDP_ENTRY_OUT_RANGE = (4, 'udp', 100, 200, '1.1.1.1', '2.2.2.2')
        self.list_entries.return_value = sorted(
                [ICMP_ENTRY, TCP_ENTRY, UDP_ENTRY,
                 TCP_ENTRY_IN_RANGE, TCP_ENTRY_OUT_RANGE,
                 UDP_ENTRY_IN_RANGE, UDP_ENTRY_OUT_RANGE])
        expected_delete_entries = sorted(
                [ICMP_ENTRY, TCP_ENTRY, UDP_ENTRY,
                 TCP_ENTRY_IN_RANGE, UDP_ENTRY_IN_RANGE])
        actual_delete_entries = self.conntrack_driver._get_entries_to_delete(
                rule_filters, self.list_entries())
        self.assertEqual(expected_delete_entries, actual_delete_entries)
