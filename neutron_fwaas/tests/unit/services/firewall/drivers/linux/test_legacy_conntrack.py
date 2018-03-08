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

import mock
import testtools

from neutron.tests import base
from neutron_fwaas.services.firewall.drivers.linux import legacy_conntrack


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
    {'source_port': '1',
     'destination_port': '0:10',
     'position': '4',
     'protocol': 'tcp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule5'},
    {'source_port': '0:10',
     'destination_port': None,
     'position': '5',
     'protocol': 'udp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule5'},
    {'source_port': '1',
     'destination_port': '3',
     'position': '6',
     'protocol': 'tcp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule6'},
    {'source_port': '1',
     'destination_port': '2',
     'position': '7',
     'protocol': 'udp',
     'ip_version': 4,
     'enabled': True,
     'action': 'reject',
     'id': 'fake-fw-rule7'},
]

ICMP_ENTRY = (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', '1234')
TCP_ENTRY = (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
UDP_ENTRY = (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')

ROUTER_NAMESPACE = 'qrouter-fake-namespace'


class ConntrackLegacyTestCase(base.BaseTestCase):
    def setUp(self):
        super(ConntrackLegacyTestCase, self).setUp()
        self.utils_exec = mock.Mock()
        self.conntrack_driver = legacy_conntrack.ConntrackLegacy()
        self.conntrack_driver.initialize(execute=self.utils_exec)

        list_entries_mock = mock.patch(
            'neutron_fwaas.services.firewall.drivers.linux'
            '.legacy_conntrack.ConntrackLegacy.list_entries')
        self.list_entries = list_entries_mock.start()

    def test_excecute_command_failed(self):
        with testtools.ExpectedException(RuntimeError):
            self.conntrack_driver._execute_command(['fake', 'command'])
            raise RuntimeError("Failed execute conntrack command fake command")

    def test_flush_entries(self):
        self.conntrack_driver.flush_entries(ROUTER_NAMESPACE)
        self.utils_exec.assert_called_with(
                ['ip', 'netns', 'exec', ROUTER_NAMESPACE,
                 'conntrack', '-D'],
                check_exit_code=True,
                extra_ok_codes=[1],
                run_as_root=True)

    def test_delete_entries(self):
        self.conntrack_driver.list_entries.return_value = [
            ICMP_ENTRY, TCP_ENTRY, UDP_ENTRY]
        self.conntrack_driver.delete_entries(FW_RULES, ROUTER_NAMESPACE)
        calls = [
            mock.call(['ip', 'netns', 'exec', ROUTER_NAMESPACE,
                       'conntrack', '-D', '-f', 'ipv4', '-p', 'icmp',
                       '--icmp-type', 8, '--icmp-code', 0,
                       '-s', '1.1.1.1', '-d', '2.2.2.2', '--icmp-id', '1234'],
                      check_exit_code=True,
                      extra_ok_codes=[1],
                      run_as_root=True),
            mock.call(['ip', 'netns', 'exec', ROUTER_NAMESPACE,
                       'conntrack', '-D', '-f', 'ipv4', '-p', 'tcp',
                       '--sport', 1, '--dport', 2,
                       '-s', '1.1.1.1', '-d', '2.2.2.2'],
                      check_exit_code=True,
                      extra_ok_codes=[1],
                      run_as_root=True),
            mock.call(['ip', 'netns', 'exec', ROUTER_NAMESPACE,
                       'conntrack', '-D', '-f', 'ipv4', '-p', 'udp',
                       '--sport', 1, '--dport', 2,
                       '-s', '1.1.1.1', '-d', '2.2.2.2'],
                      check_exit_code=True,
                      extra_ok_codes=[1],
                      run_as_root=True),

        ]
        self.utils_exec.assert_has_calls(calls)
