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
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base
from oslo_log import log as logging

import neutron_fwaas.privileged.netlink_lib as nl_lib

LOG = logging.getLogger(__name__)


def check_nf_conntrack_ipv6_is_loaded():
    try:
        output = linux_utils.execute(['lsmod'])
    except RuntimeError:
        msg = "Failed execute command lsmod!"
        raise RuntimeError(msg)
    if 'nf_conntrack' in output:
        return True
    return False


def _create_entries(namespace, conntrack_cmds):
    for cmd in conntrack_cmds:
        exec_cmd = ['ip', 'netns', 'exec', namespace] + cmd
        try:
            linux_utils.execute(exec_cmd,
                                run_as_root=True,
                                check_exit_code=True,
                                extra_ok_codes=[1],
                                privsep_exec=True)
        except RuntimeError:
            raise Exception('Error while creating entry')


class NetlinkLibTestCase(functional_base.BaseSudoTestCase):
    """Functional test for netlink_lib: List, delete, flush conntrack entries.

    For each function, first we add a specific namespace, then create real
    conntrack entries. netlink_lib function will do list, delete and flush
    these entries. This class will test this netlink_lib function work
    as expected.
    """

    CONNTRACK_CMDS = (
        ['conntrack', '-I', '-p', 'tcp',
         '-s', '1.1.1.1', '-d', '2.2.2.2',
         '--sport', '1', '--dport', '2',
         '--state', 'ESTABLISHED', '--timeout', '1234'],
        ['conntrack', '-I', '-p', 'udp',
         '-s', '1.1.1.1', '-d', '2.2.2.2',
         '--sport', '1', '--dport', '2',
         '--timeout', '1234'],
        ['conntrack', '-I', '-p', 'icmp',
         '-s', '1.1.1.1', '-d', '2.2.2.2',
         '--icmp-type', '8', '--icmp-code', '0', '--icmp-id', '3333',
         '--timeout', '1234'],
        ['conntrack', '-I', '-p', 'icmp',
         '-s', '1.1.1.1', '-d', '2.2.2.2',
         '--icmp-type', '8', '--icmp-code', '0', '--icmp-id', '3333',
         '--timeout', '1234'],
    )

    def test_list_entries(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        _create_entries(namespace, self.CONNTRACK_CMDS)
        expected = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2'),
            (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')
        )
        entries_list = nl_lib.list_entries(namespace=namespace)
        self.assertEqual(expected, entries_list)

    def _delete_entry(self, delete_entries, remain_entries):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        _create_entries(namespace, self.CONNTRACK_CMDS)
        nl_lib.delete_entries(namespace=namespace, entries=delete_entries)
        entries_list = nl_lib.list_entries(namespace)
        self.assertEqual(remain_entries, entries_list)

    def test_delete_icmp_entry(self):
        icmp_entry = [(4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333)]
        remain_entries = (
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2'),
            (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2'),
        )
        self._delete_entry(icmp_entry, remain_entries)

    def test_delete_tcp_entry(self):
        tcp_entry = [(4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')]
        remain_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333),
            (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')
        )
        self._delete_entry(tcp_entry, remain_entries)

    def test_delete_udp_entry(self):
        udp_entry = [(4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')]
        remain_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2')
        )
        self._delete_entry(udp_entry, remain_entries)

    def test_delete_multiple_entries(self):
        delete_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333),
            (4, 'tcp', 1, 2, '1.1.1.1', '2.2.2.2'),
            (4, 'udp', 1, 2, '1.1.1.1', '2.2.2.2')
        )
        remain_entries = ()
        self._delete_entry(delete_entries, remain_entries)

    def test_flush_entries(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        _create_entries(namespace, self.CONNTRACK_CMDS)
        nl_lib.flush_entries(namespace)
        entries_list = nl_lib.list_entries(namespace)
        self.assertEqual((), entries_list)


class NetlinkLibTestCaseIPv6(functional_base.BaseSudoTestCase):

    CONNTRACK_CMDS = (
        ['conntrack', '-I', '-p', 'icmp',
         '-s', '1.1.1.1', '-d', '2.2.2.2',
         '--icmp-type', '8', '--icmp-code', '0', '--icmp-id', '3333',
         '--timeout', '1234'],
        ['conntrack', '-I', '-p', 'icmpv6',
         '-s', '10::10', '-d', '20::20',
         '--icmpv6-type', '128', '--icmpv6-code', '0', '--icmpv6-id', '3456',
         '--timeout', '1234'],
    )

    def setUp(self):
        super(NetlinkLibTestCaseIPv6, self).setUp()
        if not check_nf_conntrack_ipv6_is_loaded():
            self.skipTest(
                "nf_conntrack_ipv6 module wasn't loaded. Please load"
                "this module into your system if you want to use "
                "netlink conntrack with ipv6"
            )

    def test_list_entries(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        _create_entries(namespace, self.CONNTRACK_CMDS)
        expected = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333),
            (6, 'icmpv6', 128, 0, '10::10', '20::20', 3456),
        )
        entries_list = nl_lib.list_entries(namespace=namespace)
        self.assertEqual(expected, entries_list)

    def _delete_entry(self, delete_entries, remain_entries):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        _create_entries(namespace, self.CONNTRACK_CMDS)
        nl_lib.delete_entries(namespace=namespace, entries=delete_entries)
        entries_list = nl_lib.list_entries(namespace)
        self.assertEqual(remain_entries, entries_list)

    def test_delete_icmpv6_entry(self):
        icmp_entry = [(6, 'icmpv6', 128, 0, '10::10', '20::20', 3456)]
        remain_entries = (
            (4, 'icmp', 8, 0, '1.1.1.1', '2.2.2.2', 3333),
        )
        self._delete_entry(icmp_entry, remain_entries)

    def test_flush_entries(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        _create_entries(namespace, self.CONNTRACK_CMDS)
        nl_lib.flush_entries(namespace)
        entries_list = nl_lib.list_entries(namespace)
        self.assertEqual((), entries_list)
