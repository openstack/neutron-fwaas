# Copyright 2017 Mirantis, Inc.
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
from neutron_lib import constants
import testtools

from neutron.agent.common import ovs_lib
from neutron.common import constants as n_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
    as ovs_consts
from neutron.tests import base

from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import constants as fwaas_ovs_consts
from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import exceptions
from neutron_fwaas.services.firewall.drivers.linux.l2.openvswitch_firewall \
    import firewall as ovsfw

TESTING_VLAN_TAG = 1


def create_ofport(port_dict):
    ovs_port = mock.Mock(vif_mac='00:00:00:00:00:00', ofport=1,
                         port_name="port-name")
    return ovsfw.OFPort(port_dict, ovs_port, vlan_tag=TESTING_VLAN_TAG)


class TestCreateRegNumbers(base.BaseTestCase):
    def test_no_registers_defined(self):
        flow = {'foo': 'bar'}
        ovsfw.create_reg_numbers(flow)
        self.assertEqual({'foo': 'bar'}, flow)

    def test_both_registers_defined(self):
        flow = {'foo': 'bar', 'reg_port': 1, 'reg_net': 2}
        expected_flow = {'foo': 'bar',
                         'reg{:d}'.format(fwaas_ovs_consts.REG_PORT): 1,
                         'reg{:d}'.format(fwaas_ovs_consts.REG_NET): 2}
        ovsfw.create_reg_numbers(flow)
        self.assertEqual(expected_flow, flow)


class TestFirewallGroup(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallGroup, self).setUp()
        self.fwg = ovsfw.FirewallGroup('123')
        self.fwg.members = {'type': [1, 2, 3, 4]}

    def test_update_rules(self):
        ingress_rules = [{'foo-ingress': 'bar', 'rule': 'all'},
                         {'bar-ingress': 'foo'}]
        egress_rules = [{'foo-egress': '123456'}, {'bar-egress': 'bar'}]
        self.fwg.update_rules(ingress_rules, egress_rules)

        self.assertEqual(ingress_rules, self.fwg.ingress_rules)
        self.assertEqual(egress_rules, self.fwg.egress_rules)

    def test_update_rules_protocols(self):
        # XXX FIXME(ivasilevskaya) figure out what this test does and fix
        # appropriately
        # leaving failing as it may be important
        rules = [
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_ICMP,
             'ethertype': constants.IPv4},
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_ICMP,
             'ethertype': constants.IPv6},
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_IPV6_ICMP_LEGACY,
             'ethertype': constants.IPv6},
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_TCP},
            {'foo': 'bar', 'protocol': '94'},
            {'foo': 'bar', 'protocol': 'baz'},
            {'foo': 'no_proto'}]
        self.fwg.update_rules(rules, [])

        self.assertEqual({'foo': 'no_proto'}, self.fwg.ingress_rules.pop())
        protos = [rule['protocol'] for rule in self.fwg.ingress_rules]
        self.assertEqual([constants.PROTO_NUM_ICMP,
                          constants.PROTO_NUM_IPV6_ICMP,
                          constants.PROTO_NUM_IPV6_ICMP,
                          constants.PROTO_NUM_TCP,
                          94,
                          'baz'], protos)

    def test_get_ethertype_filtered_addresses(self):
        addresses = self.fwg.get_ethertype_filtered_addresses('type')
        expected_addresses = [1, 2, 3, 4]
        self.assertEqual(expected_addresses, addresses)


class TestOFPort(base.BaseTestCase):
    def setUp(self):
        super(TestOFPort, self).setUp()
        self.ipv4_addresses = ['10.0.0.1', '192.168.0.1']
        self.ipv6_addresses = ['fe80::f816:3eff:fe2e:1']
        port_dict = {'device': 1,
                     'fixed_ips': [
                         {'subnet_id': 's_%s' % ip, 'ip_address': ip}
                         for ip in self.ipv4_addresses + self.ipv6_addresses]}
        self.port = create_ofport(port_dict)

    def test_ipv4_address(self):
        ipv4_addresses = self.port.ipv4_addresses
        self.assertEqual(self.ipv4_addresses, ipv4_addresses)

    def test_ipv6_address(self):
        ipv6_addresses = self.port.ipv6_addresses
        self.assertEqual(self.ipv6_addresses, ipv6_addresses)

    def test__get_allowed_pairs(self):
        port = {
            'allowed_address_pairs': [
                {'mac_address': 'foo', 'ip_address': '10.0.0.1'},
                {'mac_address': 'bar', 'ip_address': '192.168.0.1'},
                {'mac_address': 'qux', 'ip_address': '169.254.0.0/16'},
                {'mac_address': 'baz', 'ip_address': '2003::f'},
            ]}
        allowed_pairs_v4 = ovsfw.OFPort._get_allowed_pairs(port, version=4)
        allowed_pairs_v6 = ovsfw.OFPort._get_allowed_pairs(port, version=6)
        expected_aap_v4 = {('foo', '10.0.0.1'), ('bar', '192.168.0.1'),
                           ('qux', '169.254.0.0/16')}
        expected_aap_v6 = {('baz', '2003::f')}
        self.assertEqual(expected_aap_v4, allowed_pairs_v4)
        self.assertEqual(expected_aap_v6, allowed_pairs_v6)

    def test__get_allowed_pairs_empty(self):
        port = {}
        allowed_pairs = ovsfw.OFPort._get_allowed_pairs(port, version=4)
        self.assertFalse(allowed_pairs)

    def test_update(self):
        old_port_dict = self.port.neutron_port_dict
        new_port_dict = old_port_dict.copy()
        added_ips = [1, 2, 3]
        new_port_dict.update({
            'fixed_ips': added_ips,
            'allowed_address_pairs': [
                {'mac_address': '00:00:00:00:00:01',
                 'ip_address': '192.168.0.1'},
                {'mac_address': '00:00:00:00:00:01',
                 'ip_address': '2003::f'}],
        })
        self.port.update(new_port_dict)
        self.assertEqual(new_port_dict, self.port.neutron_port_dict)
        self.assertIsNot(new_port_dict, self.port.neutron_port_dict)
        self.assertEqual(added_ips, self.port.fixed_ips)
        self.assertEqual({('00:00:00:00:00:01', '192.168.0.1')},
                         self.port.allowed_pairs_v4)
        self.assertIn(('00:00:00:00:00:01', '2003::f'),
                      self.port.allowed_pairs_v6)


class TestFWGPortMap(base.BaseTestCase):
    def setUp(self):
        super(TestFWGPortMap, self).setUp()
        self.map = ovsfw.FWGPortMap()

    def test_get_or_create_fwg_existing_fwg(self):
        self.map.fw_groups['id'] = mock.sentinel
        fwg = self.map.get_or_create_fwg('id')
        self.assertIs(mock.sentinel, fwg)

    def test_get_or_create_fwg_nonexisting_fwg(self):
        with mock.patch.object(ovsfw, 'FirewallGroup') as fwg_mock:
            fwg = self.map.get_or_create_fwg('id')
        self.assertEqual(fwg_mock.return_value, fwg)

    def _check_port(self, port_id, expected_id):
        port = self.map.ports[port_id]
        expected_fwg = self.map.fw_groups[expected_id]
        self.assertEqual(expected_fwg, port.fw_group)

    def _check_fwg(self, fwg_id, expected_port_ids):
        fwg = self.map.fw_groups[fwg_id]
        expected_ports = {self.map.ports[port_id]
                          for port_id in expected_port_ids}
        self.assertEqual(expected_ports, fwg.ports)

    def _create_ports_and_fwgs(self):
        fwg_1 = ovsfw.FirewallGroup(1)
        fwg_2 = ovsfw.FirewallGroup(2)
        fwg_3 = ovsfw.FirewallGroup(3)
        port_a = create_ofport({'device': 'a'})
        port_b = create_ofport({'device': 'b'})
        port_c = create_ofport({'device': 'c'})
        self.map.ports = {'a': port_a, 'b': port_b, 'c': port_c}
        self.map.fw_groups = {1: fwg_1, 2: fwg_2, 3: fwg_3}
        # XXX FIXME(ivasilevskaya) see note for OFPORT
        port_a.fw_group = fwg_1
        port_b.fw_group = fwg_2
        port_c.fw_group = fwg_2
        fwg_1.ports = {port_a}
        fwg_2.ports = {port_b, port_c}

    def test_create_port(self):
        """Create a port and assign it to firewall group

        It is implied that 1 port can be assigned to one firewall group only
        """
        port = create_ofport({'device': 'a'})
        port_dict = {'some-port-attributes-go-here': 42,
                     'firewall_group': 1}
        self.map.create_port(port, port_dict)
        self._check_port('a', 1)
        self._check_fwg(1, ['a'])

    def test_update_port_another_fwg_added(self):
        """Update a port with new firewall group id

        It is implied that 1 port can be assigned to one firewall group only
        """
        self._create_ports_and_fwgs()
        self._check_port('b', 2)
        port_dict = {'firewall_group': 3}
        self.map.update_port(self.map.ports['b'], port_dict)
        self._check_port('a', 1)
        self._check_port('b', 3)
        self._check_port('c', 2)
        self._check_fwg(1, ['a'])
        self._check_fwg(2, ['c'])
        self._check_fwg(3, ['b'])

    def test_remove_port(self):
        self._create_ports_and_fwgs()
        self.map.remove_port(self.map.ports['c'])
        self._check_port('b', 2)
        self._check_fwg(1, ['a'])
        self._check_fwg(2, ['b'])
        self.assertNotIn('c', self.map.ports)

    def test_update_rules(self):
        """Just make sure it doesn't crash"""
        self.map.update_rules(42, [], [])

    def test_update_members(self):
        """Just make sure it doesn't crash"""
        self.map.update_members(42, [])


class FakeOVSPort(object):
    def __init__(self, name, port, mac):
        self.port_name = name
        self.ofport = port
        self.vif_mac = mac


class TestOVSFirewallDriver(base.BaseTestCase):
    def setUp(self):
        super(TestOVSFirewallDriver, self).setUp()
        mock_bridge = mock.patch.object(
            ovs_lib, 'OVSBridge', autospec=True).start()
        self.firewall = ovsfw.OVSFirewallDriver(mock_bridge)
        self.mock_bridge = self.firewall.int_br
        self.mock_bridge.reset_mock()
        self.fake_ovs_port = FakeOVSPort('port', 1, '00:00:00:00:00:00')
        self.mock_bridge.br.get_vif_port_by_id.return_value = \
            self.fake_ovs_port

    def _prepare_firewall_group(self):
        ingress_rules = [
            {'position': '1',
             'protocol': 'tcp',
             'ip_version': 4,
             'destination_port': '123',
             'enabled': True,
             'action': 'allow',
             'id': 'fake-fw-rule1'}
        ]
        egress_rules = [
            {'position': '2',
             'protocol': 'udp',
             'ip_version': 4,
             'enabled': True,
             'action': 'allow',
             'id': 'fake-fw-rule2'},
            {'position': '3',
             'protocol': 'tcp',
             'ip_version': 6,
             'enabled': True,
             'action': 'allow',
             'id': 'fake-fw-rule3'}]
        self.firewall.update_firewall_group_rules(1, ingress_rules, [])
        self.firewall.update_firewall_group_rules(2, [], egress_rules)

    @property
    def port_ofport(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.ofport

    @property
    def port_mac(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.vif_mac

    def test_initialize_bridge(self):
        br = self.firewall.initialize_bridge(self.mock_bridge)
        self.assertEqual(br, self.mock_bridge.deferred.return_value)

    def test__add_flow_dl_type_formatted_to_string(self):
        dl_type = 0x0800
        self.firewall._add_flow(dl_type=dl_type)

    def test__add_flow_registers_are_replaced(self):
        self.firewall._add_flow(in_port=1, reg_port=1, reg_net=2)
        expected_calls = {'in_port': 1,
                          'reg{:d}'.format(fwaas_ovs_consts.REG_PORT): 1,
                          'reg{:d}'.format(fwaas_ovs_consts.REG_NET): 2}
        self.mock_bridge.br.add_flow.assert_called_once_with(
            **expected_calls)

    def test__drop_all_unmatched_flows(self):
        self.firewall._drop_all_unmatched_flows()
        expected_calls = [
            mock.call(actions='drop', priority=0,
                      table=fwaas_ovs_consts.FW_BASE_EGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=fwaas_ovs_consts.FW_BASE_INGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE)]
        actual_calls = self.firewall.int_br.br.add_flow.call_args_list
        self.assertEqual(expected_calls, actual_calls)

    def test_get_or_create_ofport_non_existing(self):
        port_dict = {
            'device': 'port-id',
            'firewall_group': 123,
            'lvlan': TESTING_VLAN_TAG,
        }
        port = self.firewall.get_or_create_ofport(port_dict)
        port_dict = {
            'device': 'port-id',
            'firewall_group': 456,
            'lvlan': TESTING_VLAN_TAG,
        }
        port = self.firewall.get_or_create_ofport(port_dict)
        sg1, sg2 = sorted(
            self.firewall.fwg_port_map.fw_groups.values(),
            key=lambda x: x.id)
        self.assertIn(port, self.firewall.fwg_port_map.ports.values())
        self.assertEqual(port.fw_group, sg2)
        self.assertEqual(set(), sg1.ports)
        self.assertIn(port, sg2.ports)

    def test_get_or_create_ofport_existing(self):
        port_dict = {
            'device': 'port-id',
            'firewall_group': 123}
        of_port = create_ofport(port_dict)
        self.firewall.fwg_port_map.ports[of_port.id] = of_port
        port = self.firewall.get_or_create_ofport(port_dict)
        [sg1] = sorted(self.firewall.fwg_port_map.fw_groups.values(),
                       key=lambda x: x.id)
        self.assertIs(of_port, port)
        self.assertIn(port, self.firewall.fwg_port_map.ports.values())
        self.assertEqual(port.fw_group, sg1)
        self.assertIn(port, sg1.ports)

    def test_get_or_create_ofport_changed(self):
        port_dict = {
            'device': 'port-id',
            'firewall_group': 123}
        of_port = create_ofport(port_dict)
        self.firewall.fwg_port_map.ports[of_port.id] = of_port
        fake_ovs_port = FakeOVSPort('port', 2, '00:00:00:00:00:00')
        self.mock_bridge.br.get_vif_port_by_id.return_value = \
            fake_ovs_port
        port = self.firewall.get_or_create_ofport(port_dict)
        self.assertEqual(port.ofport, 2)

    def test_get_or_create_ofport_missing(self):
        port_dict = {
            'device': 'port-id',
            'firewall_group': 123}
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        with testtools.ExpectedException(exceptions.OVSFWaaSPortNotFound):
            self.firewall.get_or_create_ofport(port_dict)

    def test_get_or_create_ofport_missing_nocreate(self):
        port_dict = {
            'device': 'port-id',
            'firewall_group': 123}
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        self.assertIsNone(self.firewall.get_ofport(port_dict))
        self.assertFalse(self.mock_bridge.br.get_vif_port_by_id.called)

    def test_is_port_managed_managed_port(self):
        port_dict = {'device': 'port-id'}
        self.firewall.fwg_port_map.ports[port_dict['device']] = object()
        is_managed = self.firewall.is_port_managed(port_dict)
        self.assertTrue(is_managed)

    def test_is_port_managed_not_managed_port(self):
        port_dict = {'device': 'port-id'}
        is_managed = self.firewall.is_port_managed(port_dict)
        self.assertFalse(is_managed)

    def test_prepare_port_filter(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'fixed_ips': [{'subnet_id': "some_subnet_id_here",
                                    'ip_address': "10.0.0.1"}],
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.prepare_port_filter(port_dict)
        exp_egress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        fwaas_ovs_consts.FW_BASE_EGRESS_TABLE),
            in_port=self.port_ofport,
            priority=105,
            table=ovs_consts.TRANSIENT_TABLE)
        exp_ingress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'strip_vlan,resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        fwaas_ovs_consts.FW_BASE_INGRESS_TABLE),
            dl_dst=self.port_mac,
            dl_vlan='0x%x' % TESTING_VLAN_TAG,
            priority=95,
            table=ovs_consts.TRANSIENT_TABLE)
        filter_rule = mock.call(
            actions='ct(commit,zone=NXM_NX_REG6[0..15]),'
            'output:{:d},resubmit(,{:d})'.format(
                self.port_ofport,
                ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE),
            dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_TCP,
            priority=70,
            reg5=self.port_ofport,
            ct_state=fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
            tcp_dst='0x007b')
        calls = self.mock_bridge.br.add_flow.call_args_list
        for call in exp_ingress_classifier, exp_egress_classifier, filter_rule:
            self.assertIn(call, calls)

    def test_prepare_port_filter_in_coexistence_mode(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'fixed_ips': [{'subnet_id': "some_subnet_id_here",
                                    'ip_address': "10.0.0.1"}],
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.sg_with_ovs = True
        self.firewall.prepare_port_filter(port_dict)
        exp_egress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        fwaas_ovs_consts.FW_BASE_EGRESS_TABLE),
            in_port=self.port_ofport,
            priority=105,
            table=ovs_consts.TRANSIENT_TABLE)
        exp_ingress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'strip_vlan,resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        fwaas_ovs_consts.FW_BASE_INGRESS_TABLE),
            dl_dst=self.port_mac,
            dl_vlan='0x%x' % TESTING_VLAN_TAG,
            priority=95,
            table=ovs_consts.TRANSIENT_TABLE)
        filter_rule = mock.call(
            actions='resubmit(,{:d})'.format(ovs_consts.RULES_INGRESS_TABLE),
            dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_TCP,
            priority=70,
            reg5=self.port_ofport,
            ct_state=fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            table=fwaas_ovs_consts.FW_RULES_INGRESS_TABLE,
            tcp_dst='0x007b')
        calls = self.mock_bridge.br.add_flow.call_args_list
        for call in exp_ingress_classifier, exp_egress_classifier, filter_rule:
            self.assertIn(call, calls)

    def test_prepare_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'port_security_enabled': False}
        self._prepare_firewall_group()
        with mock.patch.object(
                self.firewall, 'initialize_port_flows') as m_init_flows:
            self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(m_init_flows.called)

    def test_prepare_port_filter_initialized_port(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)
        self.firewall.prepare_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)

    def test_update_port_filter(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.prepare_port_filter(port_dict)
        port_dict['firewall_group'] = 2
        self.mock_bridge.reset_mock()

        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        filter_rules = [
            mock.call(
                actions='resubmit(,{:d})'.format(
                    fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE),
                dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
                nw_proto=constants.PROTO_NUM_UDP,
                priority=71,
                ct_state=fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED,
                reg5=self.port_ofport,
                table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE),
            # XXX FIXME NOTE(ivasilevskaya) this test originally tested that
            # flows for SG with remote_group=this group were generated with
            # proper conjunction action. If the original idea that conj_manager
            # isn't needed for firewall groups proves to be wrong this needs to
            # be revizited and properly fixed/covered with tests
            mock.call(
                actions='resubmit(,{:d})'.format(
                    fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE),
                ct_state=fwaas_ovs_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
                dl_type=mock.ANY,
                nw_proto=6,
                priority=70, reg5=self.port_ofport,
                table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE)]
        self.mock_bridge.br.add_flow.assert_has_calls(filter_rules,
                                                      any_order=True)

    def test_update_port_filter_in_coexistence_mode(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.sg_with_ovs = True
        self.firewall.prepare_port_filter(port_dict)
        port_dict['firewall_group'] = 2
        self.mock_bridge.reset_mock()

        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        filter_rules = [
            mock.call(
                actions='resubmit(,{:d})'.format(
                    ovs_consts.RULES_EGRESS_TABLE),
                dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
                nw_proto=constants.PROTO_NUM_UDP,
                priority=71,
                ct_state=fwaas_ovs_consts.OF_STATE_NEW_NOT_ESTABLISHED,
                reg5=self.port_ofport,
                table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE),
            # XXX FIXME NOTE(ivasilevskaya) this test originally tested that
            # flows for SG with remote_group=this group were generated with
            # proper conjunction action. If the original idea that conj_manager
            # isn't needed for firewall groups proves to be wrong this needs to
            # be revizited and properly fixed/covered with tests
            mock.call(
                actions='resubmit(,{:d})'.format(
                    ovs_consts.RULES_EGRESS_TABLE),
                ct_state=fwaas_ovs_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
                dl_type=mock.ANY,
                nw_proto=6,
                priority=70, reg5=self.port_ofport,
                table=fwaas_ovs_consts.FW_RULES_EGRESS_TABLE)]
        self.mock_bridge.br.add_flow.assert_has_calls(filter_rules,
                                                      any_order=True)

    def test_update_port_filter_create_new_port_if_not_present(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1}
        self._prepare_firewall_group()
        with mock.patch.object(
                self.firewall, 'prepare_port_filter') as prepare_mock:
            self.firewall.update_port_filter(port_dict)
        self.assertTrue(prepare_mock.called)

    def test_update_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.prepare_port_filter(port_dict)
        port_dict['port_security_enabled'] = False
        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)

    def test_remove_port_filter(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': TESTING_VLAN_TAG}
        self._prepare_firewall_group()
        self.firewall.prepare_port_filter(port_dict)
        self.firewall.remove_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        self.assertIn(1, self.firewall.fwg_to_delete)

    def test_remove_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1}
        self.firewall.remove_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)

    def test_update_firewall_group_rules(self):
        """Just make sure it doesn't crash"""
        new_rules_ingress = [
            {'ip_version': 4,
             'action': 'allow',
             'protocol': constants.PROTO_NAME_ICMP},
            {'ip_version': 4,
             'direction': 'deny'}]
        self.firewall.update_firewall_group_rules(1, new_rules_ingress, [])

    def test__cleanup_stale_sg(self):
        self._prepare_firewall_group()
        self.firewall.fwg_to_delete = {1}
        with mock.patch.object(self.firewall.fwg_port_map,
                              'delete_fwg') as delete_fwg_mock:
            self.firewall._cleanup_stale_fwg()
            delete_fwg_mock.assert_called_once_with(1)

    def test_get_ovs_port(self):
        ovs_port = self.firewall.get_ovs_port('port_id')
        self.assertEqual(self.fake_ovs_port, ovs_port)

    def test_get_ovs_port_non_existent(self):
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        with testtools.ExpectedException(exceptions.OVSFWaaSPortNotFound):
            self.firewall.get_ovs_port('port_id')

    def test__initialize_egress_no_port_security_sends_to_egress(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': TESTING_VLAN_TAG}
        self.firewall._initialize_egress_no_port_security(port_dict)
        expected_call = mock.call(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=100,
            in_port=self.fake_ovs_port.ofport,
            actions='set_field:%d->reg%d,'
                    'set_field:%d->reg%d,'
                    'resubmit(,%d)' % (
                        self.fake_ovs_port.ofport,
                        fwaas_ovs_consts.REG_PORT,
                        TESTING_VLAN_TAG,
                        fwaas_ovs_consts.REG_NET,
                        fwaas_ovs_consts.FW_ACCEPT_OR_INGRESS_TABLE)
        )
        calls = self.mock_bridge.br.add_flow.call_args_list
        self.assertIn(expected_call, calls)

    def test__initialize_egress_no_port_security_no_tag(self):
        port_dict = {'device': 'port-id',
                     'firewall_group': 1,
                     'lvlan': None}
        self.firewall._initialize_egress_no_port_security(port_dict)
        self.assertFalse(self.mock_bridge.br.add_flow.called)

    def test__remove_egress_no_port_security_deletes_flow(self):
        self.mock_bridge.br.db_get_val.return_value = {'tag': TESTING_VLAN_TAG}
        self.firewall.fwg_port_map.unfiltered['port_id'] = 1
        self.firewall._remove_egress_no_port_security('port_id')
        expected_call = mock.call(
            table=ovs_consts.TRANSIENT_TABLE,
            in_port=self.fake_ovs_port.ofport,
        )
        calls = self.mock_bridge.br.delete_flows.call_args_list
        self.assertIn(expected_call, calls)

    def test__remove_egress_no_port_security_no_tag(self):
        self.mock_bridge.br.db_get_val.return_value = {}
        self.firewall._remove_egress_no_port_security('port_id')
        self.assertFalse(self.mock_bridge.br.delete_flows.called)
