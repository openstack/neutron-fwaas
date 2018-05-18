# Copyright 2017 Cisco Systems
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
#    under the License.

import copy

import mock
from neutron_lib import constants as nl_consts
from neutron_lib import context
from neutron_lib.exceptions import firewall_v2 as f_exc
from oslo_config import cfg

from neutron_fwaas.common import fwaas_constants as consts
from neutron_fwaas.services.firewall.service_drivers.agents.l2 import fwaas_v2
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.services.firewall.service_drivers.agents.l2\
    import fake_data


class TestFWaasV2AgentExtensionBase(base.BaseTestCase):

    def setUp(self):
        super(TestFWaasV2AgentExtensionBase, self).setUp()

        self.fake = fake_data.FakeFWaaSL2Agent()
        self.port = self.fake.create('port')
        self.port_minimal = self.fake.create('port', minimal=True)
        self.fwg = self.fake.create('fwg')
        self.fwg_with_rule = self.fake.create('fwg_with_rule')
        self.port_id = self.port['port_id']
        self.fwg_id = self.fwg['id']
        self.host = fake_data.HOST
        self.ctx = context.get_admin_context()

        self.l2 = fwaas_v2.FWaaSV2AgentExtension()
        self.l2.consume_api(mock.Mock())
        self.driver = mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider').start()
        self.l2.initialize(None, 'ovs')
        self.l2.vlan_manager = mock.Mock()
        self.conf = cfg.ConfigOpts()
        self.l2.fwg_map = mock.Mock()
        self.l2.conf.host = self.host
        self.rpc = self.l2.plugin_rpc


class TestFWaasV2AgentExtension(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestFWaasV2AgentExtension, self).setUp()
        cfg.CONF.set_override('firewall_l2_driver', 'ovs', group='fwaas')

    def test_initialize(self):
        with mock.patch('neutron.common.rpc.Connection') as conn:
            self.l2.initialize(None, 'ovs')
        self.driver.assert_called_with('neutron.agent.l2.firewall_drivers',
                                       'ovs')
        conn.assert_called_with()
        self.l2.conn.create_consumer.assert_called_with(
            consts.FW_AGENT, [self.l2], fanout=False)
        self.l2.conn.consume_in_threads.assert_called_with()


class TestHandlePort(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestHandlePort, self).setUp()
        self.rpc.get_firewall_group_for_port = mock.Mock(
            return_value=self.fwg)
        self.l2._compute_status = mock.Mock(return_value=nl_consts.ACTIVE)
        self.l2._apply_fwg_rules = mock.Mock(return_value=True)
        self.l2._send_fwg_status = mock.Mock()
        self.ctx = context.get_admin_context()
        self.l2._add_rule_for_trusted_port = mock.Mock()

    def test_normal(self):
        self.l2.fwg_map.get_port_fwg.return_value = None
        self.l2.handle_port(self.ctx, self.port)
        self.rpc.get_firewall_group_for_port.assert_called_once_with(
            self.ctx, self.port['port_id'])
        self.l2._apply_fwg_rules.assert_called_once_with(self.fwg, [self.port])
        self.l2._compute_status.assert_called_once_with(
            self.fwg, True, event=consts.HANDLE_PORT)
        self.l2.fwg_map.set_port_fwg.assert_called_once_with(self.port,
                                                             self.fwg)
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, fwg_id=self.fwg['id'],
            status=nl_consts.ACTIVE, host=self.l2.conf.host)

    def test_non_layer2_port(self):
        self.port['device_owner'] = 'network:router_gateway'
        self.l2.handle_port(self.ctx, self.port)

        self.rpc.get_firewall_group_for_port.assert_not_called()
        self.l2._apply_fwg_rules.assert_not_called()
        self.l2._compute_status.assert_not_called()
        self.l2.fwg_map.set_port_fwg.assert_not_called()
        self.l2._send_fwg_status.assert_not_called()

    def test_no_fwg_is_asossicate_to_port(self):
        self.l2.fwg_map.get_port_fwg.return_value = None
        self.rpc.get_firewall_group_for_port.return_value = None
        self.l2.handle_port(self.ctx, self.port)

        self.rpc.get_firewall_group_for_port.assert_called_once_with(
            self.ctx, self.port['port_id'])
        self.l2._apply_fwg_rules.assert_not_called()
        self.l2._compute_status.assert_not_called()
        self.l2.fwg_map.set_port_fwg.assert_not_called()
        self.l2._send_fwg_status.assert_not_called()

    def test_port_already_apply_fwg(self):
        self.l2.fwg_map.get_port_fwg.return_value = self.fwg
        self.l2.handle_port(self.ctx, self.port)

        self.rpc.get_firewall_group_for_port.assert_not_called()
        self.l2._apply_fwg_rules.assert_not_called()
        self.l2._compute_status.assert_not_called()
        self.l2.fwg_map.set_port_fwg.assert_not_called()
        self.l2._send_fwg_status.assert_not_called()

    def test_trusted_port(self):
        self.l2.fwg_map.get_port.return_value = None
        self.port['device_owner'] = 'network:foo'
        self.l2.handle_port(self.ctx, self.port)

        self.l2._add_rule_for_trusted_port.assert_called_once_with(self.port)
        self.l2.fwg_map.set_port.assert_called_once_with(self.port)
        self.rpc.get_firewall_group_for_port.assert_not_called()

    def test_trusted_port_registered_map(self):
        self.port['device_owner'] = 'network:dhcp'
        self.l2.fwg_map.get_port.return_value = self.port
        self.l2.handle_port(self.ctx, self.port)

        self.l2._add_rule_for_trusted_port.assert_not_called()
        self.l2.fwg_map.set_port.assert_not_called()
        self.rpc.get_firewall_group_for_port.assert_not_called()


class TestDeletePort(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestDeletePort, self).setUp()
        self.l2._compute_status = mock.Mock(return_value=nl_consts.ACTIVE)
        self.l2._apply_fwg_rules = mock.Mock(return_value=True)
        self.l2._send_fwg_status = mock.Mock()
        self.l2._delete_rule_for_trusted_port = mock.Mock()

        self.l2.fwg_map.get_port_fwg = mock.Mock(return_value=self.fwg)
        self.l2.fwg_map.set_fwg = mock.Mock()
        self.l2.fwg_map.get_port = mock.Mock(return_value=self.port)
        self.l2.fwg_map.remove_port = mock.Mock()

    def test_include_vif_port_attribute(self):
        self.port_minimal.update({'vif_port': None})
        self.l2.fwg_map.get_port_fwg.return_value = None
        self.l2.delete_port(self.ctx, self.port_minimal)

        self.l2.fwg_map.get_port_fwg.assert_not_called()
        self.l2._apply_fwg_rules.assert_not_called()

    def test_port_belongs_to_fwg(self):
        expected_ports = self.fwg['ports']
        self.fwg['ports'].append(self.port['port_id'])
        self.l2.delete_port(self.ctx, self.port_minimal)

        self.l2.fwg_map.get_port_fwg.assert_called_once_with(self.port)
        self.l2._apply_fwg_rules.assert_called_once_with(
            self.fwg, [self.port], event=consts.DELETE_FWG)
        # 'port_id' has been removed from 'ports'
        self.assertEqual(expected_ports, self.fwg['ports'])
        self.l2.fwg_map.set_fwg.assert_called_once_with(self.fwg)

    def test_port_belongs_to_no_fwg(self):
        expected_ports = self.fwg['ports']
        self.l2.delete_port(self.ctx, self.port_minimal)

        self.l2.fwg_map.get_port_fwg.assert_called_once_with(self.port)
        self.l2._apply_fwg_rules.assert_called_once_with(
            self.fwg, [self.port], event=consts.DELETE_FWG)
        # 'ports' not changed during delete_port()
        self.assertEqual(expected_ports, self.fwg['ports'])
        self.l2.fwg_map.set_fwg.assert_called_once_with(self.fwg)

    def test_non_layer2_port(self):
        self.port['device_owner'] = 'network:router_gateway'
        self.l2.delete_port(self.ctx, self.port_minimal)

        self.l2.fwg_map.get_port_fwg.assert_not_called()

    def test_cannot_get_fwg_from_port(self):
        self.l2.fwg_map.get_port_fwg.return_value = None
        self.l2.delete_port(self.ctx, self.port_minimal)

        self.l2.fwg_map.get_port_fwg.assert_called_once_with(self.port)
        self.l2._apply_fwg_rules.assert_not_called()

    def test_trusted_port_with_map(self):
        self.port['device_owner'] = 'network:dhcp'
        self.l2.fwg_map.get_port.return_value = self.port
        self.l2.delete_port(self.ctx, self.port_minimal)

        self.l2._delete_rule_for_trusted_port.assert_called_once_with(
            self.port)
        self.l2.fwg_map.remove_port.assert_called_once_with(self.port)


class TestCreateFirewallGroup(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestCreateFirewallGroup, self).setUp()
        self.l2._apply_fwg_rules = mock.Mock(return_value=True)
        self.l2._compute_status = mock.Mock(return_value='ACTIVE')
        self.l2._send_fwg_status = mock.Mock()

    def test_create_event_is_create(self):
        fwg = self.fwg_with_rule
        fwg['ports'] = [fake_data.PORT1]
        ports = [fwg['port_details'][fake_data.PORT1]]
        self.l2._create_firewall_group(
            self.ctx, fwg, self.host, event=consts.CREATE_FWG)
        self.l2._apply_fwg_rules.assert_called_once_with(
            fwg, ports, consts.CREATE_FWG)
        self.l2._compute_status.assert_called_once_with(
            fwg, True, consts.CREATE_FWG)

    def test_create_event_is_not_create(self):
        fwg = self.fwg_with_rule
        fwg['ports'] = [fake_data.PORT1]
        ports = [fwg['port_details'][fake_data.PORT1]]
        self.l2._create_firewall_group(
            self.ctx, fwg, self.host, event=consts.UPDATE_FWG)
        self.l2._apply_fwg_rules.assert_called_once_with(
            fwg, ports, consts.UPDATE_FWG)

    def test_create_with_port(self):
        fwg = self.fwg_with_rule
        ports = [fwg['port_details'][fake_data.PORT1]]
        self.l2.create_firewall_group(self.ctx, fwg, self.host)
        self.l2._apply_fwg_rules.assert_called_once_with(
            fwg, ports, consts.CREATE_FWG)

        for idx, args in enumerate(self.l2._compute_status.call_args_list):
            self.assertEqual(fwg, args[0][0])
            self.assertEqual(True, args[0][1])
            self.assertEqual(consts.CREATE_FWG, args[0][2])

        for idx, args in enumerate(self.l2._send_fwg_status.call_args_list):
            self.assertEqual(self.ctx, args[0][0])
            self.assertEqual(fwg['id'], args[0][1])
            self.assertEqual('ACTIVE', args[0][2])
            self.assertEqual(self.host, args[0][3])

    def test_create_with_no_ports(self):
        self.fwg_with_rule['add-port-ids'] = []
        self.assertIsNone(self.l2.create_firewall_group(
            self.ctx, self.fwg_with_rule, self.host))
        self.l2._apply_fwg_rules.assert_not_called()
        self.l2.fwg_map.set_port_fwg.assert_not_called()
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, self.fwg_with_rule['id'], 'INACTIVE', self.host)

    def test_create_with_invalid_host(self):
        self.fwg_with_rule['port_details'][fake_data.PORT1]['host'] = 'invalid'
        self.l2.create_firewall_group(self.ctx, self.fwg_with_rule, self.host)
        self.l2._apply_fwg_rules.assert_not_called()
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, self.fwg_with_rule['id'], 'INACTIVE', self.host)

    def test_illegal_create_with_no_l2_ports(self):
        fwg = {
            'name': 'non-default',
            'id': self.fwg_id,
            'ports': [],
            'add-port-ids': [self.port_id],
            'admin_state_up': True,
            'port_details': {
                self.port_id: {
                    'device_owner': 'network:router_interface'
                }
            }
        }
        self.l2.create_firewall_group(self.ctx, fwg, self.host)
        self.l2._apply_fwg_rules.assert_not_called()
        self.l2.fwg_map.set_port_fwg.assert_not_called()
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, fwg['id'], 'INACTIVE', self.host)


class TestDeleteFirewallGroup(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestDeleteFirewallGroup, self).setUp()
        self.l2._apply_fwg_rules = mock.Mock(return_value=True)
        self.l2._compute_status = mock.Mock(return_value='ACTIVE')
        self.l2._send_fwg_status = mock.Mock()
        self.rpc.firewall_group_deleted = mock.Mock()

    def test_delete_with_port(self):
        fwg = self.fwg_with_rule
        ports = [fwg['port_details'][fake_data.PORT2]]

        self.assertIsNone(self.l2.delete_firewall_group(
            self.ctx, self.fwg_with_rule, self.host))
        self.l2._apply_fwg_rules.assert_called_once_with(
            fwg, ports, event=consts.DELETE_FWG)
        self.l2.fwg_map.remove_fwg.assert_called_once_with(fwg)
        for idx, args in enumerate(self.l2._compute_status.call_args_list):
            self.assertEqual(fwg, args[0][0])
            self.assertEqual(True, args[0][2])
            self.assertEqual({'event': consts.CREATE_FWG}, args[1])

        for idx, args in enumerate(self.l2._send_fwg_status.call_args_list):
            self.assertEqual(self.ctx, args[0][0])
            self.assertEqual(fwg['id'], args[0][1])
            self.assertEqual('ACTIVE', args[0][2])
            self.assertEqual(self.host, args[0][3])

    def test_delete_with_no_ports(self):
        self.fwg_with_rule['del-port-ids'] = []
        self.l2.delete_firewall_group(self.ctx, self.fwg_with_rule, self.host)
        self.l2._apply_fwg_rules.assert_not_called()

    def test_delete_with_no_l2_ports(self):
        self.fwg_with_rule['port_details'][fake_data.PORT2][
            'device_owner'] = 'network:router_interface'
        self.l2.delete_firewall_group(self.ctx, self.fwg_with_rule, self.host)
        self.l2._apply_fwg_rules.assert_not_called()

    def test_delete_with_exception(self):
        self.l2._delete_firewall_group = mock.Mock(side_effect=Exception)
        self.assertIsNone(self.l2.delete_firewall_group(
            self.ctx, self.fwg_with_rule, self.host))

    def test_delete_event_is_update(self):
        self.l2._delete_firewall_group(
            self.ctx, self.fwg_with_rule, self.host, event=consts.UPDATE_FWG)
        self.l2.fwg_map.remove_fwg.assert_not_called()
        self.rpc.firewall_group_deleted.assert_not_called()
        self.l2._compute_status.assert_called_once_with(
            self.fwg_with_rule, True, consts.UPDATE_FWG)
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, self.fwg_with_rule['id'], 'ACTIVE', self.host)


class TestUpdateFirewallGroup(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestUpdateFirewallGroup, self).setUp()
        self.l2._delete_firewall_group = mock.Mock()
        self.l2._create_firewall_group = mock.Mock()
        self.l2._send_fwg_status = mock.Mock()

    def test_update(self):
        self.assertIsNone(self.l2.update_firewall_group(
            self.ctx, mock.ANY, self.host))

        self.l2._delete_firewall_group.assert_called_once_with(
                self.ctx, mock.ANY, self.host, event=consts.UPDATE_FWG)
        self.l2._create_firewall_group.assert_called_once_with(
                self.ctx, mock.ANY, self.host, event=consts.UPDATE_FWG)

    def test_update_raised_in_delete_firewall_group(self):
        self.l2._delete_firewall_group.side_effect = Exception
        fwg = self.fwg_with_rule
        self.assertIsNone(self.l2.update_firewall_group(
            self.ctx, fwg, self.host))
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, fwg['id'], status='ERROR', host=self.host)

    def test_update_raised_in_create_firewall_group(self):
        self.l2._create_firewall_group.side_effect = Exception
        fwg = self.fwg_with_rule
        self.assertIsNone(self.l2.update_firewall_group(
            self.ctx, fwg, self.host))
        self.l2._send_fwg_status.assert_called_once_with(
            self.ctx, fwg['id'], status='ERROR', host=self.host)


class TestIsPortLayer2(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestIsPortLayer2, self).setUp()

    def test_vm_port(self):
        self.assertTrue(self.l2._is_port_layer2(self.port))

    def test_not_vm_port(self):
        for device_owner in [nl_consts.DEVICE_OWNER_ROUTER_INTF,
            nl_consts.DEVICE_OWNER_ROUTER_GW,
            nl_consts.DEVICE_OWNER_DHCP,
            nl_consts.DEVICE_OWNER_DVR_INTERFACE,
            nl_consts.DEVICE_OWNER_AGENT_GW,
            nl_consts.DEVICE_OWNER_ROUTER_SNAT,
            nl_consts.DEVICE_OWNER_LOADBALANCER,
            nl_consts.DEVICE_OWNER_LOADBALANCERV2,
            'unknown device_owner',
            '']:
            self.port['device_owner'] = device_owner
            self.assertFalse(self.l2._is_port_layer2(self.port))

    def test_illegal_no_device_owner(self):
        del self.port['device_owner']
        self.assertFalse(self.l2._is_port_layer2(self.port))


class TestComputeStatus(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestComputeStatus, self).setUp()
        self.ports = list(self.fwg_with_rule['port_details'].values())

    def test_normal(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertEqual('ACTIVE', self.l2._compute_status(fwg, result))

    def test_event_is_delete(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertIsNone(self.l2._compute_status(
            fwg, result, consts.DELETE_FWG))

    def test_event_is_update(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertEqual('ACTIVE', self.l2._compute_status(
            fwg, result, consts.UPDATE_FWG))

    def test_event_is_update_and_has_last_port(self):
        result = True
        fwg = self.fake.create('fwg_with_rule', attrs={'last-port': False})

        self.assertEqual('ACTIVE', self.l2._compute_status(
            fwg, result, consts.UPDATE_FWG))

        fwg = self.fake.create('fwg_with_rule', attrs={'last-port': True})
        self.assertEqual('INACTIVE', self.l2._compute_status(
            fwg, result, consts.UPDATE_FWG))

    def test_event_is_update_and_has_no_last_port_but_has_ports(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertEqual('ACTIVE', self.l2._compute_status(
            fwg, result, consts.UPDATE_FWG))

    def test_event_is_update_and_has_no_last_port_and_ports(self):
        result = True
        fwg = self.fwg_with_rule
        fwg['ports'] = []
        self.assertEqual('INACTIVE', self.l2._compute_status(
            fwg, result, consts.UPDATE_FWG))

    def test_event_is_create(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertEqual('ACTIVE', self.l2._compute_status(
            fwg, result, consts.CREATE_FWG))

    def test_event_is_create_and_no_fwg_ports(self):
        result = True
        fwg = self.fwg_with_rule
        fwg['ports'] = []
        self.assertEqual('INACTIVE', self.l2._compute_status(
            fwg, result, consts.CREATE_FWG))

    def test_event_is_handle_port(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertEqual('ACTIVE', self.l2._compute_status(
            fwg, result, consts.HANDLE_PORT))

    def test_event_is_delete_port(self):
        result = True
        fwg = self.fwg_with_rule
        self.assertEqual('ACTIVE', self.l2._compute_status(
            fwg, result, consts.DELETE_PORT))

    def test_event_is_delete_port_and_no_fwg_ports(self):
        result = True
        fwg = self.fwg_with_rule
        fwg['ports'] = []
        self.assertEqual('INACTIVE', self.l2._compute_status(
            fwg, result, consts.DELETE_PORT))

    def test_driver_result_is_false(self):
        result = False
        fwg = self.fwg_with_rule
        self.assertEqual('ERROR', self.l2._compute_status(
            fwg, result))

    def test_admin_state_up_is_false(self):
        result = True
        self.fwg_with_rule['admin_state_up'] = False

        self.assertEqual('DOWN', self.l2._compute_status(
            self.fwg_with_rule, self.ports, result))

    def test_active_inactive_patterns(self):
        result = True
        fwg = self.fwg_with_rule
        # Case1: ingress/egress_firewall_policy_id
        # Case2: ports --> already tested at above cases
        expect_and_attrs = [
            ('INACTIVE', ('ingress_firewall_policy_id',
                          'egress_firewall_policy_id')),
            ('ACTIVE', ('ingress_firewall_policy_id',)),
            ('ACTIVE', ('egress_firewall_policy_id',)),
        ]
        for attr in expect_and_attrs:
            fwg = self.fake.create('fwg_with_rule')
            expect = attr[0]
            for p in attr[1]:
                fwg[p] = None
            self.assertEqual(expect, self.l2._compute_status(fwg, result))


class TestApplyFwgRules(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestApplyFwgRules, self).setUp()

        class DummyVlan(object):

            def __init__(self, vlan=None):
                self.vlan = vlan

        self.l2.vlan_manager.get.return_value = DummyVlan(vlan='999')

    def test_event_is_create(self):
        fwg_ports = [self.fwg_with_rule['port_details'][fake_data.PORT1]]
        driver_ports = copy.deepcopy(fwg_ports)
        driver_ports[0].update({'lvlan': 999})

        self.assertTrue(self.l2._apply_fwg_rules(
            self.fwg_with_rule, fwg_ports, event=consts.CREATE_FWG))

        self.l2.driver.create_firewall_group.assert_called_once_with(
            driver_ports, self.fwg_with_rule)
        self.l2.driver.delete_firewall_group.assert_not_called()
        self.l2.driver.update_firewall_group.assert_not_called()

    def test_event_is_update(self):
        fwg_ports = [self.fwg_with_rule['port_details'][fake_data.PORT1]]
        driver_ports = copy.deepcopy(fwg_ports)
        driver_ports[0].update({'lvlan': 999})

        self.assertTrue(self.l2._apply_fwg_rules(
            self.fwg_with_rule, fwg_ports, event=consts.UPDATE_FWG))

        self.l2.driver.update_firewall_group.assert_called_once_with(
            driver_ports, self.fwg_with_rule)

    def test_event_is_delete(self):
        fwg_ports = [self.fwg_with_rule['port_details'][fake_data.PORT1]]
        driver_ports = copy.deepcopy(fwg_ports)
        driver_ports[0].update({'lvlan': 999})

        self.assertTrue(self.l2._apply_fwg_rules(
            self.fwg_with_rule, fwg_ports, event=consts.DELETE_FWG))

        self.l2.driver.delete_firewall_group.assert_called_once_with(
            fwg_ports, self.fwg_with_rule)

    def test_raised_in_driver(self):
        self.l2.driver.delete_firewall_group.side_effect = \
            f_exc.FirewallInternalDriverError(driver='ovs firewall')
        fwg_ports = [self.fwg_with_rule['port_details'][fake_data.PORT1]]
        driver_ports = copy.deepcopy(fwg_ports)
        driver_ports[0].update({'lvlan': 999})

        self.assertFalse(self.l2._apply_fwg_rules(
            self.fwg_with_rule, fwg_ports, event=consts.DELETE_FWG))

        self.l2.driver.delete_firewall_group.assert_called_once_with(
            fwg_ports, self.fwg_with_rule)


class TestSendFwgStatus(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestSendFwgStatus, self).setUp()
        self.rpc.set_firewall_group_status = mock.Mock()

    def test_success(self):
        self.assertIsNone(self.l2._send_fwg_status(
            self.ctx, self.fwg_id, 'ACTIVE', self.host))

    def test_failure(self):
        self.rpc.set_firewall_group_status.side_effect = Exception
        self.assertIsNone(self.l2._send_fwg_status(
            self.ctx, self.fwg_id, 'ACTIVE', self.host))


class TestAddLocalVlanToPorts(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestAddLocalVlanToPorts, self).setUp()

        class DummyVlan(object):

            def __init__(self, vlan=None):
                self.vlan = vlan

        self.l2.vlan_manager.get.return_value = DummyVlan(vlan='999')
        self.port_with_detail = {
            'port_id': fake_data.PORT1,
            'id': fake_data.PORT1,
            'network_id': fake_data.NETWORK_ID,
            'port_details': {
                fake_data.PORT1: {
                    'device': 'c12e5c1e-d68e-45bd-a2d3-1f2f32604e41',
                    'device_owner': 'compute:nova',
                    'host': self.host,
                    'network_id': fake_data.NETWORK_ID,
                    'fixed_ips': [
                        {'subnet_id': fake_data.SUBNET_ID,
                         'ip_address': '172.24.4.5'}],
                    'allowed_address_pairs': [],
                    'port_security_enabled': True,
                    'id': fake_data.PORT1
                }
            }
        }

    def test_port_has_detail_and_port_id(self):
        del self.port_with_detail['id']
        expect = [copy.deepcopy(self.port_with_detail)]
        expect[0].update({'lvlan': 999})
        actual = self.l2._add_local_vlan_to_ports([self.port_with_detail])

        self.l2.vlan_manager.get.assert_called_once_with(
            self.port_with_detail['network_id'])
        self.assertEqual(expect, actual)

    def test_port_has_detail_and_id(self):
        del self.port_with_detail['port_id']
        expect = [copy.deepcopy(self.port_with_detail)]
        expect[0].update({'lvlan': 999})
        actual = self.l2._add_local_vlan_to_ports([self.port_with_detail])

        self.l2.vlan_manager.get.assert_called_once_with(
            self.port_with_detail['network_id'])
        self.assertEqual(expect, actual)

    def test_port_has_no_detail(self):
        del self.port_with_detail['port_details']
        expect = [copy.deepcopy(self.port_with_detail)]
        expect[0].update({'lvlan': 999})
        actual = self.l2._add_local_vlan_to_ports([self.port_with_detail])

        self.l2.vlan_manager.get.assert_called_once_with(
            self.port_with_detail['network_id'])
        self.assertEqual(expect, actual)


class TestFWaaSL2PluginApi(TestFWaasV2AgentExtensionBase):

    def setUp(self):
        super(TestFWaaSL2PluginApi, self).setUp()

        self.plugin = fwaas_v2.FWaaSL2PluginApi(
            consts.FIREWALL_PLUGIN, self.host)
        self.plugin.client = mock.Mock()
        self.cctxt = self.plugin.client.prepare()

    def test_get_firewall_group_for_port(self):
        self.plugin.get_firewall_group_for_port(self.ctx, mock.ANY)
        self.cctxt.call.assert_called_once_with(
            self.ctx,
            'get_firewall_group_for_port',
            port_id=mock.ANY
        )

    def test_set_firewall_group_status(self):
        self.plugin.set_firewall_group_status(
            self.ctx, self.fwg_id, 'ACTIVE', self.host)
        self.cctxt.call.assert_called_once_with(
            self.ctx,
            'set_firewall_group_status',
            fwg_id=self.fwg_id,
            status='ACTIVE',
            host=self.host,
        )

    def test_firewall_group_deleted(self):
        self.plugin.firewall_group_deleted(self.ctx, self.fwg_id, self.host)
        self.cctxt.call.assert_called_once_with(
            self.ctx,
            'firewall_group_deleted',
            fwg_id=self.fwg_id,
            host=self.host,
        )


class TestPortFirewallGroupMap(base.BaseTestCase):

    def setUp(self):
        super(TestPortFirewallGroupMap, self).setUp()
        self.fake = fake_data.FakeFWaaSL2Agent()
        self.map = fwaas_v2.PortFirewallGroupMap()
        self.fwg = self.fake.create('fwg')
        self.fwg_id = self.fwg['id']
        self.port = self.fake.create('port')
        self.fwg['ports'] = []

    def test_set_and_get(self):
        self.map.set_fwg(self.fwg)
        self.assertEqual(self.fwg, self.map.get_fwg(self.fwg_id))

    def test_set_and_get_port_fwg(self):
        port1 = self.port
        port2 = self.fake.create('port')
        self.map.set_port_fwg(port1, self.fwg)
        self.map.set_port_fwg(port2, self.fwg)
        self.assertEqual(self.fwg, self.map.get_port_fwg(port1))
        self.assertEqual(self.fwg, self.map.get_port_fwg(port2))
        self.assertIsNone(self.map.get_port_fwg('unknown'))

    def test_remove_port(self):
        port1 = self.port
        port2 = self.fake.create('port')
        self.map.set_port_fwg(port1, self.fwg)
        self.map.remove_port(port2)

        self.map.set_port_fwg(port2, self.fwg)
        self.map.remove_port(port1)
        self.assertIsNone(self.map.get_port(port1))
        self.assertEqual([port2['port_id']],
                         self.map.get_fwg(self.fwg_id)['ports'])
        self.map.remove_port(port2)
        self.assertIsNone(self.map.get_port(port2))
        self.assertEqual([], self.map.get_fwg(self.fwg_id)['ports'])

    def test_remove_non_exist_port(self):
        port1 = self.port
        port2 = self.fake.create('port')
        self.map.set_port_fwg(port1, self.fwg)

        self.map.remove_port(port2)
        self.assertIsNone(self.map.get_port(port2))

    def test_illegal_remove_port_no_relation_with_fwg(self):
        port1 = self.port
        port1_id = port1['port_id']
        self.map.set_port_fwg(port1, self.fwg)
        self.map.port_fwg[port1_id] = None
        self.map.remove_port(port1)
        self.assertIsNone(self.map.get_port(port1))

    def test_remove_fwg(self):
        self.map.set_fwg(self.fwg)
        self.assertEqual(self.fwg, self.map.get_fwg(self.fwg_id))
        self.map.remove_fwg(self.fwg)
        self.assertIsNone(self.map.get_fwg(self.fwg_id))

    def test_remove_fwg_non_exist(self):
        self.map.remove_fwg(self.fwg)
        self.assertIsNone(self.map.get_fwg(self.fwg_id))
