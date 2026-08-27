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

from neutron_lib import context
from oslo_utils import uuidutils

from neutron_fwaas.objects import firewall_v2
from neutron_fwaas.objects import register_objects
from neutron_fwaas.services.firewall.rpc import serialization as rpc_serial
from neutron_fwaas.tests import base


class TestFirewallGroupRpcSerialization(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        register_objects()
        self.ctx = context.get_admin_context()
        self.fwg_id = uuidutils.generate_uuid()
        self.rule_id = uuidutils.generate_uuid()
        self.fwg_ovo = firewall_v2.FirewallGroup(
            self.ctx,
            id=self.fwg_id,
            project_id='project-1',
            name='fwg',
            admin_state_up=True,
            status='ACTIVE',
        )
        self.rule_ovo = firewall_v2.FirewallRuleV2(
            self.ctx,
            id=self.rule_id,
            project_id='project-1',
            name='rule',
            action='allow',
            enabled=True,
        )
        self.rpc_payload = {
            'firewall_group': self.fwg_ovo,
            'ingress_rules': [self.rule_ovo],
            'egress_rules': [],
            'add_port_ids': ['port-1'],
            'del_port_ids': ['port-2'],
            'port_details': {'port-1': {'id': 'port-1', 'host': 'host-a'}},
            'last_port': True,
        }

    def test_rpc_payload_to_legacy_dict(self):
        result = rpc_serial.rpc_payload_to_legacy_dict(self.rpc_payload)
        self.assertEqual(self.fwg_id, result['id'])
        self.assertEqual(['port-1'], result['add-port-ids'])
        self.assertEqual(['port-2'], result['del-port-ids'])
        self.assertEqual({'port-1': {'id': 'port-1', 'host': 'host-a'}},
                         result['port_details'])
        self.assertTrue(result['last-port'])
        self.assertEqual(1, len(result['ingress_rule_list']))
        self.assertEqual(self.rule_id, result['ingress_rule_list'][0]['id'])

    def test_serialize_legacy_returns_dict(self):
        result = rpc_serial.serialize_firewall_group_for_rpc(
            self.rpc_payload, rpc_serial.FWAAS_RPC_VERSION_LEGACY)
        self.assertIsInstance(result, dict)
        self.assertNotIn('versioned_object.name', result)
        self.assertIn('ingress_rule_list', result)

    def test_serialize_ovo_returns_multi_object_payload(self):
        result = rpc_serial.serialize_firewall_group_for_rpc(
            self.rpc_payload, rpc_serial.FWAAS_RPC_VERSION_OVO)
        self.assertTrue(rpc_serial.is_rpc_ovo_payload(result))
        self.assertTrue(rpc_serial.is_ovo_primitive(result['firewall_group']))
        self.assertEqual(1, len(result['ingress_rules']))

    def test_deserialize_round_trip(self):
        wire = rpc_serial.serialize_firewall_group_for_rpc(
            self.rpc_payload, rpc_serial.FWAAS_RPC_VERSION_OVO)
        result = rpc_serial.deserialize_firewall_group_from_rpc(wire)
        self.assertEqual(self.fwg_id, result['id'])
        self.assertEqual(['port-1'], result['add-port-ids'])

    def test_deserialize_legacy_dict_passthrough(self):
        legacy = rpc_serial.rpc_payload_to_legacy_dict(self.rpc_payload)
        result = rpc_serial.deserialize_firewall_group_from_rpc(legacy)
        self.assertEqual(legacy, result)

    def test_build_firewall_group_rpc_payload(self):
        ingress_policy_id = uuidutils.generate_uuid()
        self.fwg_ovo.ingress_firewall_policy_id = ingress_policy_id
        firewall_db = mock.Mock()
        firewall_db.get_firewall_group.return_value = self.fwg_ovo
        firewall_db._get_policy_ordered_rule_objects.return_value = [
            self.rule_ovo]

        rpc_payload = rpc_serial.build_firewall_group_rpc_payload(
            self.ctx, firewall_db, self.fwg_id,
            add_port_ids=['port-1'])

        self.assertEqual(self.fwg_id, rpc_payload['firewall_group'].id)
        self.assertEqual(['port-1'], rpc_payload['add_port_ids'])
        self.assertEqual(1, len(rpc_payload['ingress_rules']))
        firewall_db._get_policy_ordered_rule_objects.assert_called_once_with(
            self.ctx, ingress_policy_id)
