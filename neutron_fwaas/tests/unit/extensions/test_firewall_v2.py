# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import copy

import mock
from neutron.tests.unit.api.v2 import test_base as test_api_v2
from neutron.tests.unit.extensions import base as test_api_v2_extension
from neutron_lib.db import constants as db_const
from oslo_utils import uuidutils
from webob import exc
import webtest

from neutron_fwaas.extensions import firewall_v2

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path
_long_name = 'x' * (db_const.NAME_FIELD_SIZE + 1)
_long_description = 'y' * (db_const.DESCRIPTION_FIELD_SIZE + 1)
_long_tenant = 'z' * (db_const.PROJECT_ID_FIELD_SIZE + 1)

FIREWALL_CONST = 'FIREWALL_V2'


class FirewallExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(FirewallExtensionTestCase, self).setUp()
        plural_mappings = {'firewall_policy': 'firewall_policies'}
        self._setUpExtension(
            'neutron_fwaas.extensions.firewall_v2.Firewallv2PluginBase',
            FIREWALL_CONST, firewall_v2.RESOURCE_ATTRIBUTE_MAP,
            firewall_v2.Firewall_v2, 'fwaas', plural_mappings=plural_mappings)

    def _test_create_firewall_rule(self, src_port, dst_port):
        rule_id = _uuid()
        project_id = _uuid()
        data = {'firewall_rule': {'description': 'descr_firewall_rule1',
                                  'name': 'rule1',
                                  'public': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': src_port,
                                  'destination_port': dst_port,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': project_id}}
        expected_ret_val = copy.copy(data['firewall_rule'])
        expected_ret_val['source_port'] = str(src_port)
        expected_ret_val['destination_port'] = str(dst_port)
        expected_ret_val['id'] = rule_id
        instance = self.plugin.return_value
        instance.create_firewall_rule.return_value = expected_ret_val
        res = self.api.post(_get_path('fwaas/firewall_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        data['firewall_rule'].update({'project_id': project_id})
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('firewall_rule', res)
        self.assertEqual(expected_ret_val, res['firewall_rule'])

    def test_create_firewall_rule_with_integer_ports(self):
        self._test_create_firewall_rule(1, 10)

    def test_create_firewall_rule_with_string_ports(self):
        self._test_create_firewall_rule('1', '10')

    def test_create_firewall_rule_with_port_range(self):
        self._test_create_firewall_rule('1:20', '30:40')

    def test_create_firewall_rule_invalid_long_name(self):
        data = {'firewall_rule': {'description': 'descr_firewall_rule1',
                                  'name': _long_name,
                                  'public': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': 1,
                                  'destination_port': 1,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': _uuid()}}
        res = self.api.post(_get_path('fwaas/firewall_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertIn('Invalid input for name', res.body.decode('utf-8'))

    def test_create_firewall_rule_invalid_long_description(self):
        data = {'firewall_rule': {'description': _long_description,
                                  'name': 'rule1',
                                  'public': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': 1,
                                  'destination_port': 1,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': _uuid()}}
        res = self.api.post(_get_path('fwaas/firewall_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertIn('Invalid input for description',
                      res.body.decode('utf-8'))

    def test_create_firewall_rule_invalid_long_tenant_id(self):
        data = {'firewall_rule': {'description': 'desc',
                                  'name': 'rule1',
                                  'public': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': 1,
                                  'destination_port': 1,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': _long_tenant}}
        res = self.api.post(_get_path('fwaas/firewall_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertIn('Invalid input for ', res.body.decode('utf-8'))

    def test_firewall_rule_list(self):
        rule_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': rule_id}]

        instance = self.plugin.return_value
        instance.get_firewall_rules.return_value = return_value

        res = self.api.get(_get_path('fwaas/firewall_rules', fmt=self.fmt))

        instance.get_firewall_rules.assert_called_with(mock.ANY,
                                                       fields=mock.ANY,
                                                       filters=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)

    def test_firewall_rule_get(self):
        rule_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': rule_id}

        instance = self.plugin.return_value
        instance.get_firewall_rule.return_value = return_value

        res = self.api.get(_get_path('fwaas/firewall_rules',
                                     id=rule_id, fmt=self.fmt))

        instance.get_firewall_rule.assert_called_with(mock.ANY,
                                                      rule_id,
                                                      fields=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('firewall_rule', res)
        self.assertEqual(return_value, res['firewall_rule'])

    def test_firewall_rule_update(self):
        rule_id = _uuid()
        update_data = {'firewall_rule': {'action': 'deny'}}
        return_value = {'tenant_id': _uuid(),
                        'id': rule_id}

        instance = self.plugin.return_value
        instance.update_firewall_rule.return_value = return_value

        res = self.api.put(_get_path('fwaas/firewall_rules', id=rule_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_firewall_rule.assert_called_with(
            mock.ANY,
            rule_id,
            firewall_rule=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('firewall_rule', res)
        self.assertEqual(return_value, res['firewall_rule'])

    def test_firewall_rule_delete(self):
        self._test_entity_delete('firewall_rule')

    def test_create_firewall_policy(self):
        policy_id = _uuid()
        project_id = _uuid()
        data = {'firewall_policy': {'description': 'descr_firewall_policy1',
                                    'name': 'new_fw_policy1',
                                    'public': False,
                                    'firewall_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': project_id}}
        return_value = copy.copy(data['firewall_policy'])
        return_value.update({'id': policy_id})

        instance = self.plugin.return_value
        instance.create_firewall_policy.return_value = return_value
        res = self.api.post(_get_path('fwaas/firewall_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        data['firewall_policy'].update({'project_id': project_id})
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('firewall_policy', res)
        self.assertEqual(return_value, res['firewall_policy'])

    def test_create_firewall_policy_invalid_long_name(self):
        data = {'firewall_policy': {'description': 'descr_firewall_policy1',
                                    'name': _long_name,
                                    'public': False,
                                    'firewall_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': _uuid()}}
        res = self.api.post(_get_path('fwaas/firewall_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertIn('Invalid input for name', res.body.decode('utf-8'))

    def test_create_firewall_policy_invalid_long_description(self):
        data = {'firewall_policy': {'description': _long_description,
                                    'name': 'new_fw_policy1',
                                    'public': False,
                                    'firewall_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': _uuid()}}
        res = self.api.post(_get_path('fwaas/firewall_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertIn('Invalid input for description',
                      res.body.decode('utf-8'))

    def test_create_firewall_policy_invalid_long_tenant_id(self):
        data = {'firewall_policy': {'description': 'desc',
                                    'name': 'new_fw_policy1',
                                    'public': False,
                                    'firewall_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': _long_tenant}}
        res = self.api.post(_get_path('fwaas/firewall_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertIn('Invalid input for ', res.body.decode('utf-8'))

    def test_firewall_policy_list(self):
        policy_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': policy_id}]

        instance = self.plugin.return_value
        instance.get_firewall_policies.return_value = return_value

        res = self.api.get(_get_path('fwaas/firewall_policies',
                                     fmt=self.fmt))

        instance.get_firewall_policies.assert_called_with(mock.ANY,
                                                          fields=mock.ANY,
                                                          filters=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)

    def test_firewall_policy_get(self):
        policy_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': policy_id}

        instance = self.plugin.return_value
        instance.get_firewall_policy.return_value = return_value

        res = self.api.get(_get_path('fwaas/firewall_policies',
                                     id=policy_id, fmt=self.fmt))

        instance.get_firewall_policy.assert_called_with(mock.ANY,
                                                        policy_id,
                                                        fields=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('firewall_policy', res)
        self.assertEqual(return_value, res['firewall_policy'])

    def test_firewall_policy_update(self):
        policy_id = _uuid()
        update_data = {'firewall_policy': {'audited': True}}
        return_value = {'tenant_id': _uuid(),
                        'id': policy_id}

        instance = self.plugin.return_value
        instance.update_firewall_policy.return_value = return_value

        res = self.api.put(_get_path('fwaas/firewall_policies',
                                     id=policy_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_firewall_policy.assert_called_with(
            mock.ANY,
            policy_id,
            firewall_policy=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('firewall_policy', res)
        self.assertEqual(return_value, res['firewall_policy'])

    def test_firewall_policy_update_malformed_rules(self):
        # emulating client request when no rule uuids are provided for
        # --firewall_rules parameter
        update_data = {'firewall_policy': {'firewall_rules': True}}
        # have to check for generic AppError
        self.assertRaises(
            webtest.AppError,
            self.api.put,
            _get_path('fwaas/firewall_policies', id=_uuid(), fmt=self.fmt),
            self.serialize(update_data))

    def test_firewall_policy_delete(self):
        self._test_entity_delete('firewall_policy')

    def test_firewall_policy_insert_rule(self):
        firewall_policy_id = _uuid()
        firewall_rule_id = _uuid()
        ref_firewall_rule_id = _uuid()

        insert_data = {'firewall_rule_id': firewall_rule_id,
                       'insert_before': ref_firewall_rule_id,
                       'insert_after': None}
        return_value = {'firewall_policy':
                        {'tenant_id': _uuid(),
                         'id': firewall_policy_id,
                         'firewall_rules': [ref_firewall_rule_id,
                                            firewall_rule_id]}}

        instance = self.plugin.return_value
        instance.insert_rule.return_value = return_value

        path = _get_path('fwaas/firewall_policies', id=firewall_policy_id,
                         action="insert_rule",
                         fmt=self.fmt)
        res = self.api.put(path, self.serialize(insert_data))
        instance.insert_rule.assert_called_with(mock.ANY, firewall_policy_id,
                                                insert_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertEqual(return_value, res)

    def test_firewall_policy_remove_rule(self):
        firewall_policy_id = _uuid()
        firewall_rule_id = _uuid()

        remove_data = {'firewall_rule_id': firewall_rule_id}
        return_value = {'firewall_policy':
                        {'tenant_id': _uuid(),
                         'id': firewall_policy_id,
                         'firewall_rules': []}}

        instance = self.plugin.return_value
        instance.remove_rule.return_value = return_value

        path = _get_path('fwaas/firewall_policies', id=firewall_policy_id,
                         action="remove_rule",
                         fmt=self.fmt)
        res = self.api.put(path, self.serialize(remove_data))
        instance.remove_rule.assert_called_with(mock.ANY, firewall_policy_id,
                                                remove_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertEqual(return_value, res)

    def test_create_firewall_group_invalid_long_attributes(self):
        long_targets = [{'name': _long_name},
                        {'description': _long_description},
                        {'tenant_id': _long_tenant}]

        for target in long_targets:
            data = {'firewall_group': {'description': 'fake_description',
                                       'name': 'fake_name',
                                       'tenant_id': 'fake-tenant_id',
                                       'public': False,
                                       'ingress_firewall_policy_id': None,
                                       'egress_firewall_policy_id': None,
                                       'admin_state_up': True,
                                       'ports': []}}
            data['firewall_group'].update(target)
            res = self.api.post(_get_path('fwaas/firewall_groups',
                                fmt=self.fmt),
                                self.serialize(data),
                                content_type='application/%s' % self.fmt,
                                status=exc.HTTPBadRequest.code)
            #TODO(njohnston): Remove this when neutron starts returning
            # project_id in a dependable fashion, as opposed to tenant_id.
            target_attr_name = list(target)[0]
            if target_attr_name == 'tenant_id':
                target_attr_name = ''
            self.assertIn('Invalid input for %s' % target_attr_name,
                          res.body.decode('utf-8'))
