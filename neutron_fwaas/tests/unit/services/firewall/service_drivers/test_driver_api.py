# Copyright (c) 2018 Fujitsu Limited.
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

import copy
from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib import context
from oslo_utils import uuidutils

from neutron_fwaas.common import fwaas_constants as const
from neutron_fwaas.objects import firewall_v2 as fwaas_obj
from neutron_fwaas.tests.unit.services.firewall import test_fwaas_plugin_v2


class FireWallDriverDBMixinTestCase(test_fwaas_plugin_v2.
                                    FirewallPluginV2TestCase):

    def setUp(self):
        provider = ('neutron_fwaas.services.firewall.service_drivers.'
                    'driver_api.FirewallDriverDB')
        super().setUp(
            service_provider=provider)
        self._mp_registry_publish = mock.patch(
            'neutron_lib.callbacks.registry.publish')
        self.mock_registry_publish = self._mp_registry_publish.start()
        self.addCleanup(self._mp_registry_publish.stop)
        self.driver_api = self.plugin.driver
        self.ctx = context.get_admin_context()
        self.firewall_db = self.plugin.driver.firewall_db
        self.m_payload = mock.Mock()
        self._mock_payload = mock.patch(
            'neutron_lib.callbacks.events.DBEventPayload')
        m_db_event_payload = self._mock_payload.start()
        self.addCleanup(self._mock_payload.stop)
        m_db_event_payload.return_value = self.m_payload
        self.fake_fwg = fwaas_obj.FirewallGroup(
            id=uuidutils.generate_uuid(),
            name='fake_fwg_name',
            ingress_firewall_policy_id=uuidutils.generate_uuid(),
            egress_firewall_policy_id=uuidutils.generate_uuid(),
            port_associations=[],
            project_id='fake_project_id',
            status='CREATED'
        )

        self.fake_fwp = fwaas_obj.FirewallPolicy(
            id=uuidutils.generate_uuid(),
            name='fake_fwp_name',
            firewall_rules=[],
            info='fake_rule_info',
            project_id='fake_project_id'
        )

        self.fake_fwr = fwaas_obj.FirewallRuleV2(
            id=uuidutils.generate_uuid(),
            name='fake_fwr_name',
            firewall_policy_id=[],
            project_id='fake_project_id'
        )

    # Test Firewall Group
    def test_create_firewall_group(self):

        with mock.patch.object(self.firewall_db, 'create_firewall_group',
                               return_value=self.fake_fwg):
            self.driver_api.create_firewall_group_postcommit = mock.Mock()
            self.driver_api.create_firewall_group(self.ctx, self.fake_fwg)
            self.driver_api.create_firewall_group_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwg.to_dict())
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_GROUP,
                                   events.AFTER_CREATE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_delete_firewall_group(self):

        with mock.patch.object(self.firewall_db, 'get_firewall_group',
                               return_value=self.fake_fwg), \
                mock.patch.object(self.firewall_db, 'delete_firewall_group'):
            self.driver_api.delete_firewall_group_postcommit = mock.Mock()
            self.driver_api.delete_firewall_group(self.ctx, 'fake_fwg_id')
            self.driver_api.delete_firewall_group_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwg.to_dict())
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_GROUP,
                                   events.AFTER_DELETE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_update_firewall_group(self):
        fake_fwg_delta = {
            'ingress_firewall_policy_id': uuidutils.generate_uuid(),
            'egress_firewall_policy_id': uuidutils.generate_uuid(),
        }

        fwg = fwaas_obj.FirewallGroup(
            id=uuidutils.generate_uuid(),
            ingress_firewall_policy_id=uuidutils.generate_uuid(),
            egress_firewall_policy_id=uuidutils.generate_uuid(),
            port_associations=[],
            project_id='fake_project_id',
            status='CREATED'
        )

        with mock.patch.object(self.firewall_db, 'get_firewall_group',
                               return_value=fwg):
            new_fwg = copy.deepcopy(fwg)
            new_fwg.ingress_firewall_policy_id = (
                fake_fwg_delta['ingress_firewall_policy_id'])
            new_fwg.egress_firewall_policy_id = (
                fake_fwg_delta['egress_firewall_policy_id'])

            with mock.patch.object(self.firewall_db, 'update_firewall_group',
                                   return_value=new_fwg):
                self.driver_api.\
                    update_firewall_group_postcommit = mock.Mock()
                self.driver_api.\
                    update_firewall_group(self.ctx, 'fake_fwg_id',
                                          fake_fwg_delta)
                self.driver_api.update_firewall_group_postcommit.\
                    assert_called_once_with(self.ctx, fwg.to_dict(),
                                            new_fwg.to_dict())
                self.mock_registry_publish.\
                    assert_called_with(const.FIREWALL_GROUP,
                                       events.AFTER_UPDATE,
                                       self.driver_api,
                                       payload=self.m_payload)

    # Test Firewall Policy
    def test_create_firewall_policy(self):

        with mock.patch.object(self.firewall_db, 'create_firewall_policy',
                               return_value=self.fake_fwp):
            self.driver_api.create_firewall_policy_postcommit = mock.Mock()
            self.driver_api.create_firewall_policy(self.ctx, self.fake_fwp)
            self.driver_api.create_firewall_policy_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwp.to_dict())
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_POLICY,
                                   events.AFTER_CREATE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_delete_firewall_policy(self):

        with mock.patch.object(self.firewall_db, 'delete_firewall_policy'):
            with mock.patch.object(self.firewall_db, 'get_firewall_policy',
                                   return_value=self.fake_fwp):
                self.driver_api.\
                    delete_firewall_policy_postcommit = mock.Mock()
                self.driver_api.\
                    delete_firewall_policy(self.ctx, 'fake_fwp_id')
                self.driver_api.delete_firewall_policy_postcommit.\
                    assert_called_once_with(self.ctx, self.fake_fwp.to_dict())
                self.mock_registry_publish.\
                    assert_called_with(const.FIREWALL_POLICY,
                                       events.AFTER_UPDATE,
                                       self.driver_api,
                                       payload=self.m_payload)

    def test_update_firewall_policy(self):
        fake_fwp_delta = {
            'name': 'new_fwp_name',
        }

        fwp = fwaas_obj.FirewallPolicy(
            id=uuidutils.generate_uuid(),
            firewall_rules=[],
            project_id='fake_project_id',
            name='fake_fwp_name',
        )

        with mock.patch.object(self.firewall_db, 'get_firewall_policy',
                               return_value=fwp):
            new_fwp = copy.deepcopy(fwp)
            new_fwp.name = fake_fwp_delta['name']

            with mock.patch.object(self.firewall_db, 'update_firewall_policy',
                                   return_value=new_fwp):
                self.driver_api.\
                    update_firewall_policy_postcommit = mock.Mock()
                self.driver_api.\
                    update_firewall_policy(self.ctx, 'fake_fwp_id',
                                           fake_fwp_delta)
                self.driver_api.update_firewall_policy_postcommit.\
                    assert_called_once_with(self.ctx, fwp.to_dict(),
                                            new_fwp.to_dict())
                self.mock_registry_publish.\
                    assert_called_with(const.FIREWALL_POLICY,
                                       events.AFTER_UPDATE,
                                       self.driver_api,
                                       payload=self.m_payload)

    # Test Firewall Rule
    def test_create_firewall_rule(self):

        with mock.patch.object(self.firewall_db, 'create_firewall_rule',
                               return_value=self.fake_fwr):
            self.driver_api.create_firewall_rule_postcommit = mock.Mock()
            self.driver_api.create_firewall_rule(self.ctx, self.fake_fwr)
            self.driver_api.create_firewall_rule_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwr.to_dict())
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_RULE,
                                   events.AFTER_CREATE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_delete_firewall_rule(self):

        self.firewall_db.delete_firewall_rule = mock.Mock()

        with mock.patch.object(self.firewall_db, 'get_firewall_rule',
                               return_value=self.fake_fwr):
            self.driver_api.\
                delete_firewall_rule_postcommit = mock.Mock()
            self.driver_api.\
                delete_firewall_rule(self.ctx, 'fake_fwr_id')
            self.driver_api.delete_firewall_rule_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwr.to_dict())
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_RULE,
                                   events.AFTER_DELETE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_update_firewall_rule(self):
        fake_fwr_delta = {
            'name': 'new_fwr_name'
        }
        fwr = fwaas_obj.FirewallRuleV2(
            id=uuidutils.generate_uuid(),
            firewall_policy_id=[],
            project_id='fake_project_id',
        )

        with mock.patch.object(self.firewall_db, 'get_firewall_rule',
                               return_value=fwr):
            new_fwr = copy.deepcopy(fwr)
            new_fwr.name = fake_fwr_delta['name']

            with mock.patch.object(self.firewall_db, 'update_firewall_rule',
                                   return_value=new_fwr):
                self.driver_api.\
                    update_firewall_rule_postcommit = mock.Mock()
                self.driver_api. \
                    update_firewall_rule(self.ctx, 'fake_fwr_id',
                                         fake_fwr_delta)
                self.driver_api.update_firewall_rule_postcommit.\
                    assert_called_once_with(self.ctx, fwr.to_dict(),
                                            new_fwr.to_dict())
                self.mock_registry_publish.\
                    assert_called_with(const.FIREWALL_RULE,
                                       events.AFTER_UPDATE,
                                       self.driver_api,
                                       payload=self.m_payload)

    def test_insert_rule(self):

        with mock.patch.object(self.firewall_db, 'insert_rule',
                               return_value=self.fake_fwp):
            self.driver_api.insert_rule_postcommit = mock.Mock()
            self.driver_api.insert_rule(self.ctx, 'fake_fwp_id',
                                        'fake_rule_info')
            self.driver_api.insert_rule_postcommit.\
                assert_called_once_with(self.ctx, 'fake_fwp_id',
                                        'fake_rule_info')
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_POLICY,
                                   events.AFTER_UPDATE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_remove_rule(self):

        with mock.patch.object(self.firewall_db, 'remove_rule',
                               return_value=self.fake_fwp):
            self.driver_api.remove_rule_postcommit = mock.Mock()
            self.driver_api.remove_rule(self.ctx, 'fake_fwp_id',
                                        'fake_rule_info')
            self.driver_api.remove_rule_postcommit.\
                assert_called_once_with(self.ctx, 'fake_fwp_id',
                                        'fake_rule_info')
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_POLICY,
                                   events.AFTER_UPDATE,
                                   self.driver_api,
                                   payload=self.m_payload)
