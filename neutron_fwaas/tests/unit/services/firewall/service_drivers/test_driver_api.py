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

from neutron_fwaas.common import fwaas_constants as const
from neutron_fwaas.tests.unit.services.firewall import test_fwaas_plugin_v2


class FireWallDriverDBMixinTestCase(test_fwaas_plugin_v2.
                                    FirewallPluginV2TestCase):

    def setUp(self):
        provider = ('neutron_fwaas.services.firewall.service_drivers.'
                    'driver_api.FirewallDriverDB')
        super(FireWallDriverDBMixinTestCase, self).setUp(
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
        self.fake_fwg = {
            'id': 'fake_fwg_id',
            'ingress_firewall_policy_id': 'fake_ifwp_id',
            'egress_firewall_policy_id': 'fake_efwp_id',
            'ports': [],
            'tenant_id': 'fake_tenant_id',
            'status': 'CREATED'
        }

        self.fake_fwp = {
            'id': 'fake_fwp_id',
            'firewall_rules': [],
            'info': 'fake_rule_info',
            'project_id': 'fake_project_id'
        }

        self.fake_fwr = {
            'id': 'fake_fwr_id',
            'firewall_policy_id': [],
            'project_id': 'fake_project_id'
        }

    # Test Firewall Group
    def test_create_firewall_group(self):

        with mock.patch.object(self.firewall_db, 'create_firewall_group',
                               return_value=self.fake_fwg):
            self.driver_api.create_firewall_group_postcommit = mock.Mock()
            self.driver_api.create_firewall_group(self.ctx, self.fake_fwg)
            self.driver_api.create_firewall_group_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwg)
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_GROUP,
                                   events.AFTER_CREATE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_delete_firewall_group(self):

        with mock.patch.object(self.firewall_db, 'get_firewall_group',
                               return_value=self.fake_fwg):
            self.driver_api.delete_firewall_group_postcommit = mock.Mock()
            self.driver_api.delete_firewall_group(self.ctx, 'fake_fwg_id')
            self.driver_api.delete_firewall_group_postcommit.\
                assert_called_once_with(self.ctx, self.fake_fwg)
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_GROUP,
                                   events.AFTER_DELETE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_update_firewall_group(self):
        fake_fwg_delta = {
            'ingress_firewall_policy_id': 'fake_ifwp_delta_id',
            'egress_firewall_policy_id': 'fake_efwp_delta_id',
            'ports': [],
        }

        old_fake_fwg = {
            'id': 'fake_fwg_id',
            'ingress_firewall_policy_id': 'old_fake_ifwp_id',
            'egress_firewall_policy_id': 'old_fake_efwp_id',
            'ports': [],
            'tenant_id': 'fake_tenant_id',
            'status': 'CREATED'
        }

        with mock.patch.object(self.firewall_db, 'get_firewall_group',
                               return_value=old_fake_fwg):
            new_fake_fwg = copy.deepcopy(old_fake_fwg)
            new_fake_fwg.update(fake_fwg_delta)

            with mock.patch.object(self.firewall_db, 'update_firewall_group',
                                   return_value=new_fake_fwg):
                self.driver_api.\
                    update_firewall_group_postcommit = mock.Mock()
                self.driver_api.\
                    update_firewall_group(self.ctx, 'fake_fwg_id',
                                          fake_fwg_delta)
                self.driver_api.update_firewall_group_postcommit.\
                    assert_called_once_with(self.ctx, old_fake_fwg,
                                            new_fake_fwg)
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
                assert_called_once_with(self.ctx, self.fake_fwp)
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
                    assert_called_once_with(self.ctx, self.fake_fwp)
                self.mock_registry_publish.\
                    assert_called_with(const.FIREWALL_POLICY,
                                       events.AFTER_UPDATE,
                                       self.driver_api,
                                       payload=self.m_payload)

    def test_update_firewall_policy(self):
        fake_fwp_delta = {
            'firewall_rules': [],
        }

        old_fake_fwp = {
            'id': 'fake_fwp_id',
            'firewall_rules': [],
            'project_id': 'fake_project_id'
        }

        with mock.patch.object(self.firewall_db, 'get_firewall_policy',
                               return_value=old_fake_fwp):
            new_fake_fwp = copy.deepcopy(old_fake_fwp)
            new_fake_fwp.update(fake_fwp_delta)

            with mock.patch.object(self.firewall_db, 'update_firewall_policy',
                                   return_value=new_fake_fwp):
                self.driver_api.\
                    update_firewall_policy_postcommit = mock.Mock()
                self.driver_api.\
                    update_firewall_policy(self.ctx, 'fake_fwp_id',
                                           fake_fwp_delta)
                self.driver_api.update_firewall_policy_postcommit.\
                    assert_called_once_with(self.ctx, old_fake_fwp,
                                            new_fake_fwp)
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
                assert_called_once_with(self.ctx, self.fake_fwr)
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
                assert_called_once_with(self.ctx, self.fake_fwr)
            self.mock_registry_publish.\
                assert_called_with(const.FIREWALL_RULE,
                                   events.AFTER_DELETE,
                                   self.driver_api,
                                   payload=self.m_payload)

    def test_update_firewall_rule(self):

        fake_fwr_delta = {
            'firewall_policy_id': [],
        }

        old_fake_fwr = {
            'id': 'fake_fwr_id',
            'firewall_policy_id': [],
            'project_id': 'fake_project_id'
        }

        with mock.patch.object(self.firewall_db, 'get_firewall_rule',
                               return_value=old_fake_fwr):
            new_fake_fwr = copy.deepcopy(old_fake_fwr)
            new_fake_fwr.update(fake_fwr_delta)

            with mock.patch.object(self.firewall_db, 'update_firewall_rule',
                                   return_value=new_fake_fwr):
                self.driver_api.\
                    update_firewall_rule_postcommit = mock.Mock()
                self.driver_api. \
                    update_firewall_rule(self.ctx, 'fake_fwr_id',
                                         fake_fwr_delta)
                self.driver_api.update_firewall_rule_postcommit.\
                    assert_called_once_with(self.ctx, old_fake_fwr,
                                            new_fake_fwr)
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
