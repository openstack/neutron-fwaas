# Copyright 2015 Freescale, Inc.
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

import contextlib

import mock
from neutron import context
from neutron import manager
from webob import exc

from neutron.plugins.common import constants as const
from neutron_fwaas.tests.unit.db.firewall import (
    test_firewall_db as test_db_firewall)

"""Unit testing for Freescale FWaaS Plugin."""

PLUGIN = ("neutron_fwaas.services.firewall.freescale"
          ".fwaas_plugin.FirewallPlugin")


class TestFirewallCallbacks(test_db_firewall.FirewallPluginDbTestCase):

    def setUp(self):
        mock.patch('neutronclient.v2_0.client.Client').start()
        super(TestFirewallCallbacks, self).setUp(fw_plugin=PLUGIN)
        n_mgr = manager.NeutronManager
        self.plugin = n_mgr.get_service_plugins()[const.FIREWALL]
        self.callbacks = self.plugin.endpoints[0]
        self.ctx = context.get_admin_context()

    def test_get_firewalls_for_tenant(self):
        tenant_id = 'test-tenant'
        with self.firewall_rule(name='fwr1', tenant_id=tenant_id,
                                do_delete=False) as fr:
            with self.firewall_policy(tenant_id=tenant_id,
                                      do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fw_id = fr['firewall_rule']['id']
                data = {'firewall_policy':
                        {'firewall_rules': [fw_id]}}
                self.plugin.update_firewall_policy(self.ctx, fwp_id, data)
                admin_state = test_db_firewall.ADMIN_STATE_UP
                with self.firewall(firewall_policy_id=fwp_id,
                                   tenant_id=tenant_id,
                                   do_delete=False,
                                   admin_state_up=admin_state) as fw:
                    self.callbacks.get_firewalls_for_tenant(self.ctx,
                                                            host='dummy')
                    fw_id = fw['firewall']['id']
                    fw['firewall']['config_mode'] = "NN"
                    self.plugin._client.show_firewall.assert_called_once_with(
                        fw_id)
                    self.plugin.delete_firewall(self.ctx, fw_id)
                self.callbacks.firewall_deleted(self.ctx, fw_id)
            self.plugin.delete_firewall_policy(self.ctx, fwp_id)
        self.plugin.delete_firewall_rule(self.ctx, fr['firewall_rule']['id'])


class TestFreescaleFirewallPlugin(test_db_firewall.TestFirewallDBPlugin):

    def setUp(self):
        mock.patch('neutronclient.v2_0.client.Client').start()
        super(TestFreescaleFirewallPlugin, self).setUp(fw_plugin=PLUGIN)
        self.plugin = manager.NeutronManager.get_service_plugins()['FIREWALL']
        self.callbacks = self.plugin.endpoints[0]
        self.clnt = self.plugin._client
        self.ctx = context.get_admin_context()

    def test_create_update_delete_firewall_rule(self):
        """Testing create, update and delete firewall rule."""
        ctx = context.get_admin_context()
        clnt = self.plugin._client
        with self.firewall_rule(do_delete=False) as fwr:
            fwr_id = fwr['firewall_rule']['id']
            # Create Firewall Rule
            crd_rule = {'firewall_rule': fwr}
            clnt.create_firewall_rule.assert_called_once_with(fwr)
            # Update Firewall Rule
            data = {'firewall_rule': {'name': 'new_rule_name',
                                      'source_port': '10:20',
                                      'destination_port': '30:40'}}
            fw_rule = self.plugin.update_firewall_rule(ctx, fwr_id, data)
            crd_rule = {'firewall_rule': fw_rule}
            clnt.update_firewall_rule.assert_called_once_with(fwr_id, crd_rule)
            # Delete Firewall Rule
            self.plugin.delete_firewall_rule(ctx, fwr_id)
            clnt.delete_firewall_rule.assert_called_once_with(fwr_id)

    def test_create_update_delete_firewall_policy(self):
        """Testing create, update and delete firewall policy."""
        with self.firewall_policy(do_delete=False) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            # Create Firewall Policy
            crd_policy = {'firewall_policy': fwp}
            self.clnt.create_firewall_policy.assert_called_once_with(fwp)
            # Update Firewall Policy
            data = {'firewall_policy': {'name': 'updated-name'}}
            fwp = self.plugin.update_firewall_policy(self.ctx, fwp_id, data)
            crd_policy = {'firewall_policy': fwp}
            self.clnt.update_firewall_policy.assert_called_once_with(
                fwp_id,
                crd_policy)
            # Delete Firewall Policy
            self.plugin.delete_firewall_policy(self.ctx, fwp_id)
            self.clnt.delete_firewall_policy.assert_called_once_with(fwp_id)

    def test_create_firewall(self):
        name = "firewall-fake"
        expected_attrs = self._get_test_firewall_attrs(name)
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            expected_attrs['firewall_policy_id'] = fwp_id
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False) as actual_firewall:
                fw_id = actual_firewall['firewall']['id']
                self.assertDictSupersetOf(expected_attrs,
                        actual_firewall['firewall'])
            self.plugin.delete_firewall(self.ctx, fw_id)
            self.clnt.delete_firewall.assert_called_once_with(fw_id)
            self.callbacks.firewall_deleted(self.ctx, fw_id)

    def test_show_firewall(self):
        name = "firewall1"
        expected_attrs = self._get_test_firewall_attrs(name)
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            expected_attrs['firewall_policy_id'] = fwp_id
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False) as actual_firewall:
                fw_id = actual_firewall['firewall']['id']
                req = self.new_show_request('firewalls', fw_id,
                                            fmt=self.fmt)
                actual_fw = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertDictSupersetOf(expected_attrs,
                        actual_fw['firewall'])
            self.plugin.delete_firewall(self.ctx, fw_id)
            self.clnt.delete_firewall.assert_called_once_with(fw_id)
            self.callbacks.firewall_deleted(self.ctx, fw_id)

    def test_update_firewall(self):
        name = "new_firewall1"
        expected_attrs = self._get_test_firewall_attrs(name)
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            expected_attrs['firewall_policy_id'] = fwp_id
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False) as firewall:
                fw_id = firewall['firewall']['id']
                self.callbacks.set_firewall_status(self.ctx, fw_id,
                        const.ACTIVE)
                data = {'firewall': {'name': name}}
                req = self.new_update_request('firewalls', data, fw_id)
                actual_fw = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                expected_attrs = self._replace_firewall_status(expected_attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                self.assertDictSupersetOf(expected_attrs,
                        actual_fw['firewall'])
            self.plugin.delete_firewall(self.ctx, fw_id)
            self.clnt.delete_firewall.assert_called_once_with(fw_id)
            self.callbacks.firewall_deleted(self.ctx, fw_id)

    def test_list_firewalls(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with contextlib.nested(self.firewall(name='fw1',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw'),
                                   self.firewall(name='fw2',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw'),
                                   self.firewall(name='fw3',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw')) as fwalls:
                self._test_list_resources('firewall', fwalls,
                                          query_params='description=fw')
            for fw in fwalls:
                fw_id = fw['firewall']['id']
                self.plugin.delete_firewall(self.ctx, fw_id)
                self.callbacks.firewall_deleted(self.ctx, fw_id)

    def test_delete_firewall_policy_with_firewall_association(self):
        attrs = self._get_test_firewall_attrs()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False)as fw:
                fw_id = fw['firewall']['id']
                req = self.new_delete_request('firewall_policies', fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPConflict.code)
            self.plugin.delete_firewall(self.ctx, fw_id)
            self.clnt.delete_firewall.assert_called_once_with(fw_id)
            self.callbacks.firewall_deleted(self.ctx, fw_id)

    def test_update_firewall_policy_assoc_with_other_tenant_firewall(self):
        with self.firewall_policy(shared=True, tenant_id='tenant1') as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               do_delete=False) as fw:
                fw_id = fw['firewall']['id']
                data = {'firewall_policy': {'shared': False}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPConflict.code)
            self.plugin.delete_firewall(self.ctx, fw_id)
            self.clnt.delete_firewall.assert_called_once_with(fw_id)
            self.callbacks.firewall_deleted(self.ctx, fw_id)

    def test_delete_firewall(self):
        attrs = self._get_test_firewall_attrs()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False) as firewall:
                fw_id = firewall['firewall']['id']
                attrs = self._replace_firewall_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_DELETE)
                req = self.new_delete_request('firewalls', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
            self.clnt.delete_firewall.assert_called_once_with(fw_id)
            self.plugin.endpoints[0].firewall_deleted(self.ctx, fw_id)

    def test_insert_remove_rule(self):
        """Testing Insert and Remove rule operations."""
        status_update = {"firewall": {"status": 'PENDING_UPDATE'}}
        with self.firewall_rule(name='fake_rule',
                                do_delete=False) as fr1:
            fr_id = fr1['firewall_rule']['id']
            with self.firewall_policy(do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id,
                                   do_delete=False) as fw:
                    fw_id = fw['firewall']['id']
                    # Insert Rule
                    rule_info = {'firewall_rule_id': fr_id}
                    self.plugin.insert_rule(self.ctx, fwp_id, rule_info)
                    fp_insert_rule = self.clnt.firewall_policy_insert_rule
                    fp_insert_rule.assert_called_once_with(fwp_id, rule_info)
                    self.clnt.update_firewall.assert_called_once_with(
                        fw_id,
                        status_update)
                    # Remove Rule
                    rule_info = {'firewall_rule_id': fr_id}
                    self.plugin.remove_rule(self.ctx, fwp_id, rule_info)
                    fp_remove_rule = self.clnt.firewall_policy_remove_rule
                    fp_remove_rule.assert_called_once_with(fwp_id, rule_info)
                    self.clnt.update_firewall.assert_called_with(fw_id,
                                                                 status_update)

    def test_create_firewall_with_dvr(self):
        """Skip DVR Testing."""
        self.skipTest("DVR not supported")
