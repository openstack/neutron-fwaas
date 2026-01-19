# Copyright 2026
# All rights reserved.
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

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    acl as ovn_acl
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    constants as ovn_fw_const
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    ovn_db_sync
from neutron_fwaas.tests.unit.services.firewall import test_fwaas_plugin_v2


class TestOvnNbDbSync(test_fwaas_plugin_v2.FirewallPluginV2TestCase):

    def setUp(self):
        super().setUp()
        self.core_plugin = mock.MagicMock()
        self.ovn_driver = mock.MagicMock()
        self.ovn_nb_api = mock.MagicMock()
        self.ovn_driver.nb_ovn = self.ovn_nb_api
        self.mode = ovn_const.OVN_DB_SYNC_MODE_REPAIR
        self.fwaas_plugin = mock.MagicMock()
        self.fwaas_ovn_driver = mock.MagicMock()
        self.fwaas_plugin.driver = self.fwaas_ovn_driver

        with mock.patch('neutron_lib.plugins.directory.get_plugin',
                        return_value=self.fwaas_plugin):
            self.sync = ovn_db_sync.OvnNbDbSync(
                self.core_plugin, self.ovn_driver, self.mode)
        self.sync.ovn_nb_api = self.ovn_nb_api
        self.ctx = mock.Mock()

    def test__get_fw_port_groups_from_neutron_db(self):
        """Test that DEFAULT_FWG is filtered out from results."""
        fwg1 = {
            'id': 'fwg-id-1',
            'name': 'test-fwg-1',
            'ports': ['port1', 'port2']
        }
        fwg2 = {
            'id': 'fwg-id-2',
            'name': fwaas_constants.DEFAULT_FWG,
            'ports': []
        }
        fwg3 = {
            'id': 'fwg-id-3',
            'name': 'test-fwg-3',
            'ports': ['port3']
        }

        self.fwaas_ovn_driver.get_firewall_groups.return_value = [
            fwg1, fwg2, fwg3]

        result = self.sync._get_fw_port_groups_from_neutron_db(self.ctx)

        self.assertEqual(2, len(result))
        self.assertIn('fwg-id-1', result)
        self.assertIn('fwg-id-3', result)
        self.assertNotIn('fwg-id-2', result)
        self.assertEqual(fwg1, result['fwg-id-1'])
        self.assertEqual(fwg3, result['fwg-id-3'])
        self.fwaas_ovn_driver.get_firewall_groups.assert_called_once_with(
            self.ctx)

    def test__get_fw_port_groups_from_ovn_db(self):
        """Test extraction of port groups with external IDs."""
        pg1 = mock.MagicMock()
        pg1.external_ids = {
            ovn_fw_const.OVN_FWG_EXT_ID_KEY: 'fwg-id-1'
        }
        pg1.name = 'pg-name-1'
        pg1.acls = ['acl1', 'acl2']

        pg2 = mock.MagicMock()
        pg2.external_ids = {
            ovn_fw_const.OVN_FWG_EXT_ID_KEY: 'fwg-id-2'
        }
        pg2.name = 'pg-name-2'
        pg2.acls = ['acl3']

        pg3 = mock.MagicMock()
        pg3.external_ids = {}  # No external ID, should be skipped

        execute_mock = mock.MagicMock()
        execute_mock.execute.return_value = [pg1, pg2, pg3]
        self.ovn_nb_api.db_list_rows.return_value = execute_mock

        result = self.sync._get_fw_port_groups_from_ovn_db()

        self.assertEqual(2, len(result))
        self.assertIn('fwg-id-1', result)
        self.assertIn('fwg-id-2', result)
        self.assertEqual('fwg-id-1', result['fwg-id-1']['id'])
        self.assertEqual('pg-name-1', result['fwg-id-1']['name'])
        self.assertEqual(['acl1', 'acl2'], result['fwg-id-1']['acls'])
        self.assertEqual('fwg-id-2', result['fwg-id-2']['id'])
        self.assertEqual('pg-name-2', result['fwg-id-2']['name'])
        self.assertEqual(['acl3'], result['fwg-id-2']['acls'])
        self.ovn_nb_api.db_list_rows.assert_called_once_with('Port_Group')

    def test__get_firewall_groups(self):
        """Test that _get_firewall_groups correctly identifies sync/remove."""
        neutron_fwgs = {
            'fwg-id-1': {'id': 'fwg-id-1', 'name': 'fwg-1', 'ports': []},
            'fwg-id-2': {'id': 'fwg-id-2', 'name': 'fwg-2', 'ports': []},
        }
        ovn_pgs = {
            'fwg-id-2': {'id': 'fwg-id-2', 'name': 'pg-2', 'acls': []},
            'fwg-id-3': {'id': 'fwg-id-3', 'name': 'pg-3', 'acls': []},
        }

        with mock.patch.object(
                self.sync, '_get_fw_port_groups_from_neutron_db',
                return_value=neutron_fwgs), \
             mock.patch.object(
                self.sync, '_get_fw_port_groups_from_ovn_db',
                return_value=ovn_pgs):
            groups_to_sync, groups_to_remove = self.sync._get_firewall_groups(
                self.ctx)

        # fwg-id-1 and fwg-id-2 exist in neutron, so should be synced
        self.assertEqual(2, len(groups_to_sync))
        self.assertIn('fwg-id-1', groups_to_sync)
        self.assertIn('fwg-id-2', groups_to_sync)

        # fwg-id-3 exists only in OVN, so should be removed
        self.assertEqual(1, len(groups_to_remove))
        self.assertIn('fwg-id-3', groups_to_remove)
        self.assertEqual(ovn_pgs['fwg-id-3'], groups_to_remove['fwg-id-3'])

    def test__sync_acls_for_firewall_group(self):
        fw_group = {
            'id': 'fwg-id-1',
            'ingress_firewall_policy_id': 'policy-id-1',
            'egress_firewall_policy_id': 'policy-id-2'
        }
        txn = mock.MagicMock()

        self.sync._sync_acls_for_firewall_group(self.ctx, txn, fw_group)

        self.fwaas_plugin.driver._add_rules_for_firewall_group.\
            assert_called_once_with(self.ctx, txn, 'fwg-id-1')

    def test_sync_firewall_groups_repair_mode(self):
        """Test sync in REPAIR mode syncs and removes groups."""
        self.sync.mode = ovn_const.OVN_DB_SYNC_MODE_REPAIR
        groups_to_sync = {
            'fwg-id-1': {
                'id': 'fwg-id-1',
                'name': 'fwg-1',
                'ports': ['port1', 'port2'],
                'ingress_firewall_policy_id': 'policy-1',
                'egress_firewall_policy_id': None
            },
            'fwg-id-2': {
                'id': 'fwg-id-2',
                'name': 'fwg-2',
                'ports': [],
                'ingress_firewall_policy_id': None,
                'egress_firewall_policy_id': None
            }
        }
        groups_to_remove = {
            'fwg-id-3': {
                'id': 'fwg-id-3',
                'name': 'pg-3',
                'acls': []
            }
        }

        txn_mock = mock.MagicMock()
        txn_context = mock.MagicMock()
        txn_context.__enter__ = mock.Mock(return_value=txn_mock)
        txn_context.__exit__ = mock.Mock(return_value=None)
        self.ovn_nb_api.transaction.return_value = txn_context
        self.ovn_nb_api.get_port_group.return_value = mock.MagicMock()

        with mock.patch.object(
                self.sync, '_get_firewall_groups',
                return_value=(groups_to_sync, groups_to_remove)), \
             mock.patch.object(
                ovn_utils, 'ovn_port_group_name',
                side_effect=lambda x: f'pg-{x}'), \
             mock.patch.object(
                ovn_acl, 'create_pg_for_fwg') as mock_create_pg, \
             mock.patch.object(
                ovn_acl, 'add_default_acls_for_pg') as mock_add_default, \
             mock.patch.object(
                ovn_acl, 'update_ports_for_pg') as mock_update_ports, \
             mock.patch.object(
                self.sync, '_sync_acls_for_firewall_group') as mock_sync_acls:

            self.sync._sync_firewall_groups(self.ctx)

        # Verify port groups are created for groups to sync
        self.assertEqual(2, mock_create_pg.call_count)
        mock_create_pg.assert_has_calls([
            mock.call(self.ovn_nb_api, 'fwg-id-1'),
            mock.call(self.ovn_nb_api, 'fwg-id-2')])

        # Verify default ACLs are added
        self.assertEqual(2, mock_add_default.call_count)
        mock_add_default.assert_has_calls([
            mock.call(self.ovn_nb_api, txn_mock, 'pg-fwg-id-1'),
            mock.call(self.ovn_nb_api, txn_mock, 'pg-fwg-id-2')])

        # Verify ACLs are synced
        self.assertEqual(2, mock_sync_acls.call_count)
        mock_sync_acls.assert_has_calls([
            mock.call(self.ctx, txn_mock, groups_to_sync['fwg-id-1']),
            mock.call(self.ctx, txn_mock, groups_to_sync['fwg-id-2'])
        ])

        # Verify ports are updated
        self.assertEqual(1, mock_update_ports.call_count)
        mock_update_ports.assert_called_once_with(
            self.ovn_nb_api, txn_mock, 'pg-fwg-id-1', ['port1', 'port2'])

        # Verify port group deletion for groups to remove
        self.assertEqual(1, self.ovn_nb_api.get_port_group.call_count)
        self.assertEqual(1, txn_mock.add.call_count)

    def test_sync_firewall_groups_log_mode(self):
        """Test sync in non-REPAIR mode returns early."""
        self.sync.mode = ovn_const.OVN_DB_SYNC_MODE_LOG
        groups_to_sync = {
            'fwg-id-1': {
                'id': 'fwg-id-1',
                'name': 'fwg-1',
                'ports': ['port1', 'port2'],
                'ingress_firewall_policy_id': 'policy-1',
                'egress_firewall_policy_id': None
            },
            'fwg-id-2': {
                'id': 'fwg-id-2',
                'name': 'fwg-2',
                'ports': [],
                'ingress_firewall_policy_id': None,
                'egress_firewall_policy_id': None
            }
        }
        groups_to_remove = {
            'fwg-id-3': {
                'id': 'fwg-id-3',
                'name': 'pg-3',
                'acls': []
            }
        }

        with mock.patch.object(
                self.sync, '_get_firewall_groups',
                return_value=(groups_to_sync, groups_to_remove)), \
             mock.patch.object(
                ovn_acl, 'create_pg_for_fwg') as mock_create_pg, \
             mock.patch.object(
                self.ovn_nb_api, 'transaction') as mock_txn:

            self.sync._sync_firewall_groups(self.ctx)

        # Should not create port groups or transactions
        mock_create_pg.assert_not_called()
        mock_txn.assert_not_called()
