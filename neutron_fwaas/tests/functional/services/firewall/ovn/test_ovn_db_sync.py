# Copyright 2026 Red Hat, Inc.
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
from neutron.common.ovn import utils as neutron_ovn_utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import maintenance
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import \
    ovn_db_sync as neutron_ovn_db_sync
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.tests.functional import base
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    constants as ovn_fw_const
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    ovn_db_sync


class BaseTestOvnNbSync(base.TestOVNFunctionalBase):

    def setUp(self):
        self._mock_has_lock = mock.patch.object(
            maintenance.DBInconsistenciesPeriodics, 'has_lock',
            mock.PropertyMock(return_value=True))
        self.mock_has_lock = self._mock_has_lock.start()
        self._mock_set_lock = mock.patch.object(
            ovsdb_monitor.BaseOvnIdl, 'set_lock')
        self.mock_set_lock = self._mock_set_lock.start()

        cfg.CONF.set_override(
            'service_provider',
            ['FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.'
             'service_drivers.ovn.firewall_l3_driver.OVNFwaasDriver:default'],
            group='service_providers')
        super().setUp(
            maintenance_worker=True,
            service_plugins={
                fwaas_constants.FIREWALL_V2: (
                    'neutron_fwaas.services.firewall.'
                    'fwaas_plugin_v2.FirewallPluginV2')})
        self.context.project_id = self._project_id
        self.context.tenant_id = self._project_id
        self.fwaas_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)

    def _create_basic_resources(self, number_of_networks):
        """This method creates the basic resources for the tests.
        """

        name_prefix = 'test-resource'

        router = self.l3_plugin.create_router(
            self.context,
            {'router': {
                'name': f'{name_prefix}-router', 'admin_state_up': True,
                'tenant_id': self._project_id}})

        for i in range(number_of_networks):
            res = self._create_network(
                self.fmt, f'{name_prefix}-network-{i}', True)
            network = self.deserialize(self.fmt, res)
            res = self._create_subnet(self.fmt, network['network']['id'],
                                      f'10.0.{i}.0/24')
            subnet = self.deserialize(self.fmt, res)

            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})

        res = self._list_ports(self.fmt, device_id=router['id'])
        return [port['id'] for port in
                self.deserialize(self.fmt, res)['ports']]

    def _get_ovn_port_groups(self):
        plugin_nb_ovn = self.mech_driver.nb_ovn
        port_groups = {}
        for pg in plugin_nb_ovn.db_list_rows('Port_Group').execute() or []:
            fwaas_group_id = pg.external_ids.get(
                ovn_fw_const.OVN_FWG_EXT_ID_KEY)
            if not fwaas_group_id:
                continue
            port_groups[fwaas_group_id] = {
                'name': pg.name,
                'ports': pg.ports,
                'acls': [],
            }
            for acl in plugin_nb_ovn.pg_acl_list(pg.name).execute() or []:
                port_groups[fwaas_group_id]['acls'].append({
                    'match': acl.match,
                    'action': acl.action,
                    'priority': acl.priority,
                    'direction': acl.direction,
                })
        return port_groups

    def _create_resources(self):
        for i in range(2):
            # There will be router with 2 subnets from 2 different networks
            # plugged in
            router_ports = self._create_basic_resources(number_of_networks=2)

        firewall_ingress_rule = self.fwaas_plugin.create_firewall_rule(
            self.context,
            {'firewall_rule': {
                'name': 'ingress-ssh-rule',
                'protocol': 'tcp',
                'ip_version': 4,
                'source_ip_address': '',
                'source_port': '',
                'destination_ip_address': '10.0.0.2',
                'destination_port': '22',
                'action': 'allow',
                'enabled': True,
                'project_id': self._project_id,
                'tenant_id': self._project_id,
                'description': 'test firewall SSH ingress rule',
                'shared': False,
            }})
        firewall_egress_rule = self.fwaas_plugin.create_firewall_rule(
            self.context,
            {'firewall_rule': {
                'name': 'egress-icmp-rule',
                'protocol': 'icmp',
                'ip_version': 4,
                'source_ip_address': '',
                'source_port': '',
                'destination_ip_address': '',
                'destination_port': '',
                'action': 'deny',
                'enabled': True,
                'project_id': self._project_id,
                'tenant_id': self._project_id,
                'description': 'test firewall ICMP egress rule',
                'shared': False,
            }})

        firewall_ingress_policy = self.fwaas_plugin.create_firewall_policy(
            self.context,
            {'firewall_policy': {
                'tenant_id': self._project_id,
                'project_id': self._project_id,
                'name': 'ingress-test-policy',
                'description': 'test firewall ingresspolicy',
                'shared': False,
                'audited': False,
                'firewall_rules': [firewall_ingress_rule['id']],
            }})
        firewall_egress_policy = self.fwaas_plugin.create_firewall_policy(
            self.context,
            {'firewall_policy': {
                'tenant_id': self._project_id,
                'project_id': self._project_id,
                'name': 'ingress-test-policy',
                'description': 'test firewall egresspolicy',
                'shared': False,
                'audited': False,
                'firewall_rules': [firewall_egress_rule['id']],
            }})

        self.fwaas_plugin.create_firewall_group(
            self.context,
            {'firewall_group': {
                'tenant_id': self._project_id,
                'project_id': self._project_id,
                'name': 'test-group',
                'description': 'test firewall group',
                'shared': False,
                'admin_state_up': True,
                'ingress_firewall_policy_id': firewall_ingress_policy['id'],
                'egress_firewall_policy_id': firewall_egress_policy['id'],
                'ports': router_ports,
            }})

        # Now, once all is configured, get the Port Groups from OVN DB - that
        # will be used to validate ovn_db_sync if it can restore the same
        # state later
        self.expected_ovn_port_groups = self._get_ovn_port_groups()

    def _assert_acl_lists_equal(self, list1, list2):
        self.assertEqual(len(list1), len(list2))
        for acl in list1:
            self.assertIn(acl, list2)

    def _validate_resources(self, should_match=True):
        current_ovn_port_groups = self._get_ovn_port_groups()
        if should_match:
            self.assertEqual(
                sorted(self.expected_ovn_port_groups.keys()),
                sorted(current_ovn_port_groups.keys())
            )
            for fwg_id in self.expected_ovn_port_groups.keys():
                self._assert_acl_lists_equal(
                    current_ovn_port_groups[fwg_id]['acls'],
                    self.expected_ovn_port_groups[fwg_id]['acls']
                )
                ports_in_current_ovn_port_groups = sorted([
                    p.external_ids.get(ovn_const.OVN_DEVID_EXT_ID_KEY)
                    for p in current_ovn_port_groups[fwg_id]['ports']])
                ports_in_expected_ovn_port_groups = sorted([
                    p.external_ids.get(ovn_const.OVN_DEVID_EXT_ID_KEY)
                    for p in self.expected_ovn_port_groups[fwg_id]['ports']])
                self.assertEqual(
                    ports_in_current_ovn_port_groups,
                    ports_in_expected_ovn_port_groups
                )
                self.assertEqual(
                    current_ovn_port_groups[fwg_id]['name'],
                    self.expected_ovn_port_groups[fwg_id]['name']
                )
        else:
            self.assertNotEqual(
                current_ovn_port_groups, self.expected_ovn_port_groups)

    def _test_ovn_nb_sync_helper(self, resources_modifier=None,
                                 restart_ovsdb_processes=False):
        self._create_resources()
        self._validate_resources()
        if resources_modifier:
            resources_modifier()
        if restart_ovsdb_processes:
            self.restart()
            # After deleting the OVS DB sync of the neutron resources, such as
            # networks, ports and routers is also needed
            self._sync_neutron_resources(ovn_const.OVN_DB_SYNC_MODE_REPAIR)
        if resources_modifier or restart_ovsdb_processes:
            self._validate_resources(should_match=False)
        self._sync_resources()
        self._validate_resources(should_match=self.should_match_after_sync)

    def _sync_resources(self):
        nb_synchronizer = ovn_db_sync.OvnNbDbSync(
            self.plugin, self.mech_driver, self.mode)
        self.addCleanup(nb_synchronizer.stop)
        nb_synchronizer.do_sync()

    def _sync_neutron_resources(self, mode):
        nb_synchronizer = neutron_ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver, mode)
        self.addCleanup(nb_synchronizer.stop)
        nb_synchronizer.do_sync()

    def _test_ovn_db_sync_port_group_deleted(self, restart_ovsdb_processes):

        def delete_port_group():
            plugin_nb_ovn = self.mech_driver.nb_ovn
            pg_to_delete = list(self.expected_ovn_port_groups.keys())[0]
            plugin_nb_ovn.pg_del(
                name=neutron_ovn_utils.ovn_port_group_name(pg_to_delete),
                if_exists=True
            ).execute(check_error=True)

        self._test_ovn_nb_sync_helper(
            resources_modifier=delete_port_group,
            restart_ovsdb_processes=restart_ovsdb_processes)

    def _test_ovn_nb_sync_port_group_modified(self, restart_ovsdb_processes):

        def modify_port_group():
            plugin_nb_ovn = self.mech_driver.nb_ovn
            pg_to_modify = list(self.expected_ovn_port_groups.keys())[0]
            pg_name = neutron_ovn_utils.ovn_port_group_name(pg_to_modify)
            acl = self.expected_ovn_port_groups[pg_to_modify]['acls'][0]
            port = self.expected_ovn_port_groups[pg_to_modify]['ports'][0]

            with plugin_nb_ovn.transaction(check_error=True) as txn:
                txn.add(plugin_nb_ovn.pg_acl_del(
                    pg_name, acl['direction'], acl['priority'], acl['match']))
                txn.add(plugin_nb_ovn.pg_del_ports(
                    neutron_ovn_utils.ovn_port_group_name(pg_to_modify),
                    port, if_exists=True))

        self._test_ovn_nb_sync_helper(
            resources_modifier=modify_port_group,
            restart_ovsdb_processes=restart_ovsdb_processes)


class TestOvnNbSyncRepair(BaseTestOvnNbSync):

    mode = ovn_const.OVN_DB_SYNC_MODE_REPAIR
    should_match_after_sync = True

    def get_ovsdb_server_protocol(self):
        return 'unix'

    def test_ovn_db_sync_port_group_deleted_no_restart_ovsdb(self):
        self._test_ovn_db_sync_port_group_deleted(
            restart_ovsdb_processes=False)

    def test_ovn_db_sync_port_group_deleted_restart_ovsdb(self):
        self._test_ovn_db_sync_port_group_deleted(restart_ovsdb_processes=True)

    def test_ovn_db_sync_port_group_modified_no_restart_ovsdb(self):
        self._test_ovn_nb_sync_port_group_modified(
            restart_ovsdb_processes=False)

    def test_ovn_db_sync_port_group_modified_restart_ovsdb(self):
        self._test_ovn_nb_sync_port_group_modified(
            restart_ovsdb_processes=True)


class TestOvnNbSyncLog(BaseTestOvnNbSync):

    mode = ovn_const.OVN_DB_SYNC_MODE_LOG
    should_match_after_sync = False

    def get_ovsdb_server_protocol(self):
        return 'unix'

    def test_ovn_db_sync_port_group_deleted_no_restart_ovsdb(self):
        self._test_ovn_db_sync_port_group_deleted(
            restart_ovsdb_processes=False)

    def test_ovn_db_sync_port_group_deleted_restart_ovsdb(self):
        self._test_ovn_db_sync_port_group_deleted(restart_ovsdb_processes=True)

    def test_ovn_db_sync_port_group_modified_no_restart_ovsdb(self):
        self._test_ovn_nb_sync_port_group_modified(
            restart_ovsdb_processes=False)

    def test_ovn_db_sync_port_group_modified_restart_ovsdb(self):
        self._test_ovn_nb_sync_port_group_modified(
            restart_ovsdb_processes=True)
