# Copyright (c) 2016
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

import mock
from neutron.agent.l3 import l3_agent_extension_api as l3_agent_api
from neutron.agent.l3 import router_info
from neutron.agent.linux import ip_lib
from neutron.conf.agent.l3 import config as l3_config
from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.firewall.agents import firewall_agent_api
from neutron_fwaas.services.firewall.agents.l3reference \
    import firewall_l3_agent_v2
from neutron_fwaas.services.firewall.drivers.linux \
    import iptables_fwaas_v2
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.services.firewall.agents \
    import test_firewall_agent_api


class FWaasHelper(object):
    def __init__(self):
        pass


class FWaasAgent(firewall_l3_agent_v2.L3WithFWaaS, FWaasHelper):
    neutron_service_plugins = []

    def add_router(self, context, data):
        pass

    def delete_router(self, context, data):
        pass

    def update_router(self, context, data):
        pass


def _setup_test_agent_class(service_plugins):
    class FWaasTestAgent(firewall_l3_agent_v2.L3WithFWaaS,
                         FWaasHelper):
        neutron_service_plugins = service_plugins

        def __init__(self, conf):
            self.event_observers = mock.Mock()
            self.conf = conf
            firewall_agent_api._check_required_agent_extension = mock.Mock()
            super(FWaasTestAgent, self).__init__(conf)

        def delete_router(self, context, data):
            pass

        def update_router(self, context, data):
            pass

    return FWaasTestAgent


class TestFWaaSL3AgentExtension(base.BaseTestCase):
    def setUp(self):
        super(TestFWaaSL3AgentExtension, self).setUp()

        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(firewall_agent_api.FWaaSOpts, 'fwaas')
        self.conf.host = 'myhost'
        self.api = FWaasAgent(self.conf)
        self.api.agent_api = mock.Mock()
        self.api.fwaas_driver = test_firewall_agent_api.NoopFwaasDriverV2()
        self.adminContext = context.get_admin_context()
        self.context = mock.sentinel.context
        self.router_id = uuidutils.generate_uuid()
        self.agent_conf = mock.Mock()
        self.ri_kwargs = {'router': {'id': self.router_id,
                                     'project_id': uuidutils.generate_uuid()},
                          'agent_conf': self.agent_conf,
                          'interface_driver': mock.ANY,
                          'use_ipv6': mock.ANY
                          }

    def test_fw_config_match(self):
        test_agent_class = _setup_test_agent_class([fwaas_constants.FIREWALL])
        cfg.CONF.set_override('enabled', True, 'fwaas')
        with mock.patch('oslo_utils.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_fw_config_mismatch_plugin_enabled_agent_disabled(self):
        self.skipTest('this is broken')
        test_agent_class = _setup_test_agent_class([fwaas_constants.FIREWALL])
        cfg.CONF.set_override('enabled', False, 'fwaas')
        self.assertRaises(SystemExit, test_agent_class, cfg.CONF)

    def test_fw_plugin_list_unavailable(self):
        test_agent_class = _setup_test_agent_class(None)
        cfg.CONF.set_override('enabled', False, 'fwaas')
        with mock.patch('oslo_utils.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_create_firewall_group(self):
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': True,
                          'add-port-ids': [1, 2]}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_firewall_group_ports'
                               ) as mock_get_firewall_group_ports, \
                mock.patch.object(self.api, '_get_in_ns_ports'
                                  ) as mock_get_in_ns_ports, \
                mock.patch.object(self.api.fwaas_driver,
                                  'create_firewall_group'
                                  ) as mock_driver_create_firewall_group, \
                mock.patch.object(self.api.fwplugin_rpc,
                                  'set_firewall_group_status'
                                  ) as mock_set_firewall_group_status:

            mock_driver_create_firewall_group.return_value = True

            self.api.create_firewall_group(self.context, firewall_group,
                    host='host')

            mock_get_firewall_group_ports.assert_called_once_with(self.context,
                    firewall_group)
            mock_get_in_ns_ports.assert_called
            assert mock_get_in_ns_ports
            mock_set_firewall_group_status.assert_called_once_with(
                    self.context, firewall_group['id'], 'ACTIVE')

    def test_update_firewall_group_with_ports_added_and_deleted(self):
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': True,
                          'ports': [1, 2, 3, 4],
                          'add-port-ids': [1, 2],
                          'del-port-ids': [3, 4],
                          'router_ids': [],
                    'last-port': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_firewall_group_ports'
                               ) as mock_get_firewall_group_ports, \
                mock.patch.object(self.api, '_get_in_ns_ports'
                                  ) as mock_get_in_ns_ports, \
                mock.patch.object(self.api.fwaas_driver,
                                  'update_firewall_group'
                                  ) as mock_driver_update_firewall_group, \
                mock.patch.object(self.api.fwaas_driver,
                                  'delete_firewall_group'
                                  ) as mock_driver_delete_firewall_group, \
                mock.patch.object(self.api.fwplugin_rpc,
                                  'set_firewall_group_status'
                                  ) as mock_set_firewall_group_status:

            mock_driver_delete_firewall_group.return_value = True
            mock_driver_update_firewall_group.return_value = True

            calls = [mock.call(self.context, firewall_group, to_delete=True,
                               require_new_plugin=True),
                     mock.call(self.context, firewall_group)]

            self.api.update_firewall_group(self.context, firewall_group,
                    host='host')

            self.assertEqual(mock_get_firewall_group_ports.call_args_list,
                    calls)
            mock_get_in_ns_ports.assert_called
            mock_set_firewall_group_status.assert_called_once_with(
                    self.context, firewall_group['id'], 'ACTIVE')

    def test_update_firewall_group_with_ports_added_and_admin_state_down(self):
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': False,
                          'ports': [1, 2],
                          'add-port-ids': [1, 2],
                          'del-port-ids': [],
                          'router_ids': [],
                          'last-port': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_firewall_group_ports'
                               ) as mock_get_firewall_group_ports, \
                mock.patch.object(self.api, '_get_in_ns_ports'
                                  ) as mock_get_in_ns_ports, \
                mock.patch.object(self.api.fwaas_driver,
                                  'update_firewall_group'
                                  ) as mock_driver_update_firewall_group, \
                mock.patch.object(self.api.fwplugin_rpc,
                                  'set_firewall_group_status'
                                  ) as mock_set_firewall_group_status:

            mock_driver_update_firewall_group.return_value = True

            self.api.update_firewall_group(self.context, firewall_group,
                    host='host')

            mock_get_firewall_group_ports.assert_called
            mock_get_in_ns_ports.assert_called
            mock_set_firewall_group_status.assert_called_once_with(
                   self.context, firewall_group['id'], 'DOWN')

    def test_update_firewall_group_with_all_ports_deleted(self):
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': True,
                          'ports': [3, 4],
                          'add-port-ids': [],
                          'del-port-ids': [3, 4],
                          'last-port': True}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_firewall_group_ports'
                               ) as mock_get_firewall_group_ports, \
                mock.patch.object(self.api, '_get_in_ns_ports'
                                  ) as mock_get_in_ns_ports, \
                mock.patch.object(self.api.fwaas_driver,
                                  'delete_firewall_group'
                                  ) as mock_driver_delete_firewall_group, \
                mock.patch.object(self.api.fwplugin_rpc,
                                  'set_firewall_group_status'
                                  ) as mock_set_firewall_group_status:

            mock_driver_delete_firewall_group.return_value = True

            self.api.update_firewall_group(self.context, firewall_group,
                    host='host')
            calls = [
                mock.call._get_firewall_group_ports(
                    self.context, firewall_group, require_new_plugin=True,
                    to_delete=True),
                mock.call._get_firewall_group_ports(
                    self.context, firewall_group)
            ]
            mock_get_firewall_group_ports.assert_has_calls(calls)
            mock_get_in_ns_ports.assert_called
            mock_set_firewall_group_status.assert_called_once_with(
                    self.context, firewall_group['id'], 'INACTIVE')

    def test_update_firewall_group_with_no_ports_added_or_deleted(self):
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': True,
                          'ports': [],
                          'add-port-ids': [],
                          'del-port-ids': [],
                          'router_ids': []}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api.fwaas_driver, 'update_firewall_group'
                               ) as mock_driver_update_firewall_group, \
                mock.patch.object(self.api.fwplugin_rpc,
                                  'set_firewall_group_status'
                                  ) as mock_set_firewall_group_status:

            mock_driver_update_firewall_group.return_value = True

            self.api.update_firewall_group(self.context, firewall_group,
                    host='host')
            mock_set_firewall_group_status.assert_called_once_with(
                    self.context, firewall_group['id'], 'INACTIVE')

    def test_update_firewall_group_with_only_ports_added(self):
        # This test is for bug/1634114
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': True,
                          'ports': [1, 2],
                          'add-port-ids': ['1', '2'],
                          'del-port-ids': [],
                          'last-port': False
                          }
        self.api.update_firewall_group(self.context, firewall_group,
                                       host='host')

    def test_delete_firewall_group(self):
        firewall_group = {'id': 0, 'project_id': 1,
                          'admin_state_up': True,
                          'ports': [3, 4],
                          'add-port-ids': [],
                          'del-port-ids': [3, 4],
                          'last-port': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_firewall_group_ports'
                               ) as mock_get_firewall_group_ports, \
                mock.patch.object(self.api, '_get_in_ns_ports'
                                  ) as mock_get_in_ns_ports, \
                mock.patch.object(self.api.fwaas_driver,
                                  'delete_firewall_group'
                                  ) as mock_driver_delete_firewall_group, \
                mock.patch.object(self.api.fwplugin_rpc,
                                  'firewall_group_deleted'
                                  ) as mock_firewall_group_deleted:

            mock_driver_delete_firewall_group.return_value = True

            self.api.delete_firewall_group(self.context, firewall_group,
                    host='host')

            mock_get_firewall_group_ports.assert_called_once_with(
                    self.context, firewall_group, to_delete=True)
            mock_get_in_ns_ports.assert_called
            mock_firewall_group_deleted.assert_called_once_with(self.context,
                    firewall_group['id'])

    def _prepare_router_data(self):
        return router_info.RouterInfo(self.api,
                                      self.router_id,
                                      **self.ri_kwargs)

    def test_get_in_ns_ports_for_non_ns_fw(self):
        port_ids = [1, 2]
        ports = [{'id': pid} for pid in port_ids]
        ri = self._prepare_router_data()
        ri.internal_ports = ports
        router_info = {ri.router_id: ri}
        api_object = l3_agent_api.L3AgentExtensionAPI(router_info)
        self.api.consume_api(api_object)
        fw_port_ids = port_ids

        with mock.patch.object(ip_lib,
                               'list_network_namespaces') as mock_list_netns:
            mock_list_netns.return_value = []
            ports_for_fw_list = self.api._get_in_ns_ports(fw_port_ids)

        mock_list_netns.assert_called_with()
        self.assertFalse(ports_for_fw_list)

    def test_get_in_ns_ports_for_fw(self):
        port_ids = [1, 2]
        ports = [{'id': pid} for pid in port_ids]
        ri = self._prepare_router_data()
        ri.internal_ports = ports
        router_info = {}
        router_info[ri.router_id] = ri
        api_object = l3_agent_api.L3AgentExtensionAPI(router_info)
        self.api.consume_api(api_object)
        fw_port_ids = port_ids
        ports_for_fw_expected = [(ri, port_ids)]

        with mock.patch.object(ip_lib,
                               'list_network_namespaces') as mock_list_netns:
            mock_list_netns.return_value = [ri.ns_name]
            ports_for_fw_actual = self.api._get_in_ns_ports(fw_port_ids)
            self.assertEqual(ports_for_fw_expected, ports_for_fw_actual)

    def test_add_router_for_check_input(self):
        fw_agent = _setup_test_agent_class([fwaas_constants.FIREWALL])
        cfg.CONF.set_override('enabled', True, 'fwaas')
        updated_router = {
            '_interfaces': [{
                'device_owner': 'network: router_interface',
                'id': '1',
                'tenant_id': 'demo_tenant_id',
            }],
            'tenant_id': 'demo_tenant_id',
            'id': '0b109a4e-d228-479d-ad43-08bf3245adbb',
            'name': 'demo_router'
        }
        fwg = {
            'status': 'ACTIVE',
            'admin_state_up': True,
            'tenant_id': 'demo_tenant_id',
            'ports': [1],
            'del-port-ids': [],
            'add-port-ids': ['1'],
            'id': '2932b3d9-3a7b-48a1-a16c-bf9f7b2751a5'
        }
        with mock.patch('oslo_utils.importutils.import_object'):
            agent = fw_agent(cfg.CONF)
            agent.agent_api = mock.Mock()
            agent.fwplugin_rpc = mock.Mock()
            agent.conf.agent_mode = mock.Mock()
            agent.fwaas_driver = iptables_fwaas_v2.IptablesFwaasDriver()
            with mock.patch.object(agent.fwplugin_rpc,
                                   'get_firewall_groups_for_project'
                                   ) as mock_get_firewall_groups_for_project, \
                    mock.patch.object(agent.agent_api,
                                      'get_router_hosting_port'
                                      ) as mock_get_router_hosting_port, \
                    mock.patch.object(agent.fwaas_driver,
                                      '_get_ipt_mgrs_with_if_prefix'
                                      ) as mock_get_ipt_mgrs_with_if_prefix:
                mock_get_firewall_groups_for_project.return_value = [fwg]
                mock_get_router_hosting_port.return_value = mock.Mock()
                agent.add_router(self.context, updated_router)
                mock_get_ipt_mgrs_with_if_prefix.assert_any_call(
                    agent.conf.agent_mode, mock.ANY)

    @mock.patch('oslo_utils.importutils.import_object')
    def test_add_router_with_several_ports(self, mock_import_object):
        fw_agent = _setup_test_agent_class([fwaas_constants.FIREWALL])
        cfg.CONF.set_override('enabled', True, 'fwaas')
        updated_router = {
            '_interfaces': [
                {'device_owner': 'network: router_interface',
                 'id': '1',
                 'tenant_id': 'demo_tenant_id'},
                {'device_owner': 'network: router_interface',
                 'id': '2',
                 'tenant_id': 'demo_tenant_id'},
                {'device_owner': 'network: router_interface',
                 'id': '3',
                 'tenant_id': 'demo_tenant_id'}],
            'tenant_id': 'demo_tenant_id',
            'id': '0b109a4e-d228-479d-ad43-08bf3245adbb',
            'name': 'demo_router'
        }
        fwg1 = {
            'status': 'ACTIVE',
            'admin_state_up': True,
            'tenant_id': 'demo_tenant_id',
            'del-port-ids': [],
            'add-port-ids': ['1', '3'],
            'id': '2932b3d9-3a7b-48a1-a16c-bf9f7b2751a5'
        }
        fwg2 = {
            'status': 'ACTIVE',
            'admin_state_up': True,
            'tenant_id': 'demo_tenant_id',
            'del-port-ids': [],
            'add-port-ids': ['2', '3'],
            'id': '2932b3d9-3a7b-48a1-a16c-bf9f7b2751a5'
        }
        agent = fw_agent(cfg.CONF)
        agent.agent_api = mock.Mock()
        agent.fwplugin_rpc = mock.Mock()
        agent.conf.agent_mode = mock.Mock()
        agent.fwaas_driver = iptables_fwaas_v2.IptablesFwaasDriver()

        patch_project = mock.patch.object(
            agent.fwplugin_rpc, 'get_firewall_groups_for_project')
        patch_invoke = mock.patch.object(
            agent, '_invoke_driver_for_sync_from_plugin')

        with patch_project as mock_get_firewall_groups, \
                patch_invoke as mock_invoke_driver:
            mock_get_firewall_groups.return_value = [fwg1, fwg2]
            agent.add_router(self.context, updated_router)

            # Check that mock_invoke_driver was called exactly twice with
            # correct arguments.
            self.assertEqual([
                mock.call(mock.ANY, {'1', '3'}, fwg1),
                mock.call(mock.ANY, {'2'}, fwg2),
            ], mock_invoke_driver.call_args_list)

    #TODO(Margaret) Add test for add_router method.
