# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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
from neutron.conf import common as base_config
from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.firewall.service_drivers.agents \
    import firewall_agent_api
from neutron_fwaas.services.firewall.service_drivers.agents.l3reference \
    import firewall_l3_agent
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.services.firewall.service_drivers.agents \
    import test_firewall_agent_api


class FWaasHelper(object):
    def __init__(self, host):
        pass


class FWaasAgent(firewall_l3_agent.FWaaSL3AgentExtension, FWaasHelper):
    neutron_service_plugins = []


def _setup_test_agent_class(service_plugins):
    class FWaasTestAgent(firewall_l3_agent.FWaaSL3AgentExtension,
                         FWaasHelper):
        neutron_service_plugins = service_plugins

        def __init__(self, conf):
            self.event_observers = mock.Mock()
            self.conf = conf
            super(FWaasTestAgent, self).__init__("myhost", conf)

    return FWaasTestAgent


class TestFwaasL3AgentRpcCallback(base.BaseTestCase):
    def setUp(self):
        super(TestFwaasL3AgentRpcCallback, self).setUp()

        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(firewall_agent_api.FWaaSOpts, 'fwaas')
        self.api = FWaasAgent(host=None, conf=self.conf)
        self.api.fwaas_driver = test_firewall_agent_api.NoopFwaasDriver()
        self.adminContext = context.get_admin_context()
        self.router_id = uuidutils.generate_uuid()
        self.agent_conf = mock.Mock()
        # For 'tenant_id' and 'project_id' keys
        project_id = uuidutils.generate_uuid()
        self.ri_kwargs = {'router': {'id': self.router_id,
                                     'tenant_id': project_id,
                                     'project_id': project_id},
                          'agent_conf': self.agent_conf,
                          'interface_driver': mock.ANY,
                          'use_ipv6': mock.ANY,
                          }

    def test_fw_config_match(self):
        test_agent_class = _setup_test_agent_class([fwaas_constants.FIREWALL])
        cfg.CONF.set_override('enabled', True, 'fwaas')
        with mock.patch('oslo_utils.importutils.import_object'):
            test_agent_class(cfg.CONF)

    @testtools.skip('needs to be refactored for fwaas v2')
    def test_fw_config_mismatch_plugin_enabled_agent_disabled(self):
        test_agent_class = _setup_test_agent_class([fwaas_constants.FIREWALL])
        cfg.CONF.set_override('enabled', False, 'fwaas')
        self.assertRaises(SystemExit, test_agent_class, cfg.CONF)

    def test_fw_plugin_list_unavailable(self):
        test_agent_class = _setup_test_agent_class(None)
        cfg.CONF.set_override('enabled', False, 'fwaas')
        with mock.patch('oslo_utils.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_create_firewall(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [1, 2]}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.fwaas_driver, 'create_firewall'
                                  ) as mock_driver_create_firewall, \
                mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'
                                  ) as mock_set_firewall_status:
            mock_driver_create_firewall.return_value = True
            self.api.create_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_firewall['add-router-ids'], fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'ACTIVE')

    def test_update_firewall_with_routers_added_and_deleted(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [1, 2],
                         'del-router-ids': [3, 4],
                         'router_ids': [],
                         'last-router': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.fwaas_driver, 'update_firewall'
                                  ) as mock_driver_delete_firewall, \
                mock.patch.object(self.api.fwaas_driver, 'delete_firewall'
                                  ) as mock_driver_update_firewall, \
                mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'
                                  ) as mock_set_firewall_status:

            mock_driver_delete_firewall.return_value = True
            mock_driver_update_firewall.return_value = True

            calls = [mock.call(fake_firewall['del-router-ids'],
                      fake_firewall['tenant_id']),
                     mock.call(fake_firewall['add-router-ids'],
                      fake_firewall['tenant_id'])]

            self.api.update_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            self.assertEqual(
                mock_get_router_info_list_for_tenant.call_args_list,
                calls)

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'ACTIVE')

    def test_update_firewall_with_routers_added_and_admin_state_down(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': False,
                         'add-router-ids': [1, 2],
                         'del-router-ids': [],
                         'router_ids': [],
                         'last-router': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.fwaas_driver, 'update_firewall'
                                  ) as mock_driver_update_firewall, \
                mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'
                                  ) as mock_set_firewall_status:

            mock_driver_update_firewall.return_value = True

            self.api.update_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_firewall['add-router-ids'], fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'DOWN')

    def test_update_firewall_with_all_routers_deleted(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [3, 4],
                         'last-router': True}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.fwaas_driver, 'delete_firewall'
                                  ) as mock_driver_delete_firewall, \
                mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'
                                  ) as mock_set_firewall_status:

            mock_driver_delete_firewall.return_value = True

            self.api.update_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_firewall['del-router-ids'], fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'INACTIVE')

    def test_update_firewall_with_rtrs_and_no_rtrs_added_nor_deleted(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [],
                         'router_ids': [1, 2]}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api.fwaas_driver, 'update_firewall'
                               ) as mock_driver_update_firewall, \
                mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                                  ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'
                                  ) as mock_set_firewall_status:

            mock_driver_update_firewall.return_value = True

            self.api.update_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_firewall['router_ids'], fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'ACTIVE')

    def test_update_firewall_with_no_rtrs_and_no_rtrs_added_nor_deleted(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [],
                         'router_ids': []}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api.fwaas_driver, 'update_firewall'
                               ) as mock_driver_update_firewall, \
                mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'
                                  ) as mock_set_firewall_status:

            mock_driver_update_firewall.return_value = True

            self.api.update_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'INACTIVE')

    def test_delete_firewall(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [3, 4],
                         'last-router': True}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.fwaas_driver, 'delete_firewall'
                                  ) as mock_driver_delete_firewall, \
                mock.patch.object(self.api.fwplugin_rpc, 'firewall_deleted'
                                  ) as mock_firewall_deleted:

            mock_driver_delete_firewall.return_value = True
            self.api.delete_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_firewall['del-router-ids'], fake_firewall['tenant_id'])

            mock_firewall_deleted.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'])

    def _prepare_router_data(self):
        return router_info.RouterInfo(self.api,
                                      self.router_id,
                                      **self.ri_kwargs)

    def test_get_router_info_list_for_tenant(self):
        ri = self._prepare_router_data()
        router_info = {ri.router_id: ri}
        self.api.router_info = router_info

        api_object = l3_agent_api.L3AgentExtensionAPI(router_info)
        self.api.consume_api(api_object)

        routers = [ri.router]
        router_ids = [router['id'] for router in routers]

        with mock.patch.object(ip_lib,
                               'list_network_namespaces') as mock_list_netns:
            mock_list_netns.return_value = []
            router_info_list = self.api._get_router_info_list_for_tenant(
                router_ids,
                ri.router['tenant_id'])
        mock_list_netns.assert_called_once_with()
        self.assertFalse(router_info_list)

    def _get_router_info_list_router_without_router_info_helper(self,
                                                                rtr_with_ri):
        # ri.router with associated router_info (ri)
        # rtr2 has no router_info

        ri = self._prepare_router_data()
        rtr2 = {'id': uuidutils.generate_uuid(),
                'tenant_id': ri.router['tenant_id']}

        routers = [rtr2]
        router_info = {}
        ri_expected = []

        if rtr_with_ri:
            router_info[ri.router_id] = ri
            routers.append(ri.router)
            ri_expected.append(ri)

        self.api.router_info = router_info
        router_ids = [router['id'] for router in routers]

        with mock.patch.object(ip_lib,
                               'list_network_namespaces') as mock_list_netns:
            mock_list_netns.return_value = [ri.ns_name]
            api_object = l3_agent_api.L3AgentExtensionAPI(router_info)
            self.api.consume_api(api_object)
            router_info_list = self.api._get_router_info_list_for_tenant(
                router_ids,
                ri.router['tenant_id'])
            self.assertEqual(ri_expected, router_info_list)

    def test_get_router_info_list_router_without_router_info(self):
        self._get_router_info_list_router_without_router_info_helper(
            rtr_with_ri=False)

    def test_get_router_info_list_two_routers_one_without_router_info(self):
        self._get_router_info_list_router_without_router_info_helper(
            rtr_with_ri=True)
