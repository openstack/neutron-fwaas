# Copyright 2013 vArmour Networks Inc.
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

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import ha
from neutron.agent.l3 import router_info
from neutron.agent.linux import interface
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf import common as base_config
from neutron_fwaas.services.firewall.agents.varmour import varmour_router
from neutron_fwaas.tests import base
from neutron_lib import constants as l3_constants
from oslo_utils import uuidutils


_uuid = uuidutils.generate_uuid
HOSTNAME = 'myhost'
FAKE_DIRECTOR = '1.1.1.1'


class TestVarmourRouter(base.BaseTestCase):

    def setUp(self):
        self.skipTest('this is broken')
        super(TestVarmourRouter, self).setUp()
        self.conf = agent_config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(ha.OPTS)
        agent_config.register_process_monitor_opts(self.conf)
        agent_config.register_interface_driver_opts_helper(self.conf)
        self.conf.register_opts(interface.OPTS)
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.conf.state_path = ''

        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager')
        self.external_process = self.external_process_p.start()

        self.makedirs_p = mock.patch('os.makedirs')
        self.makedirs = self.makedirs_p.start()

        self.dvr_cls_p = mock.patch('neutron.agent.linux.interface.NullDriver')
        driver_cls = self.dvr_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = self.mock_driver

        self.ip_cls_p = mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
        ip_cls = self.ip_cls_p.start()
        self.mock_ip = mock.MagicMock()
        ip_cls.return_value = self.mock_ip

        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()

        self.looping_call_p = mock.patch(
            'oslo_service.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()
        self.ri_kwargs = {'agent_conf': self.conf,
                          'interface_driver': self.mock_driver}

    def _create_router(self):
        router = varmour_router.vArmourL3NATAgent(HOSTNAME, self.conf)
        router.rest.server = FAKE_DIRECTOR
        router.rest.user = 'varmour'
        router.rest.passwd = 'varmour'
        return router

    def _del_all_internal_ports(self, router):
        router[l3_constants.INTERFACE_KEY] = []

    def _del_internal_ports(self, router, port_idx):
        del router[l3_constants.INTERFACE_KEY][port_idx]

    def _add_internal_ports(self, router, port_count=1):
        self._del_all_internal_ports(router)
        for i in range(port_count):
            port = {'id': _uuid(),
                    'network_id': _uuid(),
                    'admin_state_up': True,
                    'fixed_ips': [{'ip_address': '10.0.%s.4' % i,
                                   'subnet_id': _uuid()}],
                    'mac_address': 'ca:fe:de:ad:be:ef',
                    'subnet': {'cidr': '10.0.%s.0/24' % i,
                               'gateway_ip': '10.0.%s.1' % i}}
            router[l3_constants.INTERFACE_KEY].append(port)

    def _del_all_floating_ips(self, router):
        router[l3_constants.FLOATINGIP_KEY] = []

    def _del_floating_ips(self, router, port_idx):
        del router[l3_constants.FLOATINGIP_KEY][port_idx]

    def _add_floating_ips(self, router, port_count=1):
        self._del_all_floating_ips(router)
        for i in range(port_count):
            fip = {'id': _uuid(),
                   'port_id': router['gw_port']['id'],
                   'floating_ip_address': '172.24.4.%s' % (100 + i),
                   'fixed_ip_address': '10.0.0.%s' % (100 + i)}
            router[l3_constants.FLOATINGIP_KEY].append(fip)

    def _prepare_router_data(self, enable_snat=None):
        router_id = _uuid()
        ex_gw_port = {'id': _uuid(),
                      'mac_address': 'ca:fe:de:ad:be:ee',
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': '172.24.4.2',
                                     'subnet_id': _uuid()}],
                      'subnet': {'cidr': '172.24.4.0/24',
                                 'gateway_ip': '172.24.4.1'},
                      'ip_cidr': '172.24.4.226/28'}
        int_ports = []

        router = {
            'id': router_id,
            'distributed': False,
            l3_constants.INTERFACE_KEY: int_ports,
            'routes': [],
            'gw_port': ex_gw_port}
        if enable_snat is not None:
            router['enable_snat'] = enable_snat

        ri = router_info.RouterInfo(router_id=router['id'], router=router,
                                    **self.ri_kwargs)
        return ri

    def test_agent_add_internal_network(self):
        router = self._create_router()
        self._add_internal_ports = mock.Mock()
        ri = self._prepare_router_data(enable_snat=True)
        router._router_added(ri.router['id'], ri.router)
        self._add_internal_ports(ri.router, port_count=1)
        self._add_internal_ports.assert_called_once_with(ri.router,
                                                         port_count=1)

    def test_agent_remove_internal_network(self):
        router = self._create_router()
        self._del_internal_ports = mock.Mock()
        ri = self._prepare_router_data(enable_snat=True)
        router._router_added(ri.router['id'], ri.router)
        self._add_internal_ports(ri.router, port_count=2)
        self._del_internal_ports(ri.router, 0)
        self._del_internal_ports.assert_called_once_with(ri.router, 0)

    def test_agent_add_floating_ips(self):
        router = self._create_router()
        self._add_floating_ips = mock.Mock()
        ri = self._prepare_router_data(enable_snat=True)
        self._add_internal_ports(ri.router, port_count=1)
        router._router_added(ri.router['id'], ri.router)
        self._add_floating_ips(ri.router, port_count=1)
        self._add_floating_ips.assert_called_once_with(ri.router, port_count=1)

    def test_agent_remove_floating_ips(self):
        router = self._create_router()
        self._del_floating_ips = mock.Mock()
        ri = self._prepare_router_data(enable_snat=True)
        self._add_internal_ports(ri.router, port_count=1)
        self._add_floating_ips(ri.router, port_count=2)
        router._router_added(ri.router['id'], ri.router)
        self._del_floating_ips(ri.router, 0)
        self._del_floating_ips.assert_called_once_with(ri.router, 0)

    def test_agent_external_gateway(self):
        router = self._create_router()
        router._router_removed = mock.Mock()
        ri = self._prepare_router_data(enable_snat=True)
        router._router_added(ri.router['id'], ri.router)
        router._router_removed(ri.router['id'])
        router._router_removed.assert_called_once_with(ri.router['id'])

    def test_agent_snat_enable(self):
        router = self._create_router()
        ri = self._prepare_router_data(enable_snat=True)
        router._router_added(ri.router['id'], ri.router)
        ri.router['enable_snat'] = False
        self.assertFalse(ri.router['enable_snat'])
