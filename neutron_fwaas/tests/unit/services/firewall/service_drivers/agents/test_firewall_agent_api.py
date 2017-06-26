# Copyright (c) 2013 OpenStack Foundation
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

from neutron_fwaas.services.firewall.service_drivers.agents.drivers \
    import fwaas_base
from neutron_fwaas.services.firewall.service_drivers.agents.drivers \
    import fwaas_base_v2
from neutron_fwaas.services.firewall.service_drivers.agents \
    import firewall_agent_api as api
from neutron_fwaas.tests import base


class NoopFwaasDriver(fwaas_base.FwaasDriverBase):
    """Noop Fwaas Driver.

    v1 firewall driver which does nothing.
    This driver is for disabling Fwaas functionality.
    """

    def create_firewall_group(self, agent_mode, apply_list, firewall):
        pass

    def delete_firewall_group(self, agent_mode, apply_list, firewall):
        pass

    def update_firewall_group(self, agent_mode, apply_list, firewall):
        pass

    def apply_default_policy(self, agent_mode, apply_list, firewall):
        pass


class NoopFwaasDriverV2(fwaas_base_v2.FwaasDriverBase):
    """Noop Fwaas Driver.

    v2 firewall driver which does nothing.
    This driver is for disabling Fwaas functionality.
    """

    def create_firewall_group(self, agent_mode, apply_list, firewall):
        pass

    def delete_firewall_group(self, agent_mode, apply_list, firewall):
        pass

    def update_firewall_group(self, agent_mode, apply_list, firewall):
        pass

    def apply_default_policy(self, agent_mode, apply_list, firewall):
        pass


class TestFWaaSAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFWaaSAgentApi, self).setUp()

        self.api = api.FWaaSPluginApiMixin(
            'topic',
            'host')

    def test_init(self):
        self.assertEqual('host', self.api.host)

    def _test_firewall_method(self, method_name, **kwargs):
        with mock.patch.object(self.api.client, 'call') as rpc_mock, \
                mock.patch.object(self.api.client, 'prepare') as prepare_mock:

            prepare_mock.return_value = self.api.client
            getattr(self.api, method_name)(mock.sentinel.context, 'test',
                                           **kwargs)

        prepare_args = {}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method_name,
                                         firewall_id='test', host='host',
                                         **kwargs)

    def test_set_firewall_status(self):
        self._test_firewall_method('set_firewall_status', status='fake_status')

    def test_firewall_deleted(self):
        self._test_firewall_method('firewall_deleted')
