# Copyright 2017 Mirantis Inc.
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

from unittest import mock

from neutron import manager
from neutron_fwaas.services.firewall.service_drivers.agents.drivers.linux.l2.\
    noop import noop_driver
from neutron_fwaas.tests import base


class TestNoopDriver(base.BaseTestCase):
    def setUp(self):
        super(TestNoopDriver, self).setUp()
        mock_br = mock.Mock()
        self.firewall = noop_driver.NoopFirewallL2Driver(mock_br)

    def test_basic_methods(self):
        # just make sure it doesn't crash
        fwg_mock = mock.Mock()
        self.firewall.create_firewall_group(ports=[], firewall_group=fwg_mock)
        self.firewall.update_firewall_group(ports=[], firewall_group=fwg_mock)
        self.firewall.delete_firewall_group(ports=[], firewall_group=fwg_mock)
        self.firewall.filter_defer_apply_on()
        self.firewall.filter_defer_apply_off()
        self.firewall.defer_apply()
        self.firewall.ports

    def test_load_firewall_class(self):
        res = manager.NeutronManager.load_class_for_provider(
            'neutron.agent.l2.firewall_drivers', 'noop')
        self.assertEqual(res, noop_driver.NoopFirewallL2Driver)
