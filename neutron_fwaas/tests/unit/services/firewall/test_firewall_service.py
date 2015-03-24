# Copyright 2014 OpenStack Foundation.
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

from neutron.tests import base
from oslo_config import cfg

from neutron_fwaas.services.firewall.agents import firewall_service

FWAAS_NOP_DEVICE = ('neutron_fwaas.tests.unit.services.firewall.agents.'
                    'test_firewall_agent_api.NoopFwaasDriver')


class TestFirewallDeviceDriverLoading(base.BaseTestCase):

    def setUp(self):
        super(TestFirewallDeviceDriverLoading, self).setUp()
        self.service = firewall_service.FirewallService()

    def test_loading_firewall_device_driver(self):
        """Get the sole device driver for FWaaS."""
        cfg.CONF.set_override('driver',
                              FWAAS_NOP_DEVICE,
                              'fwaas')
        driver = self.service.load_device_drivers()
        self.assertIsNotNone(driver)
        self.assertIn(driver.__class__.__name__, FWAAS_NOP_DEVICE)

    def test_fail_no_such_firewall_device_driver(self):
        """Failure test of import error for FWaaS device driver."""
        cfg.CONF.set_override('driver',
                              'no.such.class',
                              'fwaas')
        self.assertRaises(ImportError,
                          self.service.load_device_drivers)

    def test_fail_firewall_no_device_driver_specified(self):
        """Failure test when no FWaaS device driver is specified.

        This is a configuration error, as the user must specify a device
        driver, when enabling the firewall service (and there is no default
        configuration set. We'll simulate that by using an empty string.
        """
        cfg.CONF.set_override('driver',
                              '',
                              'fwaas')
        self.assertRaises(ValueError,
                          self.service.load_device_drivers)
