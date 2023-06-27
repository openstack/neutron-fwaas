# Copyright 2019 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from oslo_config import cfg
from oslo_upgradecheck.upgradecheck import Code

from neutron_fwaas.cmd.upgrade_checks import checks
from neutron_fwaas.tests import base


class TestChecks(base.BaseTestCase):

    def setUp(self):
        super(TestChecks, self).setUp()
        self.checks = checks.Checks()

    def test_get_checks_list(self):
        self.assertIsInstance(self.checks.get_checks(), list)

    def test_fwaas_v1_check_sucess(self):
        cfg.CONF.set_override('service_plugins', ['l3', 'qos'])
        check_result = checks.Checks.fwaas_v1_check(mock.Mock())
        self.assertEqual(Code.SUCCESS, check_result.code)

    def test_fwaas_v1_check_warning(self):
        plugins_to_check = [
            ['l3', 'firewall', 'qos'],
            ['l3',
             'neutron_fwaas.services.firewall.fwaas_plugin:FirewallPlugin',
             'qos']]
        for plugins in plugins_to_check:
            cfg.CONF.set_override('service_plugins', plugins)
            check_result = checks.Checks.fwaas_v1_check(mock.Mock())
            self.assertEqual(Code.FAILURE, check_result.code)
