# Copyright (c) 2017 Thales Services SAS
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

from neutron.agent.linux import ip_lib
from neutron.common import utils as neutron_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base

from neutron_fwaas.privileged.tests.functional import utils


class InNamespaceTest(base.BaseSudoTestCase):

    def setUp(self):
        super(InNamespaceTest, self).setUp()
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name

        ip = ip_lib.IPWrapper()
        root_dev_name = neutron_utils.get_rand_device_name()
        netns_dev_name = neutron_utils.get_rand_device_name()
        self.root_dev, self.netns_dev = ip.add_veth(
            root_dev_name, netns_dev_name, namespace2=self.namespace)
        self.addCleanup(self.root_dev.link.delete)

    def test_in_namespace(self):
        before, observed, after = utils.get_in_namespace_interfaces(
            self.namespace)
        expected = ['lo', self.netns_dev.name]
        self.assertItemsEqual(expected, observed)
        # Other tests can create/delete devices, so we just checks
        # self.root_dev_name is included in the root namespace result.
        self.assertIn(self.root_dev.name, before)
        self.assertIn(self.root_dev.name, after)

    def test_in_no_namespace(self):
        before, observed, after = utils.get_in_namespace_interfaces(None)
        # Other tests can create/delete devices, so we just checks
        # self.root_dev_name is included in the root namespace result.
        self.assertIn(self.root_dev.name, observed)
        self.assertIn(self.root_dev.name, before)
        self.assertIn(self.root_dev.name, after)
