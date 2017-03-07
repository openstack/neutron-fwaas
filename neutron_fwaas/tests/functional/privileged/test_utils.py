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

import os

from neutron.tests.common import net_helpers
from neutron.tests.functional import base

from neutron_fwaas.privileged.tests.functional import utils


def get_netns_inode(namespace):
    return os.stat('/var/run/netns/%s' % namespace).st_ino


class InNamespaceTest(base.BaseSudoTestCase):

    def test_in_namespace(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        expected = get_netns_inode(namespace)
        before, observed, after = utils.get_in_namespace_netns_inodes(
            namespace)
        self.assertEqual(expected, observed)
        self.assertEqual(before, after)

    def test_in_no_namespace(self):
        inodes = utils.get_in_namespace_netns_inodes(None)
        self.assertEqual(1, len(set(inodes)))
