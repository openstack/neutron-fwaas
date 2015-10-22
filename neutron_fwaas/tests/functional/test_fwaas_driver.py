# Copyright (c) 2015 Cisco Systems, Inc.
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

# NOTE: The purpose of this module is to provide a nop test to verify that
# the functional gate is working.

from neutron.tests.functional import base


class TestFWaaSDriver(base.BaseSudoTestCase):

    """Test the iptables implementation of the FWaaS driver."""

    # NOTE: Tests may be added/removed/changed, when this is fleshed out
    # in future commits.

    def test_status_reporting(self):
        """Test status reported correctly to agent."""
        pass
