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

import mock
import testtools

from neutron_fwaas.privileged import utils
from neutron_fwaas.tests import base


class InNamespaceTest(base.BaseTestCase):
    ORG_NETNS_FD = 124
    NEW_NETNS_FD = 421
    NEW_NETNS = 'newns'

    def setUp(self):
        super(InNamespaceTest, self).setUp()

        # NOTE(cby): we should unmock os.open/close as early as possible
        # because there are used in cleanups
        open_patch = mock.patch('os.open', return_value=self.ORG_NETNS_FD)
        self.open_mock = open_patch.start()
        self.addCleanup(open_patch.stop)

        close_patch = mock.patch('os.close')
        self.close_mock = close_patch.start()
        self.addCleanup(close_patch.stop)

        self.setns_mock = mock.patch(
            'pyroute2.netns.setns', side_effect=self.fake_setns
        ).start()

    def fake_setns(self, setns):
        if setns is self.ORG_NETNS_FD:
            return self.ORG_NETNS_FD
        elif setns is self.NEW_NETNS:
            return self.NEW_NETNS_FD
        else:
            self.fail('invalid netns name')

    def test_in_namespace(self):
        with utils.in_namespace(self.NEW_NETNS):
            self.setns_mock.assert_called_once_with(self.NEW_NETNS)

        setns_calls = [mock.call(self.NEW_NETNS),
                       mock.call(self.ORG_NETNS_FD)]
        close_calls = [mock.call(self.NEW_NETNS_FD),
                       mock.call(self.ORG_NETNS_FD)]
        self.setns_mock.assert_has_calls(setns_calls)
        self.close_mock.assert_has_calls(close_calls)

    def test_in_no_namespace(self):
        for namespace in ('', None):
            with utils.in_namespace(namespace):
                pass
        self.setns_mock.assert_not_called()
        self.close_mock.assert_not_called()

    def test_in_namespace_failed(self):
        with testtools.ExpectedException(ValueError):
            with utils.in_namespace(self.NEW_NETNS):
                self.setns_mock.assert_called_once_with(self.NEW_NETNS)
                raise ValueError

        setns_calls = [mock.call(self.NEW_NETNS),
                       mock.call(self.ORG_NETNS_FD)]
        close_calls = [mock.call(self.NEW_NETNS_FD),
                       mock.call(self.ORG_NETNS_FD)]
        self.setns_mock.assert_has_calls(setns_calls)
        self.close_mock.assert_has_calls(close_calls)

    def test_in_namespace_enter_failed(self):
        self.setns_mock.side_effect = ValueError
        with testtools.ExpectedException(ValueError):
            with utils.in_namespace(self.NEW_NETNS):
                self.fail('It should fail before we reach this code')

        self.setns_mock.assert_called_once_with(self.NEW_NETNS)
        self.close_mock.assert_called_once_with(self.ORG_NETNS_FD)

    def test_in_namespace_exit_failed(self):
        self.setns_mock.side_effect = [self.NEW_NETNS_FD, ValueError]
        with testtools.ExpectedException(utils.BackInNamespaceExit):
            with utils.in_namespace(self.NEW_NETNS):
                pass
