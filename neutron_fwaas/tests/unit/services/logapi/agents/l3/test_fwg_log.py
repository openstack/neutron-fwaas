# Copyright (c) 2018 Fujitsu Limited.
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

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.tests.unit.services.logapi.agent.l3 import test_base as base
from neutron_lib import constants as lib_const

from neutron_fwaas.services.logapi.agents.l3 import fwg_log


class FWaaSL3LoggingExtensionInitializeTestCase(base.L3LoggingExtBaseTestCase):

    def setUp(self):
        super().setUp()
        self.fw_l3_log_ext = fwg_log.FWaaSL3LoggingExtension()
        self.fw_l3_log_ext.consume_api(self.agent_api)

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        call_to_patch = 'neutron_lib.rpc.Connection'
        with mock.patch(call_to_patch,
                        return_value=self.connection) as create_connection:
            self.fw_l3_log_ext.initialize(
                self.connection, lib_const.L3_AGENT_MODE)
            create_connection.assert_has_calls([mock.call()])
            self.connection.create_consumer.assert_has_calls(
                [mock.call(
                     resources_rpc.resource_type_versioned_topic(
                         resources.LOGGING_RESOURCE),
                     [rpc_mock()],
                     fanout=True)]
            )
            subscribe_mock.assert_called_with(
                mock.ANY, resources.LOGGING_RESOURCE)
