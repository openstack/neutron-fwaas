# Copyright (c) 2018 Fujitsu Limited
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

from neutron.services.logapi.agent.l3 import base
from neutron.services.logapi.agent import log_extension as log_ext
from neutron.services.logapi.rpc import agent as agent_rpc
from neutron_lib.agent import l3_extension

# TODO(annp) move to neutron-lib
FIREWALL_LOG_DRIVER_NAME = 'fwaas_v2_log'


class FWaaSL3LoggingExtension(base.L3LoggingExtensionBase,
                              l3_extension.L3AgentExtension):

    def initialize(self, connection, driver_type):
        """Initialize L3 logging agent extension"""

        fw_log_cls = self._load_driver_cls(
            log_ext.LOGGING_DRIVERS_NAMESPACE, FIREWALL_LOG_DRIVER_NAME)
        self.log_driver = fw_log_cls(self.agent_api)
        self.resource_rpc = agent_rpc.LoggingApiStub()
        self._register_rpc_consumers()
        self.log_driver.initialize(self.resource_rpc)

    def update_network(self, context, data):
        # TODO(zhouhenglc) remove at base.L3LoggingExtensionBase support
        # update_network
        pass
