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

from neutron.services.logapi.drivers import manager
from neutron_lib.callbacks import events
from neutron_lib import constants as nl_const
from neutron_lib.services.logapi import constants as log_const

from neutron_fwaas.services.logapi.common import log_db_api


class NeutronPortCallBack(manager.ResourceCallBackBase):

    def handle_event(self, resource, event, trigger, payload):
        if event == events.AFTER_UPDATE:
            context = payload.context
            original_port = payload.states[0]
            port = payload.states[1]

            if port['device_owner'] in nl_const.ROUTER_INTERFACE_OWNERS:
                if original_port['status'] != port['status']:
                    self.trigger_logging(context, port)

    def trigger_logging(self, context, port):
        log_resources = log_db_api.get_logs_for_port(context, port['id'])
        if log_resources:
            self.resource_push_api(
                log_const.RESOURCE_UPDATE, context, log_resources)
