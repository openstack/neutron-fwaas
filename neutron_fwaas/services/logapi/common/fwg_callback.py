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

from neutron.objects import ports as port_objects
from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.drivers import manager
from neutron_lib.callbacks import events
from neutron_lib import constants as nl_const

from neutron_fwaas.services.logapi.common import log_db_api


class FirewallGroupCallBack(manager.ResourceCallBackBase):

    def handle_event(self, resource, event, trigger, **kwargs):
        payload = kwargs.get('payload')
        context = payload.context
        ports_delta = []
        if event == events.AFTER_CREATE:
            # Update log when a new firewall group is created with ports
            ports_delta = payload.latest_state['ports']

        elif event == events.AFTER_UPDATE:
            old_ports = payload.states[0]['ports']
            new_ports = payload.states[1]['ports']

            # Check whether port is updated from firewall group or not
            ports_delta = \
                set(new_ports).symmetric_difference(set(old_ports))

        if self.need_to_notify(context, ports_delta):
            self.trigger_logging(context, payload.resource_id, ports_delta)

    def trigger_logging(self, context, fwg_id, ports_delta):
        log_resources = log_db_api.get_logs_for_fwg(
            context, fwg_id, ports_delta)
        if log_resources:
            self.resource_push_api(
                log_const.RESOURCE_UPDATE, context, log_resources)

    def need_to_notify(self, context, ports):
        notify = False
        for port_id in ports:
            port = port_objects.Port.get_object(context, id=port_id)
            device_owner = port.get('device_owner', '')
            if device_owner in nl_const.ROUTER_INTERFACE_OWNERS:
                notify = True
                break
        return notify
