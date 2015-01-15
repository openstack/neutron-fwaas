# Copyright 2015 OpenStack Foundation.
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
#

from neutron.agent import l3_agent
from neutron import context
from neutron.openstack.common import log as logging
from vyatta.common import l3_agent as vyatta_l3

from neutron_fwaas.services.firewall.agents.vyatta import vyatta_utils


LOG = logging.getLogger(__name__)


class VyattaFirewallAgent(vyatta_l3.L3AgentMiddleware):
    """Brocade Neutron Firewall agent for Vyatta vRouter.

    Configures zone policies on Vyatta vRouter instance.
    """
    def process_router(self, ri):
        ctx = context.Context(None, ri.router['tenant_id'])
        client = self._vyatta_clients_pool.get_by_db_lookup(
            ri.router['id'], ctx)
        fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
        if fw_list:
            fw_name = vyatta_utils.get_firewall_name(ri, fw_list[0])
            zone_cmds = vyatta_utils.get_zone_cmds(client, ri, fw_name)
            client.exec_cmd_batch(zone_cmds)


def main():
    l3_agent.main(
        manager='neutron_fwaas.services.firewall.agents.vyatta.'
                'fwaas_agent.VyattaFirewallAgent')
