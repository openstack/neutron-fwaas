# Copyright 2015 Brocade Communications System, Inc.
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

from networking_brocade.vyatta.common import l3_agent as vyatta_l3
from neutron.agent import l3_agent

from neutron_fwaas.services.firewall.agents.vyatta import firewall_service


class VyattaFirewallAgent(vyatta_l3.L3AgentMiddleware):
    """Brocade Neutron Firewall agent for Vyatta vRouter.

    The base class FWaaSL3AgentRpcCallback of the VyattaFirewallAgent creates
    the reference FirewallService object that loads the VyattaFirewallDriver
    class.The VyattaFirewallService class registers callbacks and subscribes
    to router events.
    """
    def __init__(self, host, conf=None):
        super(VyattaFirewallAgent, self).__init__(host, conf)
        self.service = firewall_service.VyattaFirewallService(self)


def main():
    l3_agent.main(
        manager='neutron_fwaas.services.firewall.agents.vyatta.'
                'fwaas_agent.VyattaFirewallAgent')
