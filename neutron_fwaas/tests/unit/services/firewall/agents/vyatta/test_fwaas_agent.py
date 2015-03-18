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

import sys
import uuid

import mock

from neutron.tests import base


class FakeL3AgentMidleware(object):
    def __init__(self, host):
        self._vyatta_clients_pool = mock.Mock()
        self.fwplugin_rpc = mock.Mock()

# Mocking imports of 3rd party vyatta library in unit tests and all modules
# that depends on this library. Import will fail if not mocked and 3rd party
# vyatta library is not installed.
with mock.patch.dict(sys.modules, {
    'networking_brocade': mock.Mock(),
    'networking_brocade.vyatta': mock.Mock(),
    'networking_brocade.vyatta.common': mock.Mock(),
    'networking_brocade.vyatta.vrouter': mock.Mock(),
}):
    from networking_brocade.vyatta.common import l3_agent
    l3_agent.L3AgentMiddleware = FakeL3AgentMidleware
    from neutron_fwaas.services.firewall.agents.vyatta import fwaas_agent
    from neutron_fwaas.services.firewall.agents.vyatta import vyatta_utils


def fake_cmd(*args, **kwargs):
    return (args, kwargs)


class TestVyattaFirewallAgent(base.BaseTestCase):

    def test_process_router(self):
        agent = self._make_agent()

        fake_client = mock.Mock()
        agent._vyatta_clients_pool.get_by_db_lookup.return_value = fake_client

        router_id = str(uuid.uuid4())

        fake_fw_record = {
            'id': str(uuid.uuid4()),
            'name': 'fake-fw-record0',
            'router_ids': [router_id]
        }
        agent.fwplugin_rpc.get_firewalls_for_tenant.return_value = [
            fake_fw_record
        ]

        router = {
            'id': router_id,
            'tenant_id': str(uuid.uuid4())
        }
        router_info = mock.NonCallableMock()
        router_info.router = router

        cmd_list = [
            fake_cmd("zone-policy"),
            fake_cmd(vyatta_utils.ZONE_INTERFACE_CMD.format(
                'fake-zone', 'eth0')),
            fake_cmd(vyatta_utils.ZONE_FIREWALL_CMD.format(
                vyatta_utils.UNTRUST_ZONE, vyatta_utils.TRUST_ZONE,
                'fake-fw-name'))
        ]

        with mock.patch.object(
                vyatta_utils, 'get_zone_cmds') as get_zone_mock:
            get_zone_mock.return_value = cmd_list

            agent.process_router(router_info)

        agent._vyatta_clients_pool.get_by_db_lookup.assert_called_once_with(
            router_info.router['id'], mock.ANY)

        fake_client.exec_cmd_batch.assert_called_once_with(cmd_list)

    def _make_agent(self):
        agent = fwaas_agent.VyattaFirewallAgent('fake-host')
        agent.router_info = dict()
        return agent
