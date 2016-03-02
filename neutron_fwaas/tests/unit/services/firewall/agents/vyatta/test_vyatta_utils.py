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

import mock

from neutron.tests import base
from neutron_lib import constants as l3_constants
from six.moves.urllib import parse

# Mocking imports of 3rd party vyatta library in unit tests and all modules
# that depends on this library. Import will fail if not mocked and 3rd party
# vyatta library is not installed.
with mock.patch.dict(sys.modules, {
    'networking_brocade': mock.Mock(),
    'networking_brocade.vyatta': mock.Mock(),
    'networking_brocade.vyatta.vrouter': mock.Mock(),
}):
    from networking_brocade.vyatta.vrouter import client as vyatta_client
    from neutron_fwaas.services.firewall.agents.vyatta import vyatta_utils


def fake_cmd(*args, **kwargs):
    return (args, kwargs)


class TestVyattaUtils(base.BaseTestCase):

    def setUp(self):
        super(TestVyattaUtils, self).setUp()

        mock.patch.object(vyatta_client, 'SetCmd', fake_cmd).start()
        mock.patch.object(vyatta_client, 'DeleteCmd', fake_cmd).start()

    def test_get_firewall_name(self):
        fake_firewall = {
            'id': '74bc106d-fff0-4f92-ac1a-60d4b6b44fe1',
        }

        fw_name = vyatta_utils.get_firewall_name(
            None, fake_firewall)

        self.assertEqual('74bc106dfff04f92ac1a60d4b6b4', fw_name)

    def test_get_trusted_zone_name(self):
        fake_apply_list = object()
        self.assertEqual(
            'Internal_Trust', vyatta_utils.get_trusted_zone_name(
                fake_apply_list))

    def test_get_untrusted_zone_name(self):
        fake_apply_list = object()
        self.assertEqual(
            'External_Untrust', vyatta_utils.get_untrusted_zone_name(
                fake_apply_list))

    def test_get_zone_cmds(self):
        firewall_name = 'fake_firewall0'
        eth_iface = 'eth0'
        fake_api = mock.NonCallableMock()
        fake_api.get_ethernet_if_id.return_value = eth_iface

        mac_address = '00:00:00:00:00:00'
        fake_apply_rule = mock.NonCallableMock()
        fake_apply_rule.router = {
            'gw_port': {
                'mac_address': mac_address},
            l3_constants.INTERFACE_KEY: [{
                'mac_address': mac_address}]
        }

        trusted_zone_name = vyatta_utils.get_trusted_zone_name(
            fake_apply_rule)
        untrusted_zone_name = vyatta_utils.get_untrusted_zone_name(
            fake_apply_rule)

        cmds_actual = vyatta_utils.get_zone_cmds(
            fake_api, fake_apply_rule, firewall_name)
        cmds_expect = [
            vyatta_client.DeleteCmd('zone-policy'),
            vyatta_client.SetCmd(
                vyatta_utils.ZONE_INTERFACE_CMD.format(
                    trusted_zone_name, eth_iface)),
            vyatta_client.SetCmd(
                vyatta_utils.ZONE_INTERFACE_CMD.format(
                    untrusted_zone_name, eth_iface)),
            vyatta_client.SetCmd(
                vyatta_utils.ZONE_FIREWALL_CMD.format(
                    trusted_zone_name, untrusted_zone_name,
                    parse.quote_plus(firewall_name))),
            vyatta_client.SetCmd(
                vyatta_utils.ZONE_FIREWALL_CMD.format(
                    untrusted_zone_name, trusted_zone_name,
                    parse.quote_plus(firewall_name))),
        ]

        self.assertEqual(cmds_expect, cmds_actual)

        fake_api.get_ethernet_if_id.assert_has_calls([
            mock.call(mac_address),
            mock.call(mac_address),
        ])
