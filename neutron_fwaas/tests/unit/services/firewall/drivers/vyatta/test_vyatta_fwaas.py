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
from oslo_utils import uuidutils
from six.moves.urllib import parse

# Mocking imports of 3rd party vyatta library in unit tests and all modules
# that depends on this library. Import will fail if not mocked and 3rd party
# vyatta library is not installed.
with mock.patch.dict(sys.modules, {
    'networking_brocade': mock.Mock(),
    'networking_brocade.vyatta': mock.Mock(),
    'networking_brocade.vyatta.common': mock.Mock(),
    'networking_brocade.vyatta.vrouter': mock.Mock(),
}):
    from networking_brocade.vyatta.vrouter import client as vyatta_client
    from neutron_fwaas.services.firewall.agents.vyatta import vyatta_utils
    from neutron_fwaas.services.firewall.drivers.vyatta import vyatta_fwaas

_uuid = uuidutils.generate_uuid

FAKE_FW_UUID = _uuid()


def fake_cmd(*args, **kwargs):
    return (args, kwargs)


class VyattaFwaasTestCase(base.BaseTestCase):
    def setUp(self):
        super(VyattaFwaasTestCase, self).setUp()

        mock.patch.object(vyatta_client, 'SetCmd', fake_cmd).start()
        mock.patch.object(vyatta_client, 'DeleteCmd', fake_cmd).start()

        self.fwaas_driver = vyatta_fwaas.VyattaFirewallDriver()

        self.fake_rules = [self._make_fake_fw_rule()]
        self.fake_firewall = self._make_fake_firewall(self.fake_rules)
        self.fake_firewall_name = vyatta_utils.get_firewall_name(
            None, self.fake_firewall)
        self.fake_apply_list = [self._make_fake_router_info()]
        self.fake_agent_mode = None

    def test_create_firewall(self):

        with mock.patch.object(
                self.fwaas_driver, 'update_firewall') as fw_update:
            self.fwaas_driver.create_firewall(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

            fw_update.assert_called_once_with(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

    def test_update_firewall(self):
        with mock.patch.object(
                self.fwaas_driver, '_update_firewall') as fw_update:
            self.fake_firewall['admin_state_up'] = True
            self.fwaas_driver.create_firewall(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

            fw_update.assert_called_once_with(
                self.fake_apply_list, self.fake_firewall)

        with mock.patch.object(
                self.fwaas_driver, 'apply_default_policy') as fw_apply_policy:
            self.fake_firewall['admin_state_up'] = False
            self.fwaas_driver.create_firewall(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

            fw_apply_policy.assert_called_once_with(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

    def test_delete_firewall(self):
        with mock.patch.object(
                self.fwaas_driver, 'apply_default_policy') as fw_apply_policy:
            self.fwaas_driver.delete_firewall(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

            fw_apply_policy.assert_called_once_with(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

    def test_apply_default_policy(self):
        with mock.patch.object(
                self.fwaas_driver, '_delete_firewall') as fw_delete:
            self.fwaas_driver.apply_default_policy(
                self.fake_agent_mode, self.fake_apply_list, self.fake_firewall)

            calls = [mock.call(x, self.fake_firewall)
                     for x in self.fake_apply_list]
            fw_delete.assert_has_calls(calls)

    def test_update_firewall_internal(self):
        with mock.patch.object(
                self.fwaas_driver, '_delete_firewall'
        ) as fw_delete, mock.patch.object(
                self.fwaas_driver, '_setup_firewall') as fw_setup:
            self.fwaas_driver._update_firewall(
                self.fake_apply_list, self.fake_firewall)

            calls = [mock.call(x, self.fake_firewall)
                     for x in self.fake_apply_list]

            fw_delete.assert_has_calls(calls)
            fw_setup.assert_has_calls(calls)

    def test_setup_firewall_internal(self):
        fake_rule = self._make_fake_fw_rule()
        fake_router_info = self._make_fake_router_info()
        fake_rule_cmd = 'fake-fw-rule0'
        fake_zone_configure_rules = ['fake-config-rule0']

        mock_api = mock.Mock()
        mock_api_gen = mock.Mock(return_value=mock_api)
        mock_get_firewall_rule = mock.Mock(return_value=[fake_rule_cmd])
        mock_get_zone_cmds = mock.Mock(return_value=fake_zone_configure_rules)
        with mock.patch.object(self.fwaas_driver, '_get_vyatta_client',
                               mock_api_gen), \
                mock.patch.object(vyatta_fwaas.vyatta_utils, 'get_zone_cmds',
                                  mock_get_zone_cmds), \
                mock.patch.object(self.fwaas_driver, '_set_firewall_rule',
                                  mock_get_firewall_rule):
            self.fwaas_driver._setup_firewall(
                fake_router_info, self.fake_firewall)

            mock_api_gen.assert_called_once_with(
                fake_router_info.router)
            mock_get_firewall_rule.assert_called_once_with(
                self.fake_firewall_name, 1, fake_rule)
            mock_get_zone_cmds.assert_called_once_with(
                mock_api, fake_router_info, self.fake_firewall_name)

            cmds = [
                vyatta_client.SetCmd(
                    vyatta_fwaas.FW_NAME.format(
                        self.fake_firewall_name)),
                vyatta_client.SetCmd(
                    vyatta_fwaas.FW_DESCRIPTION.format(
                        self.fake_firewall_name,
                        parse.quote_plus(self.fake_firewall['description']))),
                vyatta_client.SetCmd(
                    vyatta_fwaas.FW_ESTABLISHED_ACCEPT),
                vyatta_client.SetCmd(
                    vyatta_fwaas.FW_RELATED_ACCEPT),
                fake_rule_cmd,
            ] + fake_zone_configure_rules
            mock_api.exec_cmd_batch.assert_called_once_with(cmds)

    def test_delete_firewall_internal(self):
        fake_router_info = self._make_fake_router_info()

        with mock.patch.object(
                self.fwaas_driver,
                '_get_vyatta_client') as mock_client_factory:
            mock_api = mock_client_factory.return_value

            self.fwaas_driver._delete_firewall(
                fake_router_info, self.fake_firewall)

            cmds = [
                vyatta_client.DeleteCmd("zone-policy"),
                vyatta_client.DeleteCmd(vyatta_fwaas.FW_NAME.format(
                    self.fake_firewall_name)),
                vyatta_client.DeleteCmd("firewall/state-policy"),
            ]
            mock_api.exec_cmd_batch.assert_called_once_with(cmds)

    def test_set_firewall_rule_internal(self):
        fake_rule = self._make_fake_fw_rule()
        fake_firewall_name = 'fake-fw-name'

        fake_rule.update({
            'description': 'rule description',
            'source_port': '2080',
            'destination_ip_address': '172.16.1.1'
        })
        action_map = {
            'allow': 'accept',
        }

        cmds_actual = self.fwaas_driver._set_firewall_rule(
            fake_firewall_name, 1, fake_rule)
        cmds_expect = [
            vyatta_client.SetCmd(
                vyatta_fwaas.FW_RULE_DESCRIPTION.format(
                    parse.quote_plus(fake_firewall_name), 1,
                    parse.quote_plus(fake_rule['description'])))
        ]

        rules = [
            ('protocol', vyatta_fwaas.FW_RULE_PROTOCOL),
            ('source_port', vyatta_fwaas.FW_RULE_SRC_PORT),
            ('destination_port', vyatta_fwaas.FW_RULE_DEST_PORT),
            ('source_ip_address', vyatta_fwaas.FW_RULE_SRC_ADDR),
            ('destination_ip_address', vyatta_fwaas.FW_RULE_DEST_ADDR),
        ]

        for key, url in rules:
            cmds_expect.append(vyatta_client.SetCmd(
                url.format(
                    parse.quote_plus(fake_firewall_name), 1,
                    parse.quote_plus(fake_rule[key]))))

        cmds_expect.append(vyatta_client.SetCmd(
            vyatta_fwaas.FW_RULE_ACTION.format(
                parse.quote_plus(fake_firewall_name), 1,
                action_map.get(fake_rule['action'], 'drop'))))

        self.assertEqual(cmds_expect, cmds_actual)

    def _make_fake_router_info(self):
        info = mock.Mock()
        info.router = {
            'id': 'fake-router-id',
            'tenant_id': 'tenant-uuid',
        }
        return info

    def _make_fake_fw_rule(self):
        return {
            'enabled': True,
            'action': 'allow',
            'ip_version': 4,
            'protocol': 'tcp',
            'destination_port': '80',
            'source_ip_address': '10.24.4.2'}

    def _make_fake_firewall(self, rules):
        return {'id': FAKE_FW_UUID,
                'admin_state_up': True,
                'name': 'test-firewall',
                'tenant_id': 'tenant-uuid',
                'description': 'Fake firewall',
                'firewall_rule_list': rules}
