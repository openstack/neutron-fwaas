# Copyright 2015 Intel Corporation.
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


import contextlib
import mock
import neutron_fwaas.services.firewall.drivers.mcafee as mcafee
import neutron_fwaas.services.firewall.drivers.mcafee.ngfw_fwaas as fwaas

from neutron.tests import base

FAKE_FIREWALL_ID = 'firewall_id'
FAKE_POLICY_ID = 'policy_id'
FAKE_TENANT_ID = 'tenant_id'
FAKE_ROUTER_ID = 'router_id'
FAKE_FW_NAME = 'fw_name'


class NGFWFwaasTestCase(base.BaseTestCase):

    def setUp(self):
        super(NGFWFwaasTestCase, self).setUp()
        self.firewall = fwaas.NgfwFwaasDriver()

        self.rule_list = self._fake_ipv4_rules()
        self.apply_list = self._fake_apply_list()
        self.post_return = mock.MagicMock()
        self.tmp_ref = 'temp_ref'
        self.post_return.headers = {'location': self.tmp_ref}
        # we generate the policy name by formatting the ids of firewall,
        # policy, router
        self.policy_name = "%s_%s_%s" % (
                FAKE_FIREWALL_ID[0:7], FAKE_POLICY_ID[0:7],
                FAKE_ROUTER_ID[0:7])

    def _fake_ipv4_rules(self):
        rule1 = {'action': 'deny',
                 'description': '',
                 'destination_ip_address': None,
                 'destination_port': '23',
                 'enabled': True,
                 'firewall_policy_id': FAKE_POLICY_ID,
                 'id': '1',
                 'ip_version': 4,
                 'name': 'a2',
                 'position': 1,
                 'protocol': 'udp',
                 'shared': False,
                 'source_ip_address': None,
                 'source_port': '23',
                 'tenant_id': FAKE_TENANT_ID}
        rule2 = {'action': 'deny',
                 'description': '',
                 'destination_ip_address': None,
                 'destination_port': None,
                 'enabled': True,
                 'firewall_policy_id': FAKE_POLICY_ID,
                 'id': '2',
                 'ip_version': 4,
                 'name': 'a3',
                 'position': 2,
                 'protocol': 'icmp',
                 'shared': False,
                 'source_ip_address': '192.168.100.0/24',
                 'source_port': None,
                 'tenant_id': FAKE_TENANT_ID}
        rule3 = {'action': 'allow',
                 'description': '',
                 'destination_ip_address': None,
                 'destination_port': None,
                 'enabled': True,
                 'firewall_policy_id': FAKE_POLICY_ID,
                 'id': '3',
                 'ip_version': 4,
                 'name': 'a4',
                 'position': 3,
                 'protocol': 'tcp',
                 'shared': False,
                 'source_ip_address': None,
                 'source_port': None,
                 'tenant_id': FAKE_TENANT_ID}
        return [rule1, rule2, rule3]

    def _fake_firewall(self, rule_list):
        fw = {
            'admin_state_up': True,
            'description': '',
            'firewall_policy_id': FAKE_POLICY_ID,

            'id': FAKE_FIREWALL_ID,
            'name': FAKE_FW_NAME,
            'shared': None,
            'status': 'PENDING_CREATE',

            'tenant_id': FAKE_TENANT_ID,
            'firewall_rule_list': rule_list}
        return fw

    def _fake_apply_list(self):
        apply_list = []

        router_info_inst = mock.Mock()
        fake_interface = mock.Mock()
        router_inst = (
            {'_interfaces': fake_interface,
             'admin_state_up': True,
             'distributed': False,
             'external_gateway_info': None,
             'gw_port_id': None,
             'ha': False,
             'ha_vr_id': 0,
             'id': FAKE_ROUTER_ID,
             'name': 'rrr1',
             'routes': [],
             'status': 'ACTIVE',
             'tenant_id': FAKE_TENANT_ID})

        router_info_inst.router = router_inst
        apply_list.append(router_info_inst)
        return apply_list

    def test_update_firewall(self):

        firewall = self._fake_firewall(self.rule_list)

        ref_v4rule = self.tmp_ref + "/fw_ipv4_access_rule"
        ref_upload = self.tmp_ref + "/upload"

        with contextlib.nested(
                mock.patch.object(mcafee.smc_api.SMCAPIConnection, 'login'),
                mock.patch.object(mcafee.smc_api.SMCAPIConnection, 'get'),
                mock.patch.object(mcafee.smc_api.SMCAPIConnection, 'logout'),
                mock.patch.object(
                    mcafee.smc_api.SMCAPIConnection, 'post',
                    return_value=self.post_return),
        ) as (lg, get, logout, post):

            expected = [mock.call(
                'elements/fw_policy',
                '{"name": "%s", "template": null}' % self.policy_name),
                mock.call(
                'elements/udp_service',
                '{"min_dst_port": 23, "max_dst_port": 23, '
                '"name": "service-a2", "max_src_port": 23, '
                '"min_src_port": 23}'),
                mock.call(
                ref_v4rule,
                '{"action": {"action": "discard", '
                '"connection_tracking_options": {}}, '
                '"services": {"service": ["%s"]}, "sources": '
                '{"src": ["None"]}, "name": "a2", "destinations": '
                '{"dst": ["None"]}}' % self.tmp_ref, raw=True),
                mock.call(
                'elements/network',
                '{"ipv4_network": "192.168.100.0/24", '
                '"name": "network-192.168.100.0/24"}'),
                mock.call(
                'elements/icmp_service',
                '{"icmp_code": 0, "icmp_type": 0, "name": "service22"}'),
                mock.call(ref_v4rule,
                          '{"action": {"action": "discard", '
                          '"connection_tracking_options": {}}, '
                          '"services": {"service": ["%s"]}, '
                          '"sources": {"src": ["%s"]}, "name": "a3", '
                          '"destinations": {"dst": ["None"]}}' % (
                              self.tmp_ref, self.tmp_ref), raw=True),
                mock.call(
                'elements/tcp_service',
                '{"min_dst_port": 0, "max_dst_port": 65535, '
                '"name": "service-a4", "max_src_port": 65535, '
                '"min_src_port": 0}'),
                mock.call(
                ref_v4rule,
                '{"action": {"action": "allow", '
                '"connection_tracking_options": {}}, '
                '"services": {"service": ["%s"]}, '
                '"sources": {"src": ["None"]}, "name": "a4", '
                '"destinations": {"dst": ["None"]}}' %
                self.tmp_ref, raw=True),
                mock.call(ref_upload, '', raw=True)]

            self.firewall.update_firewall('legacy', self.apply_list, firewall)
            self.assertEqual(expected, post.call_args_list)

    def test_create_firewall(self):
        self.test_update_firewall()

    def test_delete_firewall(self):
        firewall = self._fake_firewall(self.rule_list)

        get_value = [{'result': [{'name': self.policy_name,
                                  'href': self.tmp_ref}, ]}, ]
        with contextlib.nested(
                mock.patch.object(mcafee.smc_api.SMCAPIConnection, 'login'),
                mock.patch.object(
                    mcafee.smc_api.SMCAPIConnection, 'get',
                    return_value=get_value),
                mock.patch.object(mcafee.smc_api.SMCAPIConnection, 'logout'),
                mock.patch.object(
                    mcafee.smc_api.SMCAPIConnection, 'post',
                    return_value=self.post_return),
                mock.patch.object(mcafee.smc_api.SMCAPIConnection, 'delete'),
        ) as (lg, get, logout, post, delete):
            self.firewall.delete_firewall('legacy', self.apply_list, firewall)

            expected = [
                mock.call(self.tmp_ref, raw=True),
                mock.call(self.tmp_ref, raw=True)
            ]
            self.assertEqual(expected, delete.call_args_list)
