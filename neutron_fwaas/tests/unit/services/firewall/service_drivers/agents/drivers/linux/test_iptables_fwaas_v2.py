# Copyright (c) 2016
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

import copy

import mock
from neutron.tests import base
from neutron.tests.unit.api.v2 import test_base as test_api_v2

import neutron_fwaas.services.firewall.service_drivers.agents.drivers.linux.\
    iptables_fwaas_v2 as fwaas


_uuid = test_api_v2._uuid
FAKE_SRC_PREFIX = '10.0.0.0/24'
FAKE_DST_PREFIX = '20.0.0.0/24'
FAKE_PROTOCOL = 'tcp'
FAKE_SRC_PORT = 5000
FAKE_DST_PORT = 22
FAKE_FW_ID = 'fake-fw-uuid'
FAKE_PORT_IDS = ('1_fake-port-uuid', '2_fake-port-uuid')
FW_LEGACY = 'legacy'
MAX_INTF_NAME_LEN = 14


class IptablesFwaasTestCase(base.BaseTestCase):
    def setUp(self):
        super(IptablesFwaasTestCase, self).setUp()
        self.iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        self.iptables_cls_p.start()
        self.firewall = fwaas.IptablesFwaasDriver()
        self.firewall.conntrack.delete_entries = mock.Mock()
        self.firewall.conntrack.flush_entries = mock.Mock()

    def _fake_rules_v4(self, fwid, apply_list):
        rule_list = []
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'source_ip_address': '10.24.4.2',
                 'id': 'fake-fw-rule1'}
        rule2 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22',
                 'id': 'fake-fw-rule2'}
        rule3 = {'enabled': True,
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '23',
                 'id': 'fake-fw-rule3'}
        ingress_chain = ('iv4%s' % fwid)[:11]
        egress_chain = ('ov4%s' % fwid)[:11]
        for router_info_inst, port_ids in apply_list:
            v4filter_inst = router_info_inst.iptables_manager.ipv4['filter']
            v4filter_inst.chains.append(ingress_chain)
            v4filter_inst.chains.append(egress_chain)
        rule_list.append(rule1)
        rule_list.append(rule2)
        rule_list.append(rule3)
        return rule_list

    def _fake_firewall_no_rule(self):
        rule_list = []
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'egress_rule_list': rule_list,
                   'ingress_rule_list': rule_list}
        return fw_inst

    def _fake_firewall(self, rule_list):
        _rule_list = copy.deepcopy(rule_list)
        for rule in _rule_list:
            rule['position'] = str(_rule_list.index(rule))
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'egress_rule_list': _rule_list,
                   'ingress_rule_list': _rule_list}
        return fw_inst

    def _fake_firewall_with_admin_down(self, rule_list):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': False,
                   'tenant_id': 'tenant-uuid',
                   'egress_rule_list': rule_list,
                   'ingress_rule_list': rule_list}
        return fw_inst

    def _fake_apply_list(self, router_count=1, distributed=False,
            distributed_mode=None):
        apply_list = []
        while router_count > 0:
            iptables_inst = mock.Mock()
            if distributed:
                router_inst = {'distributed': distributed}
            else:
                router_inst = {}
            v4filter_inst = mock.Mock()
            v6filter_inst = mock.Mock()
            v4filter_inst.chains = []
            v6filter_inst.chains = []
            iptables_inst.ipv4 = {'filter': v4filter_inst}
            iptables_inst.ipv6 = {'filter': v6filter_inst}
            router_info_inst = mock.Mock()
            router_info_inst.iptables_manager = iptables_inst
            router_info_inst.snat_iptables_manager = iptables_inst
            if distributed_mode == 'dvr':
                router_info_inst.rtr_fip_connect = True
            router_info_inst.router = router_inst
            apply_list.append((router_info_inst, FAKE_PORT_IDS))
            router_count -= 1
        return apply_list

    def _get_intf_name(self, if_prefix, port_id):
        _name = "%s%s" % (if_prefix, port_id)
        return _name[:MAX_INTF_NAME_LEN]

    def _setup_firewall_with_rules(self, func, router_count=1,
            distributed=False, distributed_mode=None):
        apply_list = self._fake_apply_list(router_count=router_count,
            distributed=distributed, distributed_mode=distributed_mode)
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall(rule_list)
        if distributed:
            if distributed_mode == 'dvr_snat':
                if_prefix = 'sg-'
            if distributed_mode == 'dvr':
                if_prefix = 'rfp-'
        else:
            if_prefix = 'qr-'
            distributed_mode = 'legacy'
        func(distributed_mode, apply_list, firewall)
        binary_name = fwaas.iptables_manager.binary_name
        dropped = '%s-dropped' % binary_name
        accepted = '%s-accepted' % binary_name
        rejected = '%s-rejected' % binary_name
        invalid_rule = '-m state --state INVALID -j %s' % dropped
        est_rule = '-m state --state RELATED,ESTABLISHED -j ACCEPT'
        rule1 = '-p tcp -s 10.24.4.2/32 -m tcp --dport 80 -j %s' % accepted
        rule2 = '-p tcp -m tcp --dport 22 -j %s' % dropped
        rule3 = '-p tcp -m tcp --dport 23 -j %s' % rejected
        ingress_chain = 'iv4%s' % firewall['id']
        egress_chain = 'ov4%s' % firewall['id']
        ipt_mgr_ichain = '%s-%s' % (binary_name, ingress_chain[:11])
        ipt_mgr_echain = '%s-%s' % (binary_name, egress_chain[:11])
        for router_info_inst, port_ids in apply_list:
            v4filter_inst = router_info_inst.iptables_manager.ipv4['filter']
            calls = [mock.call.remove_chain('iv4fake-fw-uuid'),
                     mock.call.remove_chain('ov4fake-fw-uuid'),
                     mock.call.remove_chain('fwaas-default-policy'),
                     mock.call.add_chain('fwaas-default-policy'),
                     mock.call.add_rule(
                         'fwaas-default-policy', '-j %s' % dropped),
                     mock.call.add_chain(ingress_chain),
                     mock.call.add_rule(ingress_chain, invalid_rule),
                     mock.call.add_rule(ingress_chain, est_rule),
                     mock.call.add_chain(egress_chain),
                     mock.call.add_rule(egress_chain, invalid_rule),
                     mock.call.add_rule(egress_chain, est_rule),
                     mock.call.add_rule(ingress_chain, rule1),
                     mock.call.add_rule(ingress_chain, rule2),
                     mock.call.add_rule(ingress_chain, rule3),
                     mock.call.add_rule(egress_chain, rule1),
                     mock.call.add_rule(egress_chain, rule2),
                     mock.call.add_rule(egress_chain, rule3)
                     ]

            for port in FAKE_PORT_IDS:
                intf_name = self._get_intf_name(if_prefix, port)
                calls.append(mock.call.add_rule('FORWARD',
                        '-o %s -j %s' % (intf_name, ipt_mgr_ichain)))
            for port in FAKE_PORT_IDS:
                intf_name = self._get_intf_name(if_prefix, port)
                calls.append(mock.call.add_rule('FORWARD',
                        '-i %s -j %s' % (intf_name, ipt_mgr_echain)))

            for direction in ['o', 'i']:
                for port_id in FAKE_PORT_IDS:
                    intf_name = self._get_intf_name(if_prefix, port_id)
                    calls.append(mock.call.add_rule('FORWARD',
                            '-%s %s -j %s-fwaas-defau' % (direction,
                                    intf_name, binary_name)))
            v4filter_inst.assert_has_calls(calls)

    def test_create_firewall_group_no_rules(self):
        apply_list = self._fake_apply_list()
        first_ri = apply_list[0][0]
        firewall = self._fake_firewall_no_rule()
        self.firewall.create_firewall_group('legacy', apply_list, firewall)
        binary_name = fwaas.iptables_manager.binary_name
        dropped = '%s-dropped' % binary_name
        invalid_rule = '-m state --state INVALID -j %s' % dropped
        est_rule = '-m state --state RELATED,ESTABLISHED -j ACCEPT'
        for ip_version in (4, 6):
            ingress_chain = ('iv%s%s' % (ip_version, firewall['id']))
            egress_chain = ('ov%s%s' % (ip_version, firewall['id']))
            calls = [mock.call.remove_chain(
                     'iv%sfake-fw-uuid' % ip_version),
                     mock.call.remove_chain(
                         'ov%sfake-fw-uuid' % ip_version),
                     mock.call.remove_chain('fwaas-default-policy'),
                     mock.call.add_chain('fwaas-default-policy'),
                     mock.call.add_rule(
                         'fwaas-default-policy', '-j %s' % dropped),
                     mock.call.add_chain(ingress_chain),
                     mock.call.add_rule(ingress_chain, invalid_rule),
                     mock.call.add_rule(ingress_chain, est_rule),
                     mock.call.add_chain(egress_chain),
                     mock.call.add_rule(egress_chain, invalid_rule),
                     mock.call.add_rule(egress_chain, est_rule)]

            for port_id in FAKE_PORT_IDS:
                for direction in ['o', 'i']:
                    mock.call.add_rule('FORWARD',
                           '-%s qr-%s -j %s-fwaas-defau' % (port_id,
                                                            direction,
                                                            binary_name))
            if ip_version == 4:
                v4filter_inst = first_ri.iptables_manager.ipv4['filter']
                v4filter_inst.assert_has_calls(calls)
            else:
                v6filter_inst = first_ri.iptables_manager.ipv6['filter']
                v6filter_inst.assert_has_calls(calls)

    def test_create_firewall_group_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group)

    def test_create_firewall_group_with_rules_without_distributed_attr(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group,
                                        distributed=None)

    def test_create_firewall_group_with_rules_two_routers(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group,
                                        router_count=2)

    def test_update_firewall_group_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group)

    def test_update_firewall_group_with_rules_without_distributed_attr(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
                                        distributed=None)

    def _test_delete_firewall_group(self, distributed=False):
        apply_list = self._fake_apply_list(distributed=distributed)
        first_ri = apply_list[0][0]
        firewall = self._fake_firewall_no_rule()
        self.firewall.delete_firewall_group('legacy', apply_list, firewall)
        ingress_chain = 'iv4%s' % firewall['id']
        egress_chain = 'ov4%s' % firewall['id']
        calls = [mock.call.remove_chain(ingress_chain),
                 mock.call.remove_chain(egress_chain),
                 mock.call.remove_chain('fwaas-default-policy')]
        first_ri.iptables_manager.ipv4['filter'].assert_has_calls(calls)

    def test_delete_firewall_group(self):
        self._test_delete_firewall_group()

    def test_delete_firewall_group_without_distributed_attr(self):
        self._test_delete_firewall_group(distributed=None)

    def test_create_firewall_group_with_admin_down(self):
        apply_list = self._fake_apply_list()
        first_ri = apply_list[0][0]
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall_with_admin_down(rule_list)
        binary_name = fwaas.iptables_manager.binary_name
        dropped = '%s-dropped' % binary_name
        self.firewall.create_firewall_group('legacy', apply_list, firewall)
        calls = [mock.call.remove_chain('iv4fake-fw-uuid'),
                 mock.call.remove_chain('ov4fake-fw-uuid'),
                 mock.call.remove_chain('fwaas-default-policy'),
                 mock.call.add_chain('fwaas-default-policy'),
                 mock.call.add_rule('fwaas-default-policy', '-j %s' % dropped)]
        first_ri.iptables_manager.ipv4['filter'].assert_has_calls(calls)

    def test_create_firewall_group_with_rules_dvr_snat(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group,
            distributed=True, distributed_mode='dvr_snat')

    def test_update_firewall_group_with_rules_dvr_snat(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
            distributed=True, distributed_mode='dvr_snat')

    def test_create_firewall_group_with_rules_dvr(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group,
            distributed=True, distributed_mode='dvr')

    def test_update_firewall_group_with_rules_dvr(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
            distributed=True, distributed_mode='dvr')

    def test_remove_conntrack_new_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        self.firewall.create_firewall_group(FW_LEGACY, apply_list, firewall)
        for router_info_inst, port_ids in apply_list:
            namespace = router_info_inst.iptables_manager.namespace
            calls = [mock.call(namespace)]
            self.firewall.conntrack.flush_entries.assert_has_calls(calls)

    def test_remove_conntrack_inserted_rule(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall(rule_list)
        self.firewall.create_firewall_group(FW_LEGACY, apply_list, firewall)
        self.firewall.pre_firewall = dict(firewall)
        insert_rule = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'icmp',
                 'id': 'fake-fw-rule'}
        rule_list.insert(2, insert_rule)
        firewall = self._fake_firewall(rule_list)
        self.firewall.update_firewall_group(FW_LEGACY, apply_list, firewall)
        rules_changed = [
            {'destination_port': '23',
             'position': '2',
             'protocol': 'tcp',
             'ip_version': 4,
             'enabled': True,
             'action': 'reject',
             'id': 'fake-fw-rule3'},
            {'destination_port': '23',
             'position': '3',
             'protocol': 'tcp',
             'ip_version': 4,
             'enabled': True,
             'action': 'reject',
             'id': 'fake-fw-rule3'}
        ] * 2  # Egress and ingress rule lists
        rules_inserted = [
            {'id': 'fake-fw-rule',
             'protocol': 'icmp',
             'ip_version': 4,
             'enabled': True,
             'action': 'deny',
             'position': '2'}
        ] * 2  # Egress and ingress rule lists
        for router_info_inst, port_ids in apply_list:
            namespace = router_info_inst.iptables_manager.namespace
            self.firewall.conntrack.delete_entries.assert_called_once_with(
                rules_changed + rules_inserted, namespace
            )

    def test_remove_conntrack_removed_rule(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall(rule_list)
        self.firewall.create_firewall_group(FW_LEGACY, apply_list, firewall)
        self.firewall.pre_firewall = dict(firewall)
        remove_rule = rule_list[1]
        rule_list.remove(remove_rule)
        firewall = self._fake_firewall(rule_list)
        self.firewall.update_firewall_group(FW_LEGACY, apply_list, firewall)
        rules_changed = [
            {'destination_port': '23',
             'position': '2',
             'protocol': 'tcp',
             'ip_version': 4,
             'enabled': True,
             'action': 'reject',
             'id': 'fake-fw-rule3'},
            {'destination_port': '23',
             'position': '1',
             'protocol': 'tcp',
             'ip_version': 4,
             'enabled': True,
             'action': 'reject',
             'id': 'fake-fw-rule3'}
        ] * 2  # Egress and ingress rule lists
        rules_removed = [
            {'enabled': True,
             'position': '1',
             'protocol': 'tcp',
             'id': 'fake-fw-rule2',
             'ip_version': 4,
             'action': 'deny',
             'destination_port': '22'}
        ] * 2  # Egress and ingress rule lists
        for router_info_inst, port_ids in apply_list:
            namespace = router_info_inst.iptables_manager.namespace
            self.firewall.conntrack.delete_entries.assert_called_once_with(
                rules_changed + rules_removed, namespace
            )

    def test_remove_conntrack_changed_rule(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall(rule_list)
        self.firewall.create_firewall_group(FW_LEGACY, apply_list, firewall)
        income_rule = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'id': 'fake-fw-rule3'}
        rule_list[2] = income_rule
        firewall = self._fake_firewall(rule_list)
        self.firewall.update_firewall_group(FW_LEGACY, apply_list, firewall)
        rules_changed = [
            {'id': 'fake-fw-rule3',
             'enabled': True,
             'action': 'reject',
             'position': '2',
             'destination_port': '23',
             'ip_version': 4,
             'protocol': 'tcp'},
            {'position': '2',
             'enabled': True,
             'action': 'deny',
             'id': 'fake-fw-rule3',
             'ip_version': 4,
             'protocol': 'tcp'}
        ] * 2  # Egress and ingress rule lists
        for router_info_inst, port_ids in apply_list:
            namespace = router_info_inst.iptables_manager.namespace
            self.firewall.conntrack.delete_entries.assert_called_once_with(
                rules_changed, namespace
            )
