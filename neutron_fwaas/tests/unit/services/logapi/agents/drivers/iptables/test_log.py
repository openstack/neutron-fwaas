# Copyright (c) 2018 Fujitsu Limited.
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

from collections import defaultdict

from unittest import mock

from neutron.tests.unit.api.v2 import test_base
from neutron_lib.services.logapi import constants as log_const

from neutron_fwaas.privileged.netfilter_log import libnetfilter_log as libnflog
from neutron_fwaas.services.logapi.agents.drivers.iptables import log
from neutron_fwaas.tests import base

FAKE_PROJECT_ID = 'fake_project_id'
FAKE_PORT_ID = 'fake_port_id'
FAKE_FWG_ID = 'fake_fwg_id'
FAKE_LOG_ID = 'fake_log_id'
FAKE_RESOURCE_TYPE = 'firewall_group'

FAKE_RATE = 100
FAKE_BURST = 25


class TestLogPrefix(base.BaseTestCase):

    def setUp(self):
        super(TestLogPrefix, self).setUp()
        self.log_prefix = log.LogPrefix(FAKE_PORT_ID,
                                        'fake_event',
                                        FAKE_PROJECT_ID)
        self.log_prefix.log_object_refs = set([FAKE_LOG_ID])

    def test_add_log_obj_ref(self):
        added_log_id = test_base._uuid
        expected_log_obj_ref = set([FAKE_LOG_ID, added_log_id])
        self.log_prefix.add_log_obj_ref(added_log_id)
        self.assertEqual(expected_log_obj_ref, self.log_prefix.log_object_refs)

    def test_remove_log_obj_ref(self):
        expected_log_obj_ref = set()
        self.log_prefix.remove_log_obj_ref(FAKE_LOG_ID)
        self.assertEqual(expected_log_obj_ref, self.log_prefix.log_object_refs)

    def test_is_empty(self):
        self.log_prefix.remove_log_obj_ref(FAKE_LOG_ID)
        result = self.log_prefix.is_empty
        self.assertEqual(True, result)


class BaseIptablesLogTestCase(base.BaseTestCase):

    def setUp(self):
        super(BaseIptablesLogTestCase, self).setUp()
        self.iptables_manager_patch = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        self.iptables_manager_mock = self.iptables_manager_patch.start()
        resource_rpc_mock = mock.Mock()

        self.iptables_mock = mock.Mock()
        self.v4filter_mock = mock.Mock()
        self.v6filter_mock = mock.Mock()
        self.iptables_mock.ipv4 = {'filter': self.v4filter_mock}
        self.iptables_mock.ipv6 = {'filter': self.v6filter_mock}

        self.log_driver = log.IptablesLoggingDriver(mock.Mock())
        self.log_driver.iptables_manager = self.iptables_mock
        self.log_driver.resource_rpc = resource_rpc_mock
        self.context = mock.Mock()
        self.log_driver.agent_api = mock.Mock()

    def test_start_logging(self):
        fake_router_info = mock.Mock()
        fake_router_info.router_id = 'fake_router_id'
        fake_router_info.ns_name = 'fake_namespace'
        libnflog.run_nflog = mock.Mock()
        self.log_driver._create_firewall_group_log = mock.Mock()

        # Test with router_info that has internal ports
        fake_router_info.internal_ports = [
            {'id': 'fake_port1'},
            {'id': 'fake_port2'},
        ]
        fake_kwargs = {
            'router_info': fake_router_info
        }
        self.log_driver.ports_belong_router = defaultdict(set)
        self.log_driver.start_logging(self.context, **fake_kwargs)
        self.log_driver._create_firewall_group_log.\
            assert_called_once_with(self.context,
                                    FAKE_RESOURCE_TYPE,
                                    ports=fake_router_info.internal_ports,
                                    router_id=fake_router_info.router_id)

        # Test with log_resources
        fake_kwargs = {
            'log_resources': 'fake'
        }
        self.log_driver._create_firewall_group_log.reset_mock()
        self.log_driver.start_logging(self.context, **fake_kwargs)
        self.log_driver._create_firewall_group_log. \
            assert_called_once_with(self.context,
                                    FAKE_RESOURCE_TYPE,
                                    **fake_kwargs)

    def test_stop_logging(self):
        fake_kwargs = {
            'log_resources': 'fake'
        }
        self.log_driver._delete_firewall_group_log = mock.Mock()
        self.log_driver.stop_logging(self.context, **fake_kwargs)
        self.log_driver._delete_firewall_group_log.\
            assert_called_once_with(self.context, **fake_kwargs)
        fake_kwargs = {
            'fake': 'fake'
        }
        self.log_driver._delete_firewall_group_log.reset_mock()
        self.log_driver.stop_logging(self.context, **fake_kwargs)
        self.log_driver._delete_firewall_group_log.assert_not_called()

    def test_clean_up_unused_ipt_mgrs(self):
        f_router_ids = ['r1', 'r2', 'r3']
        self.log_driver.ipt_mgr_list = self._fake_ipt_mgr_list(f_router_ids)

        # Test with a port is delete from router
        self.log_driver.unused_port_ids = set(['r1_port1'])
        self.log_driver._cleanup_unused_ipt_mgrs()
        self.assertEqual(set(), self.log_driver.unused_port_ids)
        self.assertIsNone(self.log_driver.ipt_mgr_list['r1'].get('r1_port1'))

        # Test with all ports are deleted from router
        self.log_driver.unused_port_ids = set(['r2_port1', 'r2_port2'])
        self.log_driver._cleanup_unused_ipt_mgrs()
        self.assertEqual(set(), self.log_driver.unused_port_ids)
        self.assertIsNone(self.log_driver.ipt_mgr_list.get('r2'))

    def test_get_intf_name(self):
        fake_router = mock.Mock()
        fake_port_id = 'fake_router_port_id'

        # Test with legacy router
        self.log_driver.conf.agent_mode = 'legacy'
        fake_router.router = {
            'fake': 'fake_mode'
        }
        with mock.patch.object(self.log_driver.agent_api,
                               'get_router_hosting_port',
                               return_value=fake_router):
            intf_name = self.log_driver._get_intf_name(fake_port_id)
            expected_name = 'qr-fake_router'
            self.assertEqual(expected_name, intf_name)

        # Test with dvr router
        self.log_driver.conf.agent_mode = 'dvr_snat'
        fake_router.router = {
            'distributed': 'fake_mode'
        }
        with mock.patch.object(self.log_driver.agent_api,
                               'get_router_hosting_port',
                               return_value=fake_router):
            intf_name = self.log_driver._get_intf_name(fake_port_id)
            expected_name = 'sg-fake_router'
            self.assertEqual(expected_name, intf_name)

        # Test with fip dev
        self.log_driver.conf.agent_mode = 'dvr_snat'
        fake_router.router = {
            'distributed': 'fake_mode'
        }
        fake_router.rtr_fip_connect = 'fake'
        self.log_driver.conf.agent_mode = 'fake'
        with mock.patch.object(self.log_driver.agent_api,
                               'get_router_hosting_port',
                               return_value=fake_router):
            intf_name = self.log_driver._get_intf_name(fake_port_id)
            expected_name = 'rfp-fake_route'
            self.assertEqual(expected_name, intf_name)

    def test_setup_chains(self):
        self.log_driver._add_nflog_rules_accepted = mock.Mock()
        self.log_driver._add_log_rules_dropped = mock.Mock()
        m_ipt_mgr = mock.Mock()
        m_fwg_port_log = mock.Mock()

        # Test with ALL event
        m_fwg_port_log.event = log_const.ALL_EVENT
        self.log_driver._setup_chains(m_ipt_mgr, m_fwg_port_log)

        self.log_driver._add_nflog_rules_accepted.\
            assert_called_once_with(m_ipt_mgr, m_fwg_port_log)
        self.log_driver._add_log_rules_dropped.\
            assert_called_once_with(m_ipt_mgr, m_fwg_port_log)

        # Test with ACCEPT event
        self.log_driver._add_nflog_rules_accepted.reset_mock()
        self.log_driver._add_log_rules_dropped.reset_mock()

        m_fwg_port_log.event = log_const.ACCEPT_EVENT
        self.log_driver._setup_chains(m_ipt_mgr, m_fwg_port_log)

        self.log_driver._add_nflog_rules_accepted.\
            assert_called_once_with(m_ipt_mgr, m_fwg_port_log)
        self.log_driver._add_log_rules_dropped.assert_not_called()

        # Test with DROP event
        self.log_driver._add_nflog_rules_accepted.reset_mock()
        self.log_driver._add_log_rules_dropped.reset_mock()

        m_fwg_port_log.event = log_const.DROP_EVENT
        self.log_driver._setup_chains(m_ipt_mgr, m_fwg_port_log)

        self.log_driver._add_nflog_rules_accepted.assert_not_called()
        self.log_driver._add_log_rules_dropped.\
            assert_called_once_with(m_ipt_mgr, m_fwg_port_log)

    def test_add_nflog_rules_accepted(self):
        ipt_mgr = mock.Mock()
        f_accept_prefix = log.LogPrefix(FAKE_PORT_ID, log_const.
                                        ACCEPT_EVENT,
                                        FAKE_PROJECT_ID)

        f_port_log = self._fake_port_log('fake_log_id',
                                         log_const.ACCEPT_EVENT,
                                         FAKE_PORT_ID)

        self.log_driver._add_rules_to_chain_v4v6 = mock.Mock()
        self.log_driver._get_ipt_mgr_by_port = mock.Mock(return_value=ipt_mgr)
        self.log_driver._get_intf_name = mock.Mock(return_value='fake_device')

        with mock.patch.object(self.log_driver, '_get_prefix',
                               side_effect=[f_accept_prefix, None]):

            # Test with prefix already added into prefixes_table
            self.log_driver._add_nflog_rules_accepted(ipt_mgr, f_port_log)
            self.log_driver._add_rules_to_chain_v4v6.assert_not_called()
            self.assertEqual(set(['fake_log_id']),
                             f_accept_prefix.log_object_refs)

            # Test with prefixes_tables does not include the prefix
            prefix = log.LogPrefix(FAKE_PORT_ID, log_const.
                                   ACCEPT_EVENT, FAKE_PROJECT_ID)
            with mock.patch.object(log, 'LogPrefix', return_value=prefix):
                self.log_driver._add_nflog_rules_accepted(ipt_mgr, f_port_log)
                v4_rules, v6_rules = self._fake_nflog_rule_v4v6('fake_device',
                                                                prefix.id)

                self.log_driver._add_rules_to_chain_v4v6.\
                    assert_called_once_with(ipt_mgr, 'accepted',
                                            v4_rules, v6_rules,
                                            wrap=True, top=True, tag=prefix.id)
                self.assertEqual(set(['fake_log_id']),
                                 prefix.log_object_refs)

    def test_add_nflog_rules_dropped(self):
        ipt_mgr = mock.Mock()
        f_drop_prefix = log.LogPrefix(FAKE_PORT_ID, log_const.
                                      DROP_EVENT,
                                      FAKE_PROJECT_ID)

        f_port_log = self._fake_port_log('fake_log_id',
                                         log_const.DROP_EVENT,
                                         FAKE_PORT_ID)

        self.log_driver._add_rules_to_chain_v4v6 = mock.Mock()
        self.log_driver._get_ipt_mgr_by_port = mock.Mock(return_value=ipt_mgr)
        self.log_driver._get_intf_name = mock.Mock(return_value='fake_device')

        with mock.patch.object(self.log_driver, '_get_prefix',
                               side_effect=[f_drop_prefix, None]):

            # Test with prefix already added into prefixes_table
            self.log_driver._add_log_rules_dropped(ipt_mgr, f_port_log)
            self.log_driver._add_rules_to_chain_v4v6.assert_not_called()
            self.assertEqual(set(['fake_log_id']),
                             f_drop_prefix.log_object_refs)

            # Test with prefixes_tables does not include the prefix
            prefix = log.LogPrefix(FAKE_PORT_ID, log_const.
                                   ACCEPT_EVENT, FAKE_PROJECT_ID)
            with mock.patch.object(log, 'LogPrefix', return_value=prefix):
                self.log_driver._add_log_rules_dropped(ipt_mgr, f_port_log)
                v4_rules, v6_rules = self._fake_nflog_rule_v4v6('fake_device',
                                                                prefix.id)

                calls = [
                    mock.call(ipt_mgr, 'dropped', v4_rules, v6_rules,
                              wrap=True, top=True, tag=prefix.id),
                    mock.call(ipt_mgr, 'rejected', v4_rules, v6_rules,
                              wrap=True, top=True, tag=prefix.id),
                ]
                self.log_driver._add_rules_to_chain_v4v6.\
                    assert_has_calls(calls)
                self.assertEqual(set(['fake_log_id']),
                                 prefix.log_object_refs)

    def _fake_port_log(self, log_id, event, port_id):
        f_log_info = {
            'event': event,
            'project_id': FAKE_PROJECT_ID,
            'id': log_id
        }
        return log.FWGPortLog(port_id, f_log_info)

    def _fake_nflog_rule_v4v6(self, device, tag):
        v4_nflog_rule = ['-i %s -m limit --limit %s/s --limit-burst %s '
                         '-j NFLOG --nflog-prefix %s'
                         % (device, FAKE_RATE, FAKE_BURST, tag)]
        v4_nflog_rule += ['-o %s -m limit --limit %s/s --limit-burst %s '
                         '-j NFLOG --nflog-prefix %s'
                         % (device, FAKE_RATE, FAKE_BURST, tag)]
        v6_nflog_rule = ['-i %s -m limit --limit %s/s --limit-burst %s '
                         '-j NFLOG --nflog-prefix %s'
                         % (device, FAKE_RATE, FAKE_BURST, tag)]
        v6_nflog_rule += ['-o %s -m limit --limit %s/s --limit-burst %s '
                          '-j NFLOG --nflog-prefix %s'
                          % (device, FAKE_RATE, FAKE_BURST, tag)]
        return v4_nflog_rule, v6_nflog_rule

    def _fake_ipt_mgr_list(self, router_ids):
        f_ipt_mgrs = defaultdict(dict)

        for router_id in router_ids:
            f_port_id1 = router_id + '_port1'
            f_port_id2 = router_id + '_port2'
            ipt_mgr = mock.Mock()
            ipt_mgr.ns_name = 'ns_' + router_id
            f_ipt_mgrs[router_id][f_port_id1] = ipt_mgr
            f_ipt_mgrs[router_id][f_port_id2] = ipt_mgr

        return f_ipt_mgrs
