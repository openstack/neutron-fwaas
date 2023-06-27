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

from unittest import mock

import time

from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.linux import utils as linux_utils
from neutron.tests.functional.agent.l3 import framework
from neutron_lib import constants
from neutron_lib import context as neutron_context
from neutron_lib.services.logapi import constants as log_const
from oslo_config import cfg
from oslo_log import log as logging

from neutron_fwaas.services.logapi.agents.drivers.iptables import log

LOG = logging.getLogger(__name__)

FAKE_LOG_ID = 'fake_log_id'
FAKE_PROJECT_ID = 'fake_project_id'
FAKE_RESOURCE_TYPE = 'firewall_group'

# Default chain name
ACCEPTED_CHAIN = 'accepted'
DROPPED_CHAIN = 'dropped'
REJECTED_CHAIN = 'rejected'

ACCEPT = 'ACCEPT'
DROP = 'DROP'
REJECT = 'REJECT'
ALL = 'ALL'

CHAIN_NAME_POSTFIX_MAP = {
    ACCEPT: ACCEPTED_CHAIN,
    DROP: DROPPED_CHAIN,
    REJECT: REJECTED_CHAIN
}

FWAAS_V2_LOG_OPTS = [
    cfg.StrOpt('extensions', default=['fwaas_v2', 'fwaas_v2_log']),
]

AGENT_MODE_OPTS = [
    cfg.StrOpt('agent_mode', default='legacy',
               choices=['legacy', 'dvr', 'dvr_snat', 'dvr_no_external']),
]


class FWLoggingTestBase(framework.L3AgentTestFramework):

    def setUp(self):
        super(FWLoggingTestBase, self).setUp()
        self.conf.register_opts(FWAAS_V2_LOG_OPTS, 'fwaas')
        self.conf.register_opts(AGENT_MODE_OPTS, group='DEFAULT')
        self._set_agent_mode(self.conf)
        self.if_prefix = 'qr-'

        self.context = neutron_context.get_admin_context()
        self.context.tenant_id = FAKE_PROJECT_ID
        self.resource_rpc = mock.patch(
            'neutron.services.logapi.rpc.agent.LoggingApiStub').start()
        # Initialize logging driver
        self.log_driver = self._initialize_iptables_log()
        # Prepare router_info
        self._prepare_router_info(n_ports=2)

    def _prepare_router_info(self, n_ports=0):
        router_data = self.generate_router_info(enable_ha=False,
                                                num_internal_ports=n_ports)

        self.router_info = self.manage_router(self.agent, router_data)
        self.log_driver.agent_api._router_info = {
            self.router_info.router_id: self.router_info
        }

    def _initialize_iptables_log(self):
        self.agent_api = l3_ext_api.L3AgentExtensionAPI({}, None)
        log_driver = log.IptablesLoggingDriver(self.agent_api)
        log_driver.initialize(self.resource_rpc)
        log_driver.conf = self.conf
        return log_driver

    def _refresh_logging_config(self, ipt_mgr):
        # Reset configuration for the next testing EVENT
        self.log_driver.ipt_mgr_list.clear()
        self.log_driver.fwg_port_logs.clear()
        self.log_driver.prefixes_table.clear()
        self.log_driver.cleanup_table.clear()
        self.log_driver.nflog_proc_map.clear()
        self.log_driver.unused_port_ids.clear()
        # Empty default chains
        self._empty_default_chains_v4v6(ipt_mgr=ipt_mgr)

    def _set_agent_mode(self, cfg, agent_mode='legacy'):
        cfg.agent_mode = agent_mode

    def _config_default_chains_v4v6(self, ipt_mgr):
        # Config default chains in iptables and ip6tables
        for action, chain in CHAIN_NAME_POSTFIX_MAP.items():
            v4rules_in_chain = \
                ipt_mgr.get_chain("filter", chain, ip_version=4)
            if not v4rules_in_chain:
                ipt_mgr.ipv4['filter'].add_chain(chain)
                ipt_mgr.ipv4['filter'].add_rule(chain, '-j %s' % action)

            v6rules_in_chain = \
                ipt_mgr.get_chain("filter", chain, ip_version=6)
            if not v6rules_in_chain:
                ipt_mgr.ipv6['filter'].add_chain(chain)
                ipt_mgr.ipv6['filter'].add_rule(chain, '-j %s' % action)

    def _empty_default_chains_v4v6(self, ipt_mgr):
        # Empty default chains in iptables and ip6tables
        for action, chain in CHAIN_NAME_POSTFIX_MAP.items():
            ipt_mgr.ipv4['filter'].empty_chain(chain=chain)
            ipt_mgr.ipv6['filter'].empty_chain(chain=chain)

    def _fake_log_resource(self, tenant_id, resource_id=None,
                           target_id=None, event='ALL', enabled=True):
        log_resource = {
            'id': FAKE_LOG_ID,
            'name': 'fake_log_name',
            'resource_type': FAKE_RESOURCE_TYPE,
            'project_id': tenant_id,
            'event': event,
            'enabled': True}
        if resource_id:
            log_resource['resource_id'] = resource_id
        if target_id:
            log_resource['target_id'] = target_id
        if not enabled:
            log_resource['enabled'] = enabled
        return log_resource

    def _fake_log_info(self, log_id, port_ids, event='ALL'):
        return {
            'event': event,
            'id': log_id,
            'project_id': FAKE_PROJECT_ID,
            'ports_log': port_ids
        }

    def _get_expected_nflog_rule(self, wrap_name, if_prefix, logs_info):
        # Generate an expected NFLOG rules from given log_info
        rules = set()
        limit = 'limit --limit %s/sec --limit-burst %s' % \
                (self.log_driver.rate_limit, self.log_driver.burst_limit)

        accept_chain = wrap_name + '-' + ACCEPTED_CHAIN
        drop_chain = wrap_name + '-' + DROPPED_CHAIN
        reject_chain = wrap_name + '-' + REJECTED_CHAIN
        for log_info in logs_info:
            event = log_info['event']
            ports_log = log_info['ports_log']

            for port_id in ports_log:
                device = (if_prefix + port_id)[:constants.LINUX_DEV_LEN]
                if event in [ACCEPT, ALL]:
                    # Generate iptables rules for ACCEPT action
                    prefix = self._get_log_prefix(port_id, ACCEPT)
                    rules.add('-A %s -i %s -m %s -j NFLOG --nflog-prefix  %s'
                              % (accept_chain, device, limit, prefix.id))
                    rules.add('-A %s -o %s -m %s -j NFLOG --nflog-prefix  %s'
                              % (accept_chain, device, limit, prefix.id))

                if event in [DROP, ALL]:
                    # Generate iptables rules for DROP action
                    prefix = self._get_log_prefix(port_id, DROP)
                    rules.add('-A %s -i %s -m %s -j NFLOG --nflog-prefix  %s'
                              % (drop_chain, device, limit, prefix.id))
                    rules.add('-A %s -o %s -m %s -j NFLOG --nflog-prefix  %s'
                              % (drop_chain, device, limit, prefix.id))

                    # Generate iptables rules for REJECT action
                    rules.add('-A %s -i %s -m %s -j NFLOG --nflog-prefix  %s'
                              % (reject_chain, device, limit, prefix.id))
                    rules.add('-A %s -o %s -m %s -j NFLOG --nflog-prefix  %s'
                              % (reject_chain, device, limit, prefix.id))
        return rules

    def _get_log_prefix(self, port_id, action):
        prefix_table = self.log_driver.prefixes_table
        if port_id in prefix_table:
            for prefix in prefix_table[port_id]:
                if prefix.action == action:
                    return prefix
        return None

    def _get_nflog_entries(self, namespace, table='iptables', chain_name=None):
        # Get NFLOG entries from iptables and ip6tables
        exec_cmd = ['ip', 'netns', 'exec', namespace, table, '-S']
        if chain_name:
            exec_cmd += [chain_name]
        while True:
            try:
                output = linux_utils.execute(exec_cmd,
                                             run_as_root=True,
                                             check_exit_code=True,
                                             extra_ok_codes=[1],
                                             privsep_exec=True)
                nflog_rules = [rule for rule in output.splitlines()
                               if 'NFLOG' in rule]
                return nflog_rules
            except RuntimeError:
                time.sleep(1)

    def assert_logging_results(self, ipt_mgr, log_info):
        # Comparing between expected NFLOG rules and NFLOG rules from iptables
        v4_rules = v6_rules = self._get_expected_nflog_rule(
            ipt_mgr.wrap_name, self.if_prefix, log_info)

        v4_actual = self._get_nflog_entries(ipt_mgr.namespace,
                                            table='iptables')
        v6_actual = self._get_nflog_entries(ipt_mgr.namespace,
                                            table='ip6tables')

        self.assertEqual(sorted(v4_rules), sorted(v4_actual))
        self.assertEqual(sorted(v6_rules), sorted(v6_actual))

    def run_start_logging(self, ipt_mgr, log_info, **kwargs):
        # Run start logging function with a give log_info
        router_info = kwargs.get('router_info')
        log_resources = kwargs.get('log_resources')

        self._config_default_chains_v4v6(ipt_mgr)
        if router_info:
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_port',
                                   return_value=log_info):
                self.log_driver.start_logging(self.context,
                                              router_info=router_info)
        elif log_resources:
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_log_resources',
                                   return_value=log_info):
                self.log_driver.start_logging(self.context,
                                              log_resources=log_resources)


class FWLoggingTestCase(FWLoggingTestBase):

    def test_start_logging_when_l3_starting(self):
        # Get router information
        ipt_mgr = self.router_info.iptables_manager
        port_ids = [port['id'] for port in self.router_info.internal_ports]

        for event in log_const.LOG_EVENTS:
            # Test start_logging with single log resource
            f_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            self.run_start_logging(ipt_mgr,
                                   log_info=f_log_info,
                                   router_info=self.router_info)

            # Test start_logging with multiple log resources
            f_log_info = [
                self._fake_log_info(log_id='fake_log_id_1',
                                    port_ids=[port_ids[0]],
                                    event=event),
                self._fake_log_info(log_id='fake_log_id_2',
                                    port_ids=[port_ids[1]],
                                    event=event)
            ]
            self.run_start_logging(ipt_mgr,
                                   log_info=f_log_info,
                                   router_info=self.router_info)

            self.assert_logging_results(ipt_mgr, f_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_start_logging_when_create_log(self):
        # Get router information
        ipt_mgr = self.router_info.iptables_manager
        port_ids = [port['id'] for port in self.router_info.internal_ports]

        for event in log_const.LOG_EVENTS:
            log_resources = [self._fake_log_resource(FAKE_PROJECT_ID,
                                                     event=event)]
            f_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            self.run_start_logging(ipt_mgr,
                                   log_info=f_log_info,
                                   log_resources=log_resources)

            self.assert_logging_results(ipt_mgr, f_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_start_logging_when_add_router_port(self):
        ipt_mgr = self.router_info.iptables_manager

        for event in log_const.LOG_EVENTS:
            port_ids = [port['id'] for port in self.router_info.internal_ports]

            # Making log_info when there is only one port
            added_port_id = port_ids.pop()
            initial_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            # Make log_info with new adding port
            port_ids.append(added_port_id)
            add_port_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]

            self._config_default_chains_v4v6(ipt_mgr)
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_port',
                                   side_effect=[initial_log_info,
                                                add_port_log_info]):
                # Start logging with a single port as normal to get initial
                # NFLOG rules into iptables
                self.log_driver.start_logging(self.context,
                                              router_info=self.router_info)
                # Start logging with the new port
                self.log_driver.start_logging(self.context,
                                              router_info=self.router_info)

            self.assert_logging_results(ipt_mgr, add_port_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_start_logging_when_remove_port(self):
        ipt_mgr = self.router_info.iptables_manager

        for event in log_const.LOG_EVENTS:
            port_ids = [port['id'] for port in self.router_info.internal_ports]

            # Making log_info when there are two ports on router
            initial_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            # Make log_info when a port is removed from router
            port_ids.pop()
            remove_port_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]

            self._config_default_chains_v4v6(ipt_mgr)
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_port',
                                   side_effect=[initial_log_info,
                                                remove_port_log_info]):
                # Start logging with a single port as normal to get initial
                # NFLOG rules into iptables
                self.log_driver.start_logging(self.context,
                                              router_info=self.router_info)
                # Start logging with the new port
                self.log_driver.start_logging(self.context,
                                              router_info=self.router_info)

            self.assert_logging_results(ipt_mgr, remove_port_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_start_logging_when_attach_port_to_fwg(self):
        ipt_mgr = self.router_info.iptables_manager

        for event in log_const.LOG_EVENTS:
            port_ids = [port['id'] for port in self.router_info.internal_ports]

            # Making log_info when there is only one port
            attached_port_id = port_ids.pop()
            initial_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            # Make log_info with a new port that attached to fwg
            port_ids.append(attached_port_id)

            attached_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            log_resources = [
                self._fake_log_resource(FAKE_PROJECT_ID,
                                        resource_id=attached_port_id,
                                        event=event)
            ]

            self._config_default_chains_v4v6(ipt_mgr)
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_port',
                                   return_value=initial_log_info):
                with mock.patch.object(self.resource_rpc,
                                       'get_sg_log_info_for_log_resources',
                                       return_value=attached_log_info):
                    # Start logging with a single port as normal to get initial
                    # NFLOG rules into iptables
                    self.log_driver.start_logging(self.context,
                                                  router_info=self.router_info)
                    # Start logging with the new port attach to fwg
                    self.log_driver.start_logging(self.context,
                                                  log_resources=log_resources)

            self.assert_logging_results(ipt_mgr, attached_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_start_logging_when_detach_port_from_fwg(self):
        ipt_mgr = self.router_info.iptables_manager

        for event in log_const.LOG_EVENTS:
            port_ids = [port['id'] for port in self.router_info.internal_ports]

            # Making log_info when there are two ports attached to fwg
            initial_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            # Make log_info when a port is detached from fwg
            detached_port_id = port_ids.pop()
            detached_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=event)
            ]
            log_resources = [
                self._fake_log_resource(FAKE_PROJECT_ID,
                                        resource_id=detached_port_id,
                                        event=event)
            ]

            self._config_default_chains_v4v6(ipt_mgr)
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_port',
                                   return_value=initial_log_info):
                with mock.patch.object(self.resource_rpc,
                                       'get_sg_log_info_for_log_resources',
                                       return_value=detached_log_info):
                    # Start logging with a single port as normal to get initial
                    # NFLOG rules into iptables
                    self.log_driver.start_logging(self.context,
                                                  router_info=self.router_info)

                    # Start logging with the new port attach to fwg
                    self.log_driver.start_logging(self.context,
                                                  log_resources=log_resources)

            self.assert_logging_results(ipt_mgr, detached_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_start_logging_when_enable_router(self):
        ipt_mgr = self.router_info.iptables_manager
        port_ids = [port['id'] for port in self.router_info.internal_ports]
        for event in log_const.LOG_EVENTS:
            # Log info to initialize NFLOG rules
            f_log_info = [
                self._fake_log_info(log_id=FAKE_LOG_ID,
                                    port_ids=port_ids,
                                    event=ALL)
            ]
            # Initialize NFLOG rules with start_logging
            self.run_start_logging(ipt_mgr,
                                   log_info=f_log_info,
                                   router_info=self.router_info)
            # Fake disable router by running stop_logging with router_info
            self.log_driver.stop_logging(
                self.context, router_info=self.router_info.router_id)
            # Fake enable router by running start_logging with router_info
            self.log_driver.start_logging(self.context,
                                          router_info=self.router_info)

            self.assert_logging_results(ipt_mgr, f_log_info)
            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_stop_logging_when_delete_log(self):
        ipt_mgr = self.router_info.iptables_manager

        for event in log_const.LOG_EVENTS:
            port_ids = [port['id'] for port in self.router_info.internal_ports]

            # Initialize log_info to start logging
            log_info_1 = self._fake_log_info(log_id='fake_log_id_1',
                                             port_ids=port_ids,
                                             event=event)
            log_info_2 = self._fake_log_info(log_id='fake_log_id_2',
                                             port_ids=[port_ids[0]],
                                             event=event)
            initial_log_info = [
                log_info_1,
                log_info_2
            ]

            self._config_default_chains_v4v6(ipt_mgr)
            with mock.patch.object(self.resource_rpc,
                                   'get_sg_log_info_for_port',
                                   return_value=initial_log_info):
                # Start logging to get initial NFLOG rules
                self.log_driver.start_logging(self.context,
                                              router_info=self.router_info)

                # Stop logging by deleting fake_log_id_1
                deleted_log_1 = [{'id': 'fake_log_id_1'}]
                self.log_driver.stop_logging(self.context,
                                             log_resources=deleted_log_1)
                self.assert_logging_results(ipt_mgr, [log_info_2])

                # Stop logging by deleting fake_log_id_2
                deleted_log_2 = [{'id': 'fake_log_id_2'}]
                self.log_driver.stop_logging(self.context,
                                             log_resources=deleted_log_2)
                self.assert_logging_results(ipt_mgr, [])

            self._refresh_logging_config(ipt_mgr=ipt_mgr)

    def test_stop_logging_when_delete_log_with_event_combination(self):
        ipt_mgr = self.router_info.iptables_manager

        port_ids = [port['id'] for port in self.router_info.internal_ports]

        # Initial log_info to start logging
        log_info_1 = self._fake_log_info(log_id='accept_log_id',
                                         port_ids=port_ids,
                                         event=ACCEPT)
        log_info_2 = self._fake_log_info(log_id='all_log_id',
                                         port_ids=[port_ids[0]],
                                         event=ALL)
        initial_log_info = [
            log_info_1,
            log_info_2
        ]

        self._config_default_chains_v4v6(ipt_mgr)
        with mock.patch.object(self.resource_rpc,
                               'get_sg_log_info_for_port',
                               return_value=initial_log_info):
            # Start logging to get initial NFLOG rules
            self.log_driver.start_logging(self.context,
                                          router_info=self.router_info)

            # Stop logging by deleting accept_log_id
            accepted_log = [{'id': 'accept_log_id'}]
            self.log_driver.stop_logging(self.context,
                                         log_resources=accepted_log)
            self.assert_logging_results(ipt_mgr, [log_info_2])

            # Stop logging by deleting all_log_id
            all_log = [{'id': 'all_log_id'}]
            self.log_driver.stop_logging(self.context,
                                         log_resources=all_log)
            self.assert_logging_results(ipt_mgr, [])
