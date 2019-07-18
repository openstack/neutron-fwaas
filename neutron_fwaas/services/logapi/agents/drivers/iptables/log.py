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
import signal
import uuid

from neutron.agent.linux import utils
from neutron.services.logapi.agent import log_extension as log_ext
from neutron_lib import constants
from neutron_lib.services.logapi import constants as log_const
from oslo_config import cfg
from oslo_log import formatters
from oslo_log import handlers
from oslo_log import log as logging

from neutron_fwaas.privileged.netfilter_log import libnetfilter_log as libnflog

LOG = logging.getLogger(__name__)

UINT64_BITMASK = (1 << 64) - 1

MAX_INTF_NAME_LEN = 14
INTERNAL_DEV_PREFIX = 'qr-'
SNAT_INT_DEV_PREFIX = 'sg-'
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'

IPTABLES_DIRECTION_DEVICE = {
    constants.INGRESS_DIRECTION: 'i',
    constants.EGRESS_DIRECTION: 'o'
}


def setup_logging():

    log_file = cfg.CONF.network_log.local_output_log_base
    if log_file:
        from logging import handlers as watch_handler
        log_file_handler = watch_handler.WatchedFileHandler(log_file)
        log_file_handler.setLevel(
            logging.DEBUG if cfg.CONF.debug else logging.INFO)
        LOG.logger.addHandler(log_file_handler)
        log_file_handler.setFormatter(
            formatters.ContextFormatter(
                fmt=cfg.CONF.logging_default_format_string,
                datefmt=cfg.CONF.log_date_format))
    elif cfg.CONF.use_journal:
        journal_handler = handlers.OSJournalHandler()
        LOG.logger.addHandler(journal_handler)
    else:
        syslog_handler = handlers.OSSysLogHandler()
        LOG.logger.addHandler(syslog_handler)


class LogPrefix(object):
    """LogPrefix could be used as prefix in NFLOG rules
    Each of a couple (port_id, event) has its own LogPrefix object
    """

    def __init__(self, port_id, event, project_id):
        self.id = self._generate_prefix_id()
        self.port_id = port_id
        self.action = event
        # A list of log objects that referenced to this prefix
        self.log_object_refs = set()
        self.project_id = project_id

    def __eq__(self, other):
        return (self.id == other.id and
                self.action == other.action and
                self.port_id == other.port_id)

    def __hash__(self):
        return hash(self.id)

    def _generate_prefix_id(self):
        return uuid.uuid4().int & UINT64_BITMASK

    def add_log_obj_ref(self, log_id):
        self.log_object_refs.add(log_id)

    def remove_log_obj_ref(self, log_id):
        self.log_object_refs.discard(log_id)

    @property
    def is_empty(self):
        return not self.log_object_refs


class FWGPortLog(object):
    """A firewall group port log per log_object"""

    def __init__(self, port_id, log_info):
        self.port_id = port_id
        self.log_id = log_info['id']
        self.project_id = log_info['project_id']
        self.event = log_info['event']


class IptablesLoggingDriver(log_ext.LoggingDriver):

    SUPPORTED_LOGGING_TYPES = ['firewall_group']

    def __init__(self, agent_api):
        self.agent_api = agent_api
        self.conf = cfg.CONF
        self.rate_limit = self.conf.network_log.rate_limit
        if self.rate_limit:
            self.burst_limit = self.conf.network_log.burst_limit
        self.ipt_mgr_list = defaultdict(dict)
        # A list of fwg port logs that are being logged
        self.fwg_port_logs = defaultdict(set)
        # A list of prefixes that are being used in iptables
        self.prefixes_table = {}
        self.cleanup_table = defaultdict(set)
        # Handle NFLOG processing
        self.nflog_proc_map = {}
        # A list of unused ports
        self.unused_port_ids = set()

    def initialize(self, resource_rpc, **kwargs):
        self.resource_rpc = resource_rpc
        setup_logging()
        self.log_app = libnflog.NFLogApp()
        self.log_app.register_packet_handler(self.log_packet)
        self.log_app.start()

    def log_packet(self, ev):
        prefix = ev['prefix']
        pkt = ev['msg']
        prefix_entry = self._get_prefix_by_id(prefix)
        if prefix_entry:
            logs_id = [str(id) for id in prefix_entry.log_object_refs]
            LOG.info("action=%s, project_id=%s, log_resource_ids=%s, port=%s, "
                     "pkt=%s", prefix_entry.action,
                     prefix_entry.project_id, logs_id,
                     prefix_entry.port_id, pkt)
        else:
            LOG.warning("Unknown cookie packet_in pkt=%s", pkt)
        return 0

    def _get_prefix(self, port_id, action):
        if port_id in self.prefixes_table:
            for prefix in self.prefixes_table[port_id]:
                if prefix.action == action:
                    return prefix
        return None

    def _get_prefix_by_id(self, prefix_id):
        for port, prefixes in self.prefixes_table.items():
            for prefix in prefixes:
                if str(prefix.id) == str(prefix_id):
                    return prefix
        return None

    def _add_to_cleanup(self, port_id, prefix_id):
        if port_id not in self.cleanup_table:
            self.cleanup_table[port_id] = set()
        self.cleanup_table[port_id].add(prefix_id)

    def _add_to_prefixes_table(self, port_id, prefix):
        if port_id not in self.prefixes_table:
            self.prefixes_table[port_id] = []
        self.prefixes_table[port_id].append(prefix)

    def _cleanup_nflog_process(self, router_info):
        LOG.debug("Delete router_info %s", router_info)
        if router_info in self.nflog_proc_map:
            pid = self.nflog_proc_map[router_info]
            try:
                # A process started by a root helper will be running as
                # root and need to be killed via the same helper.
                LOG.debug('Trying to kill NFLOG process %d', pid)
                utils.kill_process(pid, signal.SIGKILL, run_as_root=True)
                del self.nflog_proc_map[router_info]
            except Exception:
                LOG.exception(
                    'An error occurred while killing process %d', pid)

    def _cleanup_prefix_by_router(self, router_id):

        ipt_mgr_per_port = set()
        for port_id in self.ipt_mgr_list[router_id]:
            ipt_mgr = self.ipt_mgr_list[router_id][port_id]
            ipt_mgr_per_port.add(ipt_mgr)
            # Cleanup prefix
            if port_id in self.prefixes_table:
                for prefix in self.prefixes_table[port_id]:
                    self._add_to_cleanup(port_id, prefix.id)
                del self.prefixes_table[port_id]
                self.unused_port_ids.add(port_id)
        return ipt_mgr_per_port

    def _cleanup_unused_ipt_mgrs(self):

        need_cleanup = set()
        for port_id in self.unused_port_ids:
            for router_id in self.ipt_mgr_list:
                if port_id in self.ipt_mgr_list[router_id]:
                    del self.ipt_mgr_list[router_id][port_id]
                if not self.ipt_mgr_list[router_id]:
                    need_cleanup.add(router_id)

        for router_id in need_cleanup:
            del self.ipt_mgr_list[router_id]

        self.unused_port_ids.clear()

    def start_logging(self, context, **kwargs):
        LOG.debug("Start logging: %s", str(kwargs))

        for resource_type in self.SUPPORTED_LOGGING_TYPES:
            router_info = kwargs.get('router_info')
            if router_info:
                # Handle router updated or L3 agent restart
                router_id = router_info.router_id
                internal_ports = router_info.internal_ports
                self._create_firewall_group_log(context, resource_type,
                                                ports=internal_ports,
                                                router_id=router_id)

                # Start libnetfilter_log after router starting up
                pid = libnflog.run_nflog(router_info.ns_name)
                LOG.debug("NFLOG process ID %s for router %s has started",
                        pid, router_info.router_id)
                self.nflog_proc_map[router_id] = pid
            else:
                # Handle the log request
                self._create_firewall_group_log(context, resource_type,
                                                **kwargs)

    def stop_logging(self, context, **kwargs):
        LOG.debug("Stop logging: %s", str(kwargs))

        # Delete router
        router_info = kwargs.get('router_info')
        if router_info:
            self._cleanup_nflog_process(router_info)

        if kwargs.get('log_resources'):
            # Handle incoming log request
            self._delete_firewall_group_log(context, **kwargs)

    def _create_firewall_group_log(self, context, resource_type, **kwargs):
        ports = kwargs.get('ports')
        log_resources = kwargs.get('log_resources')
        applied_ipt_mgrs = set()
        logs_info = []

        port_ids = []
        # Get log objects from database via RPC
        if ports:
            port_ids = [port['id'] for port in ports]
            logs_info = self.resource_rpc. \
                get_sg_log_info_for_port(context, resource_type,
                                         port_id=port_ids)
        elif log_resources:
            logs_info = self.resource_rpc.\
                get_sg_log_info_for_log_resources(context, resource_type,
                                                  log_resources=log_resources)
        # Handle logs_info
        for log_info in logs_info:
            log_id = log_info['id']
            old_fwg_port_logs = self.fwg_port_logs.get(log_id, [])
            new_ports_log = log_info.get('ports_log')
            self.fwg_port_logs[log_id] = set()
            for port in new_ports_log:
                self._add_fwg_port_log(log_id, port, log_info)

            for port in old_fwg_port_logs:
                if port.port_id not in new_ports_log:
                    # Remove port not bound by log_id
                    self._cleanup_prefixes_table(port.port_id, log_id)

            for fwg_port_log in self.fwg_port_logs[log_id]:
                self._setup_chains(applied_ipt_mgrs, fwg_port_log)

        router_id = kwargs.get("router_id")
        if router_id:
            if not port_ids:
                ipt_mgrs = self._cleanup_prefix_by_router(router_id)
                applied_ipt_mgrs.update(ipt_mgrs)

            for port_id in port_ids:
                try:
                    ipt_mgr = self.ipt_mgr_list[router_id][port_id]
                    applied_ipt_mgrs.add(ipt_mgr)
                except KeyError:
                    pass

        # Clean up NFLOG rules
        self._cleanup_nflog_rules(applied_ipt_mgrs)

        # Apply NFLOG rules into iptables managers
        for ipt_mgr in applied_ipt_mgrs:
            LOG.debug('Apply NFLOG rules in namespace %s', ipt_mgr.namespace)
            ipt_mgr.defer_apply_off()

        # Clean up unused iptables managers from ports
        self._cleanup_unused_ipt_mgrs()

    def _cleanup_prefixes_table(self, port_id, log_id):

        # Each a port has at most 2 prefix
        for index in [1, 0]:
            try:
                prefix = self.prefixes_table[port_id][index]
                prefix.remove_log_obj_ref(log_id)
                if prefix.is_empty:
                    self._add_to_cleanup(port_id, prefix.id)
                    self.prefixes_table[port_id].remove(prefix)
            except Exception:
                pass

        if port_id in self.prefixes_table:
            if not self.prefixes_table[port_id]:
                del self.prefixes_table[port_id]
                self.unused_port_ids.add(port_id)

    def _cleanup_nflog_rules(self, applied_ipt_mgrs):
        for port_id, prefix_ids in self.cleanup_table.items():
            ipt_mgr = self._get_ipt_mgr_by_port(port_id)
            for prefix_id in prefix_ids:
                self._clear_rules_from_tag_v4v6(ipt_mgr, tag=prefix_id)
            applied_ipt_mgrs.add(ipt_mgr)
        self.cleanup_table.clear()

    def _delete_firewall_group_log(self, context, **kwargs):
        log_resources = kwargs.get('log_resources')
        applied_ipt_mgrs = set()

        for log_resource in log_resources:
            log_id = log_resource.get('id')
            fwg_port_logs = self.fwg_port_logs[log_id]
            for port in fwg_port_logs:
                self._cleanup_prefixes_table(port.port_id, log_id)
            del self.fwg_port_logs[log_id]

        # Clean NFLOG rules:
        self._cleanup_nflog_rules(applied_ipt_mgrs)

        # Apply NFLOG rules into iptables managers
        for ipt_mgr in applied_ipt_mgrs:
            ipt_mgr.defer_apply_off()

        # Clean up unused iptables managers
        self._cleanup_unused_ipt_mgrs()

    def _get_if_prefix(self, agent_mode, router):
        """Get the if prefix from router"""
        if not router.router.get('distributed'):
            return INTERNAL_DEV_PREFIX

        if agent_mode == 'dvr_snat':
            return SNAT_INT_DEV_PREFIX

        if router.rtr_fip_connect:
            return ROUTER_2_FIP_DEV_PREFIX

    def _get_intf_name(self, port_id):
        agent_mode = self.conf.agent_mode
        router = self.agent_api.get_router_hosting_port(port_id)
        if_prefix = self._get_if_prefix(agent_mode, router)
        return (if_prefix + port_id)[:constants.LINUX_DEV_LEN]

    def _get_ipt_mgr_by_port(self, port_id):

        router = self.agent_api.get_router_hosting_port(port_id)
        if router:
            try:
                ipt_mgr = self.ipt_mgr_list[router.router_id][port_id]
                return ipt_mgr
            except KeyError:
                pass

            ipt_mgr = router.iptables_manager
            self.ipt_mgr_list[router.router_id][port_id] = ipt_mgr
            return ipt_mgr

        for router_id in self.ipt_mgr_list:
            if port_id in self.ipt_mgr_list[router_id]:
                return self.ipt_mgr_list[router_id][port_id]

    def _setup_chains(self, applied_ipt_mgrs, fwg_port_log):
        # Add NFLOG rules by log event
        event = fwg_port_log.event
        if event in [log_const.ACCEPT_EVENT, log_const.ALL_EVENT]:
            self._add_nflog_rules_accepted(applied_ipt_mgrs, fwg_port_log)
        if event in [log_const.DROP_EVENT, log_const.ALL_EVENT]:
            self._add_log_rules_dropped(applied_ipt_mgrs, fwg_port_log)

    def _add_nflog_rules_accepted(self, applied_ipt_mgrs, fwg_port_log):
        """Add NFLOG rules to the accepted chain into iptables"""
        action = log_const.ACCEPT_EVENT
        port_id = fwg_port_log.port_id
        prefix = self._get_prefix(port_id, action)
        if not prefix:
            # Generate a new prefix from port and action
            project_id = fwg_port_log.project_id
            prefix = LogPrefix(port_id, action, project_id)
            self._add_to_prefixes_table(port_id, prefix)

            # Get iptables manager from router port
            ipt_mgr = self._get_ipt_mgr_by_port(port_id)
            if ipt_mgr:
                applied_ipt_mgrs.add(ipt_mgr)

            device = self._get_intf_name(port_id)

            # Add the NFLOG rules to the dropped chain into iptables
            ipv4_rules, ipv6_rules = \
                self._generate_nflog_rules_v4v6(device, prefix=prefix.id)
            self._add_rules_to_chain_v4v6(ipt_mgr,
                                          'accepted', ipv4_rules, ipv6_rules,
                                          wrap=True, top=True, tag=prefix.id)

        prefix.add_log_obj_ref(fwg_port_log.log_id)

    def _add_log_rules_dropped(self, applied_ipt_mgrs, fwg_port_log):
        """Add NFLOG rules to the dropped chain into iptables"""

        action = log_const.DROP_EVENT
        port_id = fwg_port_log.port_id
        prefix = self._get_prefix(port_id, action)
        if not prefix:
            # Generate a new prefix from port and action
            project_id = fwg_port_log.project_id
            prefix = LogPrefix(port_id, action, project_id)
            self._add_to_prefixes_table(port_id, prefix)
            device = self._get_intf_name(port_id)

            # Get iptables manager from router port
            ipt_mgr = self._get_ipt_mgr_by_port(port_id)
            if ipt_mgr:
                applied_ipt_mgrs.add(ipt_mgr)

            # Add the NFLOG rules to the dropped chain into iptables
            ipv4_rules, ipv6_rules = \
                self._generate_nflog_rules_v4v6(device, prefix=prefix.id)
            self._add_rules_to_chain_v4v6(ipt_mgr,
                                          'dropped', ipv4_rules, ipv6_rules,
                                          wrap=True, top=True, tag=prefix.id)
            # Add the NFLOG rules to the rejected chain in iptables
            self._add_rules_to_chain_v4v6(ipt_mgr,
                                          'rejected', ipv4_rules, ipv6_rules,
                                          wrap=True, top=True, tag=prefix.id)
        prefix.add_log_obj_ref(fwg_port_log.log_id)

    def _add_rules_to_chain_v4v6(self, ipt_mgr, chain_name, v4_rules, v6_rules,
                                 wrap=False, comment=None,
                                 top=False, tag=None):
        """Add rules to filter table in iptables and ip6tables"""

        for rule in v4_rules:
            ipt_mgr.ipv4['filter'].add_rule(chain_name, rule, wrap=wrap,
                                            comment=comment, top=top, tag=tag)
        for rule in v6_rules:
            ipt_mgr.ipv6['filter'].add_rule(chain_name, rule, wrap=wrap,
                                            comment=comment, top=top, tag=tag)

    def _add_fwg_port_log(self, log_id, port_id, log_info):

        self.fwg_port_logs[log_id].add(FWGPortLog(port_id, log_info))

        # Add log ID into the corresponding LogPrefix object
        if log_info['event'] == log_const.ALL_EVENT:
            events = [log_const.ACCEPT_EVENT, log_const.DROP_EVENT]
        else:
            events = [log_info['event']]
        for event in events:
            prefix = self._get_prefix(port_id, event)
            if prefix:
                prefix.add_log_obj_ref(log_id)

    def _generate_nflog_rules_v4v6(self, device, prefix):
        iptables_rules = []
        added_rules = set()
        for direction in constants.VALID_DIRECTIONS:
            args = self._generate_iptables_args(direction, device, prefix)
            rule = ' '.join(args)
            if rule in added_rules:
                # Since these rules are already added to iptables,
                # so we ignore them here
                continue
            added_rules.add(rule)
            iptables_rules.append(rule)
        LOG.debug("iptables-nflog-rules %r", iptables_rules)
        return iptables_rules, iptables_rules

    def _generate_iptables_args(self, direction, device, prefix=None):

        direction_config = ['-%s %s' %
                  (IPTABLES_DIRECTION_DEVICE[direction], device)]
        match_rule = []
        if self.rate_limit:
            match_rule += ['-m', 'limit', '--limit', '%s/s' % self.rate_limit]
            if self.burst_limit:
                match_rule += ['--limit-burst %s' % self.burst_limit]
        target = ['-j', 'NFLOG']
        if prefix:
            target += ['--nflog-prefix', '%s' % prefix]

        args = direction_config + match_rule + target
        return args

    def _clear_rules_from_tag_v4v6(self, ipt_mgt, tag):
        """Remove rules from filter table in iptables and ip6tables"""
        ipt_mgt.ipv4['filter'].clear_rules_by_tag(tag)
        ipt_mgt.ipv6['filter'].clear_rules_by_tag(tag)
