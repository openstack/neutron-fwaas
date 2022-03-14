# Copyright 2013 Dell Inc.
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

from neutron.agent.linux import iptables_manager
from neutron.common import utils
from neutron_lib import constants
from neutron_lib.exceptions import firewall_v1 as f_exc
from oslo_log import log as logging

from neutron_fwaas.common import fwaas_constants as f_const
from neutron_fwaas.services.firewall.service_drivers.agents.drivers import\
    conntrack_base
from neutron_fwaas.services.firewall.service_drivers.agents.drivers import\
    fwaas_base


LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas iptables driver'
FWAAS_DEFAULT_CHAIN = 'fwaas-default-policy'

FWAAS_TO_IPTABLE_ACTION_MAP = {'allow': 'ACCEPT',
                               'deny': 'DROP',
                               'reject': 'REJECT'}

CHAIN_NAME_PREFIX = {constants.INGRESS_DIRECTION: 'i',
                     constants.EGRESS_DIRECTION: 'o'}

""" Firewall rules are applied on internal-interfaces of Neutron router.
    The packets ingressing tenant's network will be on the output
    direction on internal-interfaces.
"""
IPTABLES_DIR = {constants.INGRESS_DIRECTION: '-o',
                constants.EGRESS_DIRECTION: '-i'}
IPV4 = 'ipv4'
IPV6 = 'ipv6'
IP_VER_TAG = {IPV4: 'v4',
              IPV6: 'v6'}

INTERNAL_DEV_PREFIX = 'qr-'
SNAT_INT_DEV_PREFIX = 'sg-'
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'


class IptablesFwaasDriver(fwaas_base.FwaasDriverBase):
    """IPTables driver for Firewall As A Service."""

    def __init__(self):
        LOG.debug("Initializing fwaas iptables driver")
        self.pre_firewall = None
        self.conntrack = conntrack_base.load_and_init_conntrack_driver()

    def create_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug('Creating firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': firewall['id'], 'tid': firewall['tenant_id']})
        try:
            if firewall['admin_state_up']:
                self._setup_firewall(agent_mode, apply_list, firewall)
                self._remove_conntrack_new_firewall(agent_mode,
                                                    apply_list, firewall)
                self.pre_firewall = dict(firewall)
            else:
                self.apply_default_policy(agent_mode, apply_list, firewall)
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Fwaas generic exception
            LOG.exception("Failed to create firewall: %s", firewall['id'])
            raise f_exc.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    def _get_ipt_mgrs_with_if_prefix(self, agent_mode, router_info):
        """Gets the iptables manager along with the if prefix to apply rules.

        With DVR we can have differing namespaces depending on which agent
        (on Network or Compute node). Also, there is an associated i/f for
        each namespace. The iptables on the relevant namespace and matching
        i/f are provided. On the Network node we could have both the snat
        namespace and a fip so this is provided back as a list - so in that
        scenario rules can be applied on both.
        """
        if not router_info.router.get('distributed'):
            return [{'ipt': router_info.iptables_manager,
                     'if_prefix': INTERNAL_DEV_PREFIX}]
        ipt_mgrs = []
        # TODO(sridar): refactor to get strings to a common location.
        if agent_mode == 'dvr_snat':
            if router_info.snat_iptables_manager:
                ipt_mgrs.append({'ipt': router_info.snat_iptables_manager,
                                 'if_prefix': SNAT_INT_DEV_PREFIX})
        if router_info.rtr_fip_connect:
            # handle the fip case on n/w or compute node.
            ipt_mgrs.append({'ipt': router_info.iptables_manager,
                             'if_prefix': ROUTER_2_FIP_DEV_PREFIX})
        return ipt_mgrs

    def delete_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug('Deleting firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': firewall['id'], 'tid': firewall['tenant_id']})
        fwid = firewall['id']
        try:
            for router_info in apply_list:
                ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                    agent_mode, router_info)
                for ipt_if_prefix in ipt_if_prefix_list:
                    ipt_mgr = ipt_if_prefix['ipt']
                    self._remove_chains(fwid, ipt_mgr)
                    self._remove_default_chains(ipt_mgr)
                    # apply the changes immediately (no defer in firewall path)
                    ipt_mgr.defer_apply_off()
            self.pre_firewall = None
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Fwaas generic exception
            LOG.exception("Failed to delete firewall: %s", fwid)
            raise f_exc.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    def update_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug('Updating firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': firewall['id'], 'tid': firewall['tenant_id']})
        try:
            if firewall['admin_state_up']:
                self._setup_firewall(agent_mode, apply_list, firewall)
                if self.pre_firewall:
                    self._remove_conntrack_updated_firewall(agent_mode,
                                    apply_list, self.pre_firewall, firewall)
                else:
                    self._remove_conntrack_new_firewall(agent_mode,
                                                    apply_list, firewall)
            else:
                self.apply_default_policy(agent_mode, apply_list, firewall)
            self.pre_firewall = dict(firewall)
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Fwaas generic exception
            LOG.exception("Failed to update firewall: %s", firewall['id'])
            raise f_exc.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    def apply_default_policy(self, agent_mode, apply_list, firewall):
        LOG.debug('Applying firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': firewall['id'], 'tid': firewall['tenant_id']})
        fwid = firewall['id']
        try:
            for router_info in apply_list:
                ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                    agent_mode, router_info)
                for ipt_if_prefix in ipt_if_prefix_list:
                    # the following only updates local memory; no hole in FW
                    ipt_mgr = ipt_if_prefix['ipt']
                    self._remove_chains(fwid, ipt_mgr)
                    self._remove_default_chains(ipt_mgr)

                    # create default 'DROP ALL' policy chain
                    self._add_default_policy_chain_v4v6(ipt_mgr)
                    self._enable_policy_chain(fwid, ipt_if_prefix)

                    # apply the changes immediately (no defer in firewall path)
                    ipt_mgr.defer_apply_off()
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Fwaas generic exception
            LOG.exception(
                "Failed to apply default policy on firewall: %s", fwid)
            raise f_exc.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    def _setup_firewall(self, agent_mode, apply_list, firewall):
        fwid = firewall['id']
        for router_info in apply_list:
            ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                agent_mode, router_info)
            for ipt_if_prefix in ipt_if_prefix_list:
                ipt_mgr = ipt_if_prefix['ipt']
                # the following only updates local memory; no hole in FW
                self._remove_chains(fwid, ipt_mgr)
                self._remove_default_chains(ipt_mgr)

                # create default 'DROP ALL' policy chain
                self._add_default_policy_chain_v4v6(ipt_mgr)
                #create chain based on configured policy
                self._setup_chains(firewall, ipt_if_prefix)

                # apply the changes immediately (no defer in firewall path)
                ipt_mgr.defer_apply_off()

    def _get_chain_name(self, fwid, ver, direction):
        return '%s%s%s' % (CHAIN_NAME_PREFIX[direction],
                           IP_VER_TAG[ver],
                           fwid)

    def _setup_chains(self, firewall, ipt_if_prefix):
        """Create Fwaas chain using the rules in the policy
        """
        fw_rules_list = firewall['firewall_rule_list']
        fwid = firewall['id']
        ipt_mgr = ipt_if_prefix['ipt']

        #default rules for invalid packets and established sessions
        invalid_rule = self._drop_invalid_packets_rule()
        est_rule = self._allow_established_rule()

        for ver in [IPV4, IPV6]:
            if ver == IPV4:
                table = ipt_mgr.ipv4['filter']
            else:
                table = ipt_mgr.ipv6['filter']
            ichain_name = self._get_chain_name(
                fwid, ver, constants.INGRESS_DIRECTION)
            ochain_name = self._get_chain_name(
                fwid, ver, constants.EGRESS_DIRECTION)
            for name in [ichain_name, ochain_name]:
                table.add_chain(name)
                table.add_rule(name, invalid_rule)
                table.add_rule(name, est_rule)

        for rule in fw_rules_list:
            if not rule['enabled']:
                continue
            iptbl_rule = self._convert_fwaas_to_iptables_rule(rule)
            if rule['ip_version'] == 4:
                ver = IPV4
                table = ipt_mgr.ipv4['filter']
            else:
                ver = IPV6
                table = ipt_mgr.ipv6['filter']
            ichain_name = self._get_chain_name(
                fwid, ver, constants.INGRESS_DIRECTION)
            ochain_name = self._get_chain_name(
                fwid, ver, constants.EGRESS_DIRECTION)
            table.add_rule(ichain_name, iptbl_rule)
            table.add_rule(ochain_name, iptbl_rule)
        self._enable_policy_chain(fwid, ipt_if_prefix)

    def _find_changed_rules(self, pre_firewall, firewall):
        """Find the rules changed between the current firewall
        and the updating rule
        """
        changed_rules = []
        fw_rules_list = firewall[f_const.FIREWALL_RULE_LIST]
        pre_fw_rules_list = pre_firewall[f_const.FIREWALL_RULE_LIST]
        for pre_fw_rule in pre_fw_rules_list:
            for fw_rule in fw_rules_list:
                if (pre_fw_rule.get('id') == fw_rule.get('id') and
                    pre_fw_rule != fw_rule):
                    changed_rules.append(pre_fw_rule)
                    changed_rules.append(fw_rule)
        return changed_rules

    def _find_removed_rules(self, pre_firewall, firewall):
        fw_rules_list = firewall[f_const.FIREWALL_RULE_LIST]
        pre_fw_rules_list = pre_firewall[f_const.FIREWALL_RULE_LIST]
        fw_rule_ids = [fw_rule.get('id') for fw_rule in fw_rules_list]
        removed_rules = [pre_fw_rule for pre_fw_rule in
            pre_fw_rules_list if pre_fw_rule.get('id') not in fw_rule_ids]
        return removed_rules

    def _find_new_rules(self, pre_firewall, firewall):
        return self._find_removed_rules(firewall, pre_firewall)

    def _remove_conntrack_new_firewall(self, agent_mode, apply_list, firewall):
        """Remove conntrack when create new firewall"""
        routers_list = list(set(apply_list))
        for router_info in routers_list:
            ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                agent_mode, router_info)
            for ipt_if_prefix in ipt_if_prefix_list:
                ipt_mgr = ipt_if_prefix['ipt']
                self.conntrack.flush_entries(ipt_mgr.namespace)

    def _remove_conntrack_updated_firewall(self, agent_mode,
                                           apply_list, pre_firewall, firewall):
        """Remove conntrack when updated firewall"""
        router_list = list(set(apply_list))
        for router_info in router_list:
            ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                agent_mode, router_info)
            for ipt_if_prefix in ipt_if_prefix_list:
                ipt_mgr = ipt_if_prefix['ipt']
                ch_rules = self._find_changed_rules(pre_firewall,
                                                    firewall)
                i_rules = self._find_new_rules(pre_firewall, firewall)
                r_rules = self._find_removed_rules(pre_firewall, firewall)
                removed_conntrack_rules_list = ch_rules + i_rules + r_rules
                self.conntrack.delete_entries(removed_conntrack_rules_list,
                                              ipt_mgr.namespace)

    def _remove_default_chains(self, nsid):
        """Remove fwaas default policy chain."""
        self._remove_chain_by_name(IPV4, FWAAS_DEFAULT_CHAIN, nsid)
        self._remove_chain_by_name(IPV6, FWAAS_DEFAULT_CHAIN, nsid)

    def _remove_chains(self, fwid, ipt_mgr):
        """Remove fwaas policy chain."""
        for ver in [IPV4, IPV6]:
            for direction in [constants.INGRESS_DIRECTION,
                              constants.EGRESS_DIRECTION]:
                chain_name = self._get_chain_name(fwid, ver, direction)
                self._remove_chain_by_name(ver, chain_name, ipt_mgr)

    def _add_default_policy_chain_v4v6(self, ipt_mgr):
        ipt_mgr.ipv4['filter'].add_chain(FWAAS_DEFAULT_CHAIN)
        ipt_mgr.ipv4['filter'].add_rule(FWAAS_DEFAULT_CHAIN, '-j DROP')
        ipt_mgr.ipv6['filter'].add_chain(FWAAS_DEFAULT_CHAIN)
        ipt_mgr.ipv6['filter'].add_rule(FWAAS_DEFAULT_CHAIN, '-j DROP')

    def _remove_chain_by_name(self, ver, chain_name, ipt_mgr):
        if ver == IPV4:
            ipt_mgr.ipv4['filter'].remove_chain(chain_name)
        else:
            ipt_mgr.ipv6['filter'].remove_chain(chain_name)

    def _add_rules_to_chain(self, ipt_mgr, ver, chain_name, rules):
        if ver == IPV4:
            table = ipt_mgr.ipv4['filter']
        else:
            table = ipt_mgr.ipv6['filter']
        for rule in rules:
            table.add_rule(chain_name, rule)

    def _enable_policy_chain(self, fwid, ipt_if_prefix):
        bname = iptables_manager.binary_name
        ipt_mgr = ipt_if_prefix['ipt']
        if_prefix = ipt_if_prefix['if_prefix']

        for (ver, tbl) in [(IPV4, ipt_mgr.ipv4['filter']),
                           (IPV6, ipt_mgr.ipv6['filter'])]:
            for direction in [constants.INGRESS_DIRECTION,
                              constants.EGRESS_DIRECTION]:
                chain_name = self._get_chain_name(fwid, ver, direction)
                chain_name = iptables_manager.get_chain_name(chain_name)
                if chain_name in tbl.chains:
                    jump_rule = ['%s %s+ -j %s-%s' % (IPTABLES_DIR[direction],
                        if_prefix, bname, chain_name)]
                    self._add_rules_to_chain(ipt_mgr,
                        ver, 'FORWARD', jump_rule)

        #jump to DROP_ALL policy
        chain_name = iptables_manager.get_chain_name(FWAAS_DEFAULT_CHAIN)
        jump_rule = ['-o %s+ -j %s-%s' % (if_prefix, bname, chain_name)]
        self._add_rules_to_chain(ipt_mgr, IPV4, 'FORWARD', jump_rule)
        self._add_rules_to_chain(ipt_mgr, IPV6, 'FORWARD', jump_rule)

        #jump to DROP_ALL policy
        chain_name = iptables_manager.get_chain_name(FWAAS_DEFAULT_CHAIN)
        jump_rule = ['-i %s+ -j %s-%s' % (if_prefix, bname, chain_name)]
        self._add_rules_to_chain(ipt_mgr, IPV4, 'FORWARD', jump_rule)
        self._add_rules_to_chain(ipt_mgr, IPV6, 'FORWARD', jump_rule)

    def _convert_fwaas_to_iptables_rule(self, rule):
        action = FWAAS_TO_IPTABLE_ACTION_MAP[rule.get('action')]

        # Output ordering is important here as it must exactly match what
        # is returned by iptables-save.  If not we risk unnecessarily removing
        # and readding rules.
        args = []

        args += self._protocol_arg(rule.get('protocol'),
                                   rule.get('ip_version'))

        args += self._ip_prefix_arg('s', rule.get('source_ip_address'))
        args += self._ip_prefix_arg('d', rule.get('destination_ip_address'))

        # iptables adds '-m protocol' when any source
        # or destination port number is specified
        if (rule.get('source_port') is not None or
            rule.get('destination_port') is not None):
            args += self._match_arg(rule.get('protocol'))

        args += self._port_arg('sport',
                               rule.get('protocol'),
                               rule.get('source_port'))

        args += self._port_arg('dport',
                               rule.get('protocol'),
                               rule.get('destination_port'))

        args += self._action_arg(action)

        iptables_rule = ' '.join(args)
        return iptables_rule

    def _drop_invalid_packets_rule(self):
        return '-m state --state INVALID -j DROP'

    def _allow_established_rule(self):
        return '-m state --state RELATED,ESTABLISHED -j ACCEPT'

    def _action_arg(self, action):
        if not action:
            return []

        args = ['-j', action]

        return args

    def _protocol_arg(self, protocol, ip_version=constants.IP_VERSION_4):
        if not protocol:
            return []

        if (protocol == constants.PROTO_NAME_ICMP and
            ip_version == constants.IP_VERSION_6):
            protocol = constants.PROTO_NAME_IPV6_ICMP

        args = ['-p', protocol]

        return args

    def _match_arg(self, protocol):
        if not protocol:
            return []

        protocol_modules = {'udp': 'udp', 'tcp': 'tcp',
                           'icmp': 'icmp', 'ipv6-icmp': 'icmp6'}
        # iptables adds '-m protocol' when the port number is specified
        args = ['-m', protocol_modules[protocol]]

        return args

    def _port_arg(self, direction, protocol, port):
        if protocol not in ['udp', 'tcp'] or port is None:
            return []

        args = ['--%s' % direction, '%s' % port]

        return args

    def _ip_prefix_arg(self, direction, ip_prefix):
        if not(ip_prefix):
            return []

        args = ['-%s' % direction, '%s' % utils.ip_to_cidr(ip_prefix)]
        return args
