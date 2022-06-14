# Copyright 2022 EasyStack, Inc.
# All rights reserved.
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

from neutron.common.ovn import utils as ovn_utils
from neutron_lib import constants as const
from oslo_log import log as logging

from neutron_fwaas.services.firewall.service_drivers import driver_api
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    acl as ovn_acl
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    constants as ovn_const
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    exceptions as ovn_fw_exc

LOG = logging.getLogger(__name__)


class OVNFwaasDriver(driver_api.FirewallDriverDB):
    """OVN l3 acl driver to implement

    Depends on ml2/ovn, use ovn_client to put acl rules to the lsp which
    is a peer of the lrp.
    """

    def __init__(self, service_plugin):
        super(OVNFwaasDriver, self).__init__(service_plugin)
        self._mech = None

    def is_supported_l2_port(self, port):
        return False

    def is_supported_l3_port(self, port):
        return True

    def start_rpc_listener(self):
        return []

    @property
    def _nb_ovn(self):
        return self._mech_driver.nb_ovn

    @property
    def _mech_driver(self):
        if self._mech is None:
            drivers = ('ovn', 'ovn-sync')
            for driver in drivers:
                try:
                    self._mech = \
                        self._core_plugin.mechanism_manager.mech_drivers[
                            driver].obj
                    break
                except KeyError:
                    pass
            else:
                raise ovn_fw_exc.MechanismDriverNotFound(
                    mechanism_drivers=drivers)
        return self._mech

    def _init_firewall_group(self, txn, fwg_id):
        """Add port_group for firewall_group

        After create port_group for fwg, add default drop acls to it
        """
        pg_name = ovn_utils.ovn_port_group_name(fwg_id)
        ovn_acl.create_pg_for_fwg(self._nb_ovn, fwg_id)
        ovn_acl.add_default_acls_for_pg(self._nb_ovn, txn, pg_name)
        LOG.info("Successfully created port_group for firewall_group: %s",
                 fwg_id)

    def _add_rules_for_firewall_group(self, context, txn, fwg_id,
                                      rule_id=None):
        """Add all rules belong to firewall_group
        """
        fwg_with_rules = \
            self.firewall_db.make_firewall_group_dict_with_rules(
                context, fwg_id)
        egress_rule_list = fwg_with_rules['egress_rule_list']
        ingress_rule_list = fwg_with_rules['ingress_rule_list']
        pg_name = ovn_utils.ovn_port_group_name(fwg_id)
        rule_map = {const.INGRESS_DIRECTION: ingress_rule_list,
                    const.EGRESS_DIRECTION: egress_rule_list}
        for dir, rule_list in rule_map.items():
            position = 0
            for rule in rule_list:
                rule['position'] = position
                position += 1
                if not rule['enabled']:
                    continue
                if rule_id:
                    # For specify rule id
                    if rule_id == rule['id']:
                        ovn_acl.process_rule_for_pg(self._nb_ovn, txn,
                                                    pg_name, rule, dir,
                                                    op=ovn_const.OP_ADD)
                        LOG.info("Successfully enable rule %(rule)s to "
                                 "firewall_group %(fwg)s",
                                 {"rule": rule_id,
                                  "fwg": fwg_id})
                        break
                else:
                    ovn_acl.process_rule_for_pg(self._nb_ovn, txn, pg_name,
                                                rule, dir,
                                                op=ovn_const.OP_ADD)
        LOG.info("Successfully added rules for firewall_group %s",
                 fwg_id)

    def _clear_rules_for_firewall_group(self, context, txn, fwg_id):
        """Clear acls belong to firewall_group

        Delete all rule acls but remain the default acls
        """
        pg_name = ovn_utils.ovn_port_group_name(fwg_id)
        default_acls = ovn_acl.get_default_acls_for_pg(self._nb_ovn, pg_name)
        if len(default_acls) == ovn_const.DEFAULT_ACL_NUM:
            txn.add(self._nb_ovn.db_set(
                'Port_Group', pg_name,
                ('acls', default_acls)))
        else:
            ovn_acl.add_default_acls_for_pg(self._nb_ovn, txn, pg_name)
        LOG.info("Successfully clear rules for firewall_group %s",
                 fwg_id)

    def _process_acls_by_policies_or_rule(self, context, policy_ids,
                                          rule_info=None,
                                          op=ovn_const.OP_ADD):
        """Delete/Update/Add the acls by rule or policies
        """
        ing_fwg_list = []
        eg_fwg_list = []
        if not policy_ids:
            return
        for policy_id in policy_ids:
            ing_fwg_ids, eg_fwg_ids = self.firewall_db.get_fwgs_with_policy(
                context, policy_id)
            ing_fwg_list += ing_fwg_ids
            eg_fwg_list += eg_fwg_ids

        if not rule_info and op == ovn_const.OP_ADD:
            # Add acls
            rule_info = {}
            for fwg_id in list(set(ing_fwg_list + eg_fwg_list)):
                pg_name = ovn_utils.ovn_port_group_name(fwg_id)
                with self._nb_ovn.transaction(check_error=True) as txn:
                    if self._nb_ovn.get_port_group(pg_name):
                        self._clear_rules_for_firewall_group(context, txn,
                                                             fwg_id)
                    else:
                        self._init_firewall_group(txn, fwg_id)
                    self._add_rules_for_firewall_group(context, txn, fwg_id)
        elif rule_info and op == ovn_const.OP_ADD:
            # Process the rule when enabled
            for fwg_id in list(set(ing_fwg_list + eg_fwg_list)):
                pg_name = ovn_utils.ovn_port_group_name(fwg_id)
                with self._nb_ovn.transaction(check_error=True) as txn:
                    if self._nb_ovn.get_port_group(pg_name):
                        self._add_rules_for_firewall_group(context, txn,
                                                           fwg_id,
                                                           rule_info['id'])
        elif rule_info:
            # Delete/Update acls
            fwg_map = {const.INGRESS_DIRECTION: list(set(ing_fwg_list)),
                       const.EGRESS_DIRECTION: list(set(eg_fwg_list))}
            for dir, fwg_list in fwg_map.items():
                for fwg_id in fwg_list:
                    pg_name = ovn_utils.ovn_port_group_name(fwg_id)
                    with self._nb_ovn.transaction(check_error=True) as txn:
                        if not self._nb_ovn.get_port_group(pg_name):
                            LOG.warning("Cannot find Port_Group with name: %s",
                                        pg_name)
                            continue
                        ovn_acl.process_rule_for_pg(self._nb_ovn, txn,
                                                    pg_name, rule_info,
                                                    dir, op=op)
        LOG.info("Successfully %(op)s acls by rule %(rule)s "
                 "and policies %(p_ids)s",
                 {"op": op,
                  "rule": rule_info.get('id'),
                  "p_ids": policy_ids})

    def create_firewall_group_precommit(self, context, firewall_group):
        if not firewall_group['ports']:
            LOG.info("No ports bound to firewall_group: %s, "
                     "set it to inactive", firewall_group['id'])
            status = const.INACTIVE
        else:
            status = const.PENDING_CREATE
        with self._nb_ovn.transaction(check_error=True) as txn:
            self._init_firewall_group(txn, firewall_group['id'])
        firewall_group['status'] = status

    def create_firewall_group_postcommit(self, context, firewall_group):
        pg_name = ovn_utils.ovn_port_group_name(firewall_group['id'])
        try:
            with self._nb_ovn.transaction(check_error=True) as txn:
                if (firewall_group['ingress_firewall_policy_id'] or
                        firewall_group['egress_firewall_policy_id']):
                    # Add rule acls to port_group
                    self._add_rules_for_firewall_group(context, txn,
                                                       firewall_group['id'])

                if firewall_group['ports']:
                    # Add ports to port_group
                    ovn_acl.update_ports_for_pg(self._nb_ovn,
                                                txn, pg_name,
                                                firewall_group['ports'])
                    firewall_group['status'] = const.ACTIVE
                    LOG.info("Successfully added ports for firewall_group %s",
                             firewall_group['id'])
        except Exception:
            with self._nb_ovn.transaction(check_error=True) as txn:
                if self._nb_ovn.get_port_group(pg_name):
                    txn.add(self._nb_ovn.pg_del(name=pg_name, if_exists=True))
            LOG.error("Failed to create_firewall_group_postcommit.")
            raise
        else:
            self.firewall_db.update_firewall_group_status(
                context, firewall_group['id'], firewall_group['status'])

    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        port_updated = (set(new_firewall_group['ports']) !=
                        set(old_firewall_group['ports']))
        policies_updated = (
                new_firewall_group['ingress_firewall_policy_id'] !=
                old_firewall_group['ingress_firewall_policy_id'] or
                new_firewall_group['egress_firewall_policy_id'] !=
                old_firewall_group['egress_firewall_policy_id']
        )
        if port_updated or policies_updated:
            new_firewall_group['status'] = const.PENDING_UPDATE

    def update_firewall_group_postcommit(self, context, old_firewall_group,
                                         new_firewall_group):
        if new_firewall_group['status'] != const.PENDING_UPDATE:
            return
        old_ports = set(old_firewall_group['ports'])
        new_ports = set(new_firewall_group['ports'])
        old_ing_policy = old_firewall_group['ingress_firewall_policy_id']
        new_ing_policy = new_firewall_group['ingress_firewall_policy_id']
        old_eg_policy = old_firewall_group['egress_firewall_policy_id']
        new_eg_policy = new_firewall_group['egress_firewall_policy_id']
        pg_name = ovn_utils.ovn_port_group_name(new_firewall_group['id'])

        # We except it would be active
        # If no ports, set it to inactive
        new_firewall_group['status'] = const.ACTIVE
        if not new_ports:
            LOG.info("No ports bound to firewall_group: %s, "
                     "set it to inactive", new_firewall_group['id'])
            new_firewall_group['status'] = const.INACTIVE

        # If port_group is not exist, recreate it,
        # add acls and ports.
        if not self._nb_ovn.get_port_group(pg_name):
            with self._nb_ovn.transaction(check_error=True) as txn:
                self._init_firewall_group(txn, new_firewall_group['id'])
                if new_ports:
                    ovn_acl.update_ports_for_pg(self._nb_ovn, txn,
                                                pg_name, new_ports)
                if new_ing_policy or new_eg_policy:
                    self._add_rules_for_firewall_group(
                        context, txn, new_firewall_group['id'])
        else:
            with self._nb_ovn.transaction(check_error=True) as txn:
                # Process changes of ports
                if old_ports != new_ports:
                    ports_add = list(new_ports - old_ports)
                    ports_delete = list(old_ports - new_ports)
                    ovn_acl.update_ports_for_pg(self._nb_ovn, txn, pg_name,
                                                ports_add, ports_delete)
                # Process changes of policies
                if (old_ing_policy != new_ing_policy or
                        old_eg_policy != new_eg_policy):
                    # Clear rules first
                    self._clear_rules_for_firewall_group(
                        context, txn, new_firewall_group['id'])
                    # Add rules if it has
                    if new_ing_policy or new_eg_policy:
                        self._add_rules_for_firewall_group(
                            context, txn, new_firewall_group['id'])

        self.firewall_db.update_firewall_group_status(
            context, new_firewall_group['id'],
            new_firewall_group['status'])

    def delete_firewall_group_precommit(self, context, firewall_group):
        pg_name = ovn_utils.ovn_port_group_name(firewall_group['id'])
        with self._nb_ovn.transaction(check_error=True) as txn:
            if self._nb_ovn.get_port_group(pg_name):
                txn.add(self._nb_ovn.pg_del(name=pg_name, if_exists=True))

    def update_firewall_policy_postcommit(self, context, old_firewall_policy,
                                          new_firewall_policy):
        old_rules = old_firewall_policy['firewall_rules']
        new_rules = new_firewall_policy['firewall_rules']
        if old_rules == new_rules:
            return
        self._process_acls_by_policies_or_rule(context,
                                               [new_firewall_policy['id']])

    def update_firewall_rule_postcommit(self, context, old_firewall_rule,
                                        new_firewall_rule):
        NEED_UPDATE_FIELDS = ['enabled', 'protocol', 'ip_version',
                              'source_ip_address', 'destination_ip_address',
                              'source_port', 'destination_port', 'action']
        need_update = False
        for field in NEED_UPDATE_FIELDS:
            if old_firewall_rule[field] != new_firewall_rule[field]:
                need_update = True
        if not need_update:
            return
        firewall_policy_ids = old_firewall_rule.get('firewall_policy_id')

        # If rule is enabled, its acls should be inserted
        # If rule is disabled, its acls should be removed
        # If rule is always disabled, nothing to do
        if not old_firewall_rule['enabled'] and new_firewall_rule['enabled']:
            self._process_acls_by_policies_or_rule(context,
                                                   firewall_policy_ids,
                                                   new_firewall_rule)
            return
        elif old_firewall_rule['enabled'] and not new_firewall_rule['enabled']:
            self._process_acls_by_policies_or_rule(context,
                                                   firewall_policy_ids,
                                                   old_firewall_rule,
                                                   ovn_const.OP_DEL)
            return
        elif not new_firewall_rule['enabled']:
            return

        # Process changes of rule
        self._process_acls_by_policies_or_rule(
            context, firewall_policy_ids, new_firewall_rule, ovn_const.OP_MOD)
        LOG.info("Successfully updated acls for rule: %s",
                 new_firewall_rule['id'])

    def insert_rule_postcommit(self, context, policy_id, rule_info):
        # Add acls by policy_id
        self._process_acls_by_policies_or_rule(context, [policy_id])

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        rule_detail = self.firewall_db.get_firewall_rule(
            context, rule_info['firewall_rule_id'])
        self._process_acls_by_policies_or_rule(
            context, [policy_id], rule_detail, ovn_const.OP_DEL)
