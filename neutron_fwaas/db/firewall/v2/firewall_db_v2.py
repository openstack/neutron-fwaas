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
import netaddr

from neutron_lib import constants as nl_constants
from neutron_lib import context as lib_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.objects import exceptions as o_exc
from neutron_lib.utils import net as net_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron_fwaas.common import fwaas_constants as const
from neutron_fwaas.common import utils as fwaas_utils
from neutron_fwaas.objects import firewall_v2 as fw_obj

_IP_ADDR_FIELDS = ('source_ip_address', 'destination_ip_address')


def _ip_str_to_network(value):
    """Convert an IP address string to AuthenticIPNetwork for OVO fields.

    AuthenticIPNetwork preserves the original string representation
    so '1.1.1.1' stays '1.1.1.1' rather than becoming '1.1.1.1/32'.
    """
    # TODO(slaweq): check if this isinstance check is still needed
    if value:
        if isinstance(value, netaddr.IPNetwork):
            return value
        return net_utils.AuthenticIPNetwork(value)
    return None


LOG = logging.getLogger(__name__)


class FirewallDefaultParameterExists(exceptions.InUse):
    """Default Firewall Parameter conflict exception

    Occurs when user creates/updates any existing firewall resource with
    reserved parameter names.
    """
    message = ("Operation cannot be performed since '%(name)s' "
               "is a reserved name for %(resource_type)s.")


class FirewallDefaultObjectUpdateRestricted(FirewallDefaultParameterExists):
    message = ("Operation cannot be performed on default object "
               "'%(resource_id)s' of type %(resource_type)s.")


class FirewallPluginDb:

    def _get_firewall_rule(self, context, id):
        fwr = fw_obj.FirewallRuleV2.get_object(context, id=id)
        if not fwr:
            raise f_exc.FirewallRuleNotFound(firewall_rule_id=id)
        return fwr

    def _get_policy_ordered_rules(self, context, policy_id):
        """Return ordered list of rule dicts for a given policy (for RPC)."""
        with db_api.CONTEXT_READER.using(context):
            assocs = fw_obj.FirewallPolicyRuleAssociation.get_objects(
                context, firewall_policy_id=policy_id)
            assocs.sort(key=lambda a: a.position)
            rule_ids = [a.firewall_rule_id for a in assocs]
            if not rule_ids:
                return []
            rules = fw_obj.FirewallRuleV2.get_objects(context, id=rule_ids)
            rules_by_id = {r.id: r for r in rules}
            return [rules_by_id[rid].to_dict()
                    for rid in rule_ids if rid in rules_by_id]

    def make_firewall_group_dict_with_rules(self, context, firewall_group_id):
        """Build a dict with embedded rule lists, suitable for RPC."""
        fwg = self.get_firewall_group(context, firewall_group_id)
        fwg_dict = fwg.to_dict()
        ingress_policy_id = fwg_dict.get('ingress_firewall_policy_id')
        if ingress_policy_id:
            fwg_dict['ingress_rule_list'] = (
                self._get_policy_ordered_rules(context, ingress_policy_id))
        else:
            fwg_dict['ingress_rule_list'] = []

        egress_policy_id = fwg_dict.get('egress_firewall_policy_id')
        if egress_policy_id:
            fwg_dict['egress_rule_list'] = (
                self._get_policy_ordered_rules(context, egress_policy_id))
        else:
            fwg_dict['egress_rule_list'] = []
        return fwg_dict

    def _check_firewall_rule_conflict(self, fwr_db, fwp_db):
        if not fwr_db['shared']:
            if fwr_db['project_id'] != fwp_db['project_id']:
                raise f_exc.FirewallRuleConflict(
                    firewall_rule_id=fwr_db['id'],
                    project_id=fwr_db['project_id'])

    def _process_rule_for_policy(self, context, firewall_policy_id,
                                 firewall_rule_id, position):
        with db_api.CONTEXT_WRITER.using(context):
            assocs = fw_obj.FirewallPolicyRuleAssociation.get_objects(
                context, firewall_policy_id=firewall_policy_id)
            assocs.sort(key=lambda a: a.position)
            rule_ids = [a.firewall_rule_id for a in assocs]
            if position:
                # Note that although position numbering starts at 1,
                # internal ordering of the list starts at 0, so we compensate.
                rule_ids.insert(position - 1, firewall_rule_id)
            else:
                rule_ids.remove(firewall_rule_id)
            fw_obj.FirewallPolicyRuleAssociation.delete_policy_associations(
                context, firewall_policy_id)
            for pos, rule_id in enumerate(rule_ids, start=1):
                assoc = fw_obj.FirewallPolicyRuleAssociation(
                    context,
                    firewall_policy_id=firewall_policy_id,
                    firewall_rule_id=rule_id,
                    position=pos)
                assoc.create()
            fwp_ovo = self.get_firewall_policy(context, firewall_policy_id)
            context.session.expire(fwp_ovo.db_obj)
            fwp_ovo.update_fields({'audited': False})
            fwp_ovo.update()
        return self.get_firewall_policy(context, firewall_policy_id)

    def _ensure_rule_not_already_associated(self, context, firewall_policy_id,
                                            firewall_rule_id):
        """Checks that a rule is not already associated with a particular
        policy. If it is the function will throw an exception.
        """
        assoc = fw_obj.FirewallPolicyRuleAssociation.get_object(
            context,
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        if assoc:
            raise f_exc.FirewallRuleAlreadyAssociated(
                firewall_rule_id=firewall_rule_id,
                firewall_policy_id=firewall_policy_id)

    def _get_policy_rule_association(self, context, firewall_policy_id,
                                     firewall_rule_id):
        """Returns the association between a firewall rule and a firewall
        policy. Throws an exception if the association does not exist.
        """
        assoc = fw_obj.FirewallPolicyRuleAssociation.get_object(
            context,
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        if not assoc:
            raise f_exc.FirewallRuleNotAssociatedWithPolicy(
                firewall_rule_id=firewall_rule_id,
                firewall_policy_id=firewall_policy_id)
        return assoc

    def _create_default_firewall_rules(self, context, project_id):
        # NOTE(xgerman) Maybe generating the final set of rules from a
        # configuration file makes sense. Can be done some time later

        # 1. Firewall rule for ingress IPv4 packets (DROP by default)
        in_fwr_v4 = {
            'description': const.DEFAULT_FWR_INGRESS_IPV4_DESC,
            'name': const.DEFAULT_FWR_INGRESS_IPV4,
            'shared': cfg.CONF.default_fwg_rules.shared,
            'protocol': cfg.CONF.default_fwg_rules.protocol,
            'project_id': project_id,
            'ip_version': nl_constants.IP_VERSION_4,
            'action': cfg.CONF.default_fwg_rules.ingress_action,
            'enabled': cfg.CONF.default_fwg_rules.enabled,
            'source_port': cfg.CONF.default_fwg_rules.ingress_source_port,
            'source_ip_address':
                cfg.CONF.default_fwg_rules.ingress_source_ipv4_address,
            'destination_port':
                cfg.CONF.default_fwg_rules.ingress_destination_port,
            'destination_ip_address':
                cfg.CONF.default_fwg_rules.ingress_destination_ipv4_address,
        }

        # 2. Firewall rule for ingress IPv6 packets (DROP by default)
        in_fwr_v6 = copy.deepcopy(in_fwr_v4)
        in_fwr_v6['description'] = const.DEFAULT_FWR_INGRESS_IPV6_DESC
        in_fwr_v6['name'] = const.DEFAULT_FWR_INGRESS_IPV6
        in_fwr_v6['ip_version'] = nl_constants.IP_VERSION_6
        in_fwr_v6['source_ip_address'] = \
            cfg.CONF.default_fwg_rules.ingress_source_ipv6_address
        in_fwr_v6['destination_ip_address'] = \
            cfg.CONF.default_fwg_rules.ingress_destination_ipv6_address

        # 3. Firewall rule for egress IPv4 packets (ALLOW by default)
        eg_fwr_v4 = copy.deepcopy(in_fwr_v4)
        eg_fwr_v4['description'] = const.DEFAULT_FWR_EGRESS_IPV4_DESC
        eg_fwr_v4['name'] = const.DEFAULT_FWR_EGRESS_IPV4
        eg_fwr_v4['action'] = cfg.CONF.default_fwg_rules.egress_action
        eg_fwr_v4['source_port'] = \
            cfg.CONF.default_fwg_rules.egress_source_port
        eg_fwr_v4['source_ip_address'] = \
            cfg.CONF.default_fwg_rules.egress_source_ipv4_address
        eg_fwr_v4['destination_port'] = \
            cfg.CONF.default_fwg_rules.egress_destination_port
        eg_fwr_v4['destination_ip_address'] = \
            cfg.CONF.default_fwg_rules.egress_destination_ipv4_address

        # 4. Firewall rule for egress IPv6 packets (ALLOW by default)
        eg_fwr_v6 = copy.deepcopy(in_fwr_v6)
        eg_fwr_v6['description'] = const.DEFAULT_FWR_EGRESS_IPV6_DESC
        eg_fwr_v6['name'] = const.DEFAULT_FWR_EGRESS_IPV6
        eg_fwr_v6['action'] = cfg.CONF.default_fwg_rules.egress_action
        eg_fwr_v6['source_port'] = \
            cfg.CONF.default_fwg_rules.egress_source_port
        eg_fwr_v6['source_ip_address'] = \
            cfg.CONF.default_fwg_rules.egress_source_ipv6_address
        eg_fwr_v6['destination_port'] = \
            cfg.CONF.default_fwg_rules.egress_destination_port
        eg_fwr_v6['destination_ip_address'] = \
            cfg.CONF.default_fwg_rules.egress_destination_ipv6_address

        return {
            'in_ipv4': self.create_firewall_rule(context, in_fwr_v4)['id'],
            'in_ipv6': self.create_firewall_rule(context, in_fwr_v6)['id'],
            'eg_ipv4': self.create_firewall_rule(context, eg_fwr_v4)['id'],
            'eg_ipv6': self.create_firewall_rule(context, eg_fwr_v6)['id'],
        }

    def create_firewall_rule(self, context, firewall_rule):
        fwr = firewall_rule
        fwaas_utils.validate_fwr_protocol_parameters(fwr)
        fwaas_utils.validate_fwr_src_dst_ip_version(fwr)

        src_port_min, src_port_max = fwaas_utils.get_min_max_ports_from_range(
            fwr['source_port'])
        dst_port_min, dst_port_max = fwaas_utils.get_min_max_ports_from_range(
            fwr['destination_port'])
        with db_api.CONTEXT_WRITER.using(context):
            fwr_ovo = fw_obj.FirewallRuleV2(
                context,
                id=uuidutils.generate_uuid(),
                project_id=firewall_rule['project_id'],
                name=firewall_rule['name'],
                description=firewall_rule['description'],
                protocol=firewall_rule['protocol'],
                ip_version=firewall_rule['ip_version'],
                source_ip_address=_ip_str_to_network(
                    firewall_rule['source_ip_address']),
                destination_ip_address=_ip_str_to_network(
                    firewall_rule['destination_ip_address']),
                source_port_range_min=src_port_min,
                source_port_range_max=src_port_max,
                destination_port_range_min=dst_port_min,
                destination_port_range_max=dst_port_max,
                action=firewall_rule['action'],
                enabled=firewall_rule['enabled'],
                shared=firewall_rule['shared'])
            fwr_ovo.create()
        return fwr_ovo

    def update_firewall_rule(self, context, id, firewall_rule):
        fwr_ovo = self._get_firewall_rule(context, id)
        fwr_merged = fwr_ovo.to_dict()
        fwr_merged.update(firewall_rule)

        fwaas_utils.validate_fwr_protocol_parameters(fwr_merged)
        fwaas_utils.validate_fwr_src_dst_ip_version(fwr_merged)
        if 'source_port' in firewall_rule:
            src_port_min, src_port_max = (
                fwaas_utils.get_min_max_ports_from_range(
                    firewall_rule['source_port']))
            firewall_rule['source_port_range_min'] = src_port_min
            firewall_rule['source_port_range_max'] = src_port_max
            del firewall_rule['source_port']
        if 'destination_port' in firewall_rule:
            dst_port_min, dst_port_max = (
                fwaas_utils.get_min_max_ports_from_range(
                    firewall_rule['destination_port']))
            firewall_rule['destination_port_range_min'] = dst_port_min
            firewall_rule['destination_port_range_max'] = dst_port_max
            del firewall_rule['destination_port']
        for ip_field in _IP_ADDR_FIELDS:
            if ip_field in firewall_rule:
                firewall_rule[ip_field] = _ip_str_to_network(
                    firewall_rule[ip_field])
        with db_api.CONTEXT_WRITER.using(context):
            fwr_ovo.update_fields(firewall_rule)
            fwr_ovo.update()
            fwp_ids = self.get_policies_with_rule(context, id)
            for fwp_id in fwp_ids:
                fwp_ovo = self.get_firewall_policy(context, fwp_id)
                fwp_ovo.update_fields({'audited': False})
                fwp_ovo.update()
        return fwr_ovo

    def delete_firewall_rule(self, context, id):
        with db_api.CONTEXT_WRITER.using(context):
            fwr = self._get_firewall_rule(context, id)
            # make sure rule is not associated with any policy
            if self.get_policies_with_rule(context, id):
                raise f_exc.FirewallRuleInUse(firewall_rule_id=id)
            fwr.delete()

    def insert_rule(self, context, id, rule_info):
        firewall_rule_id = rule_info['firewall_rule_id']
        # ensure rule is not already assigned to the policy
        self._ensure_rule_not_already_associated(context, id, firewall_rule_id)
        insert_before = True
        ref_firewall_rule_id = None
        if 'insert_before' in rule_info:
            ref_firewall_rule_id = rule_info['insert_before']
        if not ref_firewall_rule_id and 'insert_after' in rule_info:
            # If insert_before is set, we will ignore insert_after.
            ref_firewall_rule_id = rule_info['insert_after']
            insert_before = False
        with db_api.CONTEXT_WRITER.using(context):
            fwr_db = self._get_firewall_rule(context, firewall_rule_id)
            fwp_db = self.get_firewall_policy(context, id)
            self._check_firewall_rule_conflict(fwr_db, fwp_db)
            if ref_firewall_rule_id:
                # If reference_firewall_rule_id is set, the new rule
                # is inserted depending on the value of insert_before.
                # If insert_before is set, the new rule is inserted before
                # reference_firewall_rule_id, and if it is not set the new
                # rule is inserted after reference_firewall_rule_id.
                fwpra_db = self._get_policy_rule_association(
                    context, id, ref_firewall_rule_id)
                if insert_before:
                    position = fwpra_db.position
                else:
                    position = fwpra_db.position + 1
            else:
                # If reference_firewall_rule_id is not set, it is assumed
                # that the new rule needs to be inserted at the top.
                # insert_before field is ignored.
                # So default insertion is always at the top.
                # Also note that position numbering starts at 1.
                position = 1
            return self._process_rule_for_policy(context, id, firewall_rule_id,
                                                 position)

    def remove_rule(self, context, id, rule_info):
        firewall_rule_id = rule_info['firewall_rule_id']
        with db_api.CONTEXT_WRITER.using(context):
            # Getting fwr rule and rule association here is just to validate
            # that they exist and raise proper exception if they don't.
            self._get_firewall_rule(context, firewall_rule_id)
            self._get_policy_rule_association(context, id, firewall_rule_id)
            return self._process_rule_for_policy(context, id, firewall_rule_id,
                                                 None)

    @db_api.CONTEXT_READER
    def get_firewall_rule(self, context, id, fields=None):
        fwr = self._get_firewall_rule(context, id)
        fwr._policies = self.get_policies_with_rule(context, id) or None
        return fwr

    def get_firewall_rules(self, context, filters=None, fields=None):
        project_id = filters.get('project_id', [None])[0] if filters else None
        self._ensure_default_firewall_group(context, project_id)
        with db_api.CONTEXT_READER.using(context):
            return fw_obj.FirewallRuleV2.get_objects(
                context, validate_filters=False, **(filters or {}))

    def _get_rules_in_policy(self, context, fwpid):
        """Gets rules in a firewall policy"""
        with db_api.CONTEXT_READER.using(context):
            assocs = fw_obj.FirewallPolicyRuleAssociation.get_objects(
                context, firewall_policy_id=fwpid)
            return [assoc.firewall_rule_id for assoc in assocs]

    def get_policies_with_rule(self, context, fwrid):
        """Gets policies that contain a given firewall rule"""
        with db_api.CONTEXT_READER.using(context):
            assocs = fw_obj.FirewallPolicyRuleAssociation.get_objects(
                context, firewall_rule_id=fwrid)
            return [assoc.firewall_policy_id for assoc in assocs]

    def _set_rules_in_policy_rule_assoc(self, context, fwp_ovo, rule_id_list):
        if not rule_id_list:
            return
        with db_api.CONTEXT_WRITER.using(context):
            for position, rule_id in enumerate(rule_id_list, start=1):
                assoc = fw_obj.FirewallPolicyRuleAssociation(
                    context,
                    firewall_policy_id=fwp_ovo.id,
                    firewall_rule_id=rule_id,
                    position=position)
                assoc.create()

    def _check_rules_for_policy_is_valid(self, context, fwp, fwp_db,
                                         rule_id_list):
        rules_in_db = fw_obj.FirewallRuleV2.get_objects(
            context, id=rule_id_list)
        rules_dict = {fwr.id: fwr for fwr in rules_in_db}
        for fwrule_id in rule_id_list:
            if fwrule_id not in rules_dict:
                raise f_exc.FirewallRuleNotFound(
                    firewall_rule_id=fwrule_id)
            if 'shared' in fwp:
                if fwp['shared'] and not rules_dict[fwrule_id]['shared']:
                    raise f_exc.FirewallRuleSharingConflict(
                        firewall_rule_id=fwrule_id,
                        firewall_policy_id=fwp_db['id'])
            elif fwp_db['shared'] and not rules_dict[fwrule_id]['shared']:
                raise f_exc.FirewallRuleSharingConflict(
                    firewall_rule_id=fwrule_id,
                    firewall_policy_id=fwp_db['id'])
            else:
                if not rules_dict[fwrule_id]['shared']:
                    if (rules_dict[fwrule_id]['project_id'] != fwp_db[
                            'project_id']):
                        raise f_exc.FirewallRuleConflict(
                            firewall_rule_id=fwrule_id,
                            project_id=rules_dict[fwrule_id]['project_id'])

    def _check_if_rules_shared_for_policy_shared(self, context, fwp_db, fwp):
        if fwp['shared']:
            rules_in_db = fwp_db.rule_associations or []
            for entry in rules_in_db:
                fwr_db = self._get_firewall_rule(context,
                                                 entry.firewall_rule_id)
                if not fwr_db['shared']:
                    raise f_exc.FirewallPolicySharingConflict(
                        firewall_rule_id=fwr_db['id'],
                        firewall_policy_id=fwp_db['id'])

    def get_fwgs_with_policy(self, context, fwp_id):
        with db_api.CONTEXT_READER.using(context):
            ing_fwgs = fw_obj.FirewallGroup.get_objects(
                context, ingress_firewall_policy_id=fwp_id)
            ing_fwg_ids = [fwg.id for fwg in ing_fwgs]
            eg_fwgs = fw_obj.FirewallGroup.get_objects(
                context, egress_firewall_policy_id=fwp_id)
            eg_fwg_ids = [fwg.id for fwg in eg_fwgs]
        return ing_fwg_ids, eg_fwg_ids

    def _check_fwgs_associated_with_policy_in_same_project(self, context,
                                                           fwp_id,
                                                           fwp_project_id):
        with db_api.CONTEXT_READER.using(context):
            ing_fwgs = fw_obj.FirewallGroup.get_objects(
                context, ingress_firewall_policy_id=fwp_id)
            eg_fwgs = fw_obj.FirewallGroup.get_objects(
                context, egress_firewall_policy_id=fwp_id)
        for entry in list(ing_fwgs) + list(eg_fwgs):
            if entry.project_id != fwp_project_id:
                raise f_exc.FirewallPolicyInUse(
                            firewall_policy_id=fwp_id)

    def _delete_all_rules_from_policy(self, context, fwp_id):
        fw_obj.FirewallPolicyRuleAssociation.delete_policy_associations(
            context, fwp_id)

    def _set_rules_for_policy(self, context, fwp_ovo, fwp):
        rule_id_list = fwp['firewall_rules']
        with db_api.CONTEXT_WRITER.using(context):
            if not rule_id_list:
                self._delete_all_rules_from_policy(context, fwp_ovo.id)
                return
            self._check_rules_for_policy_is_valid(context, fwp, fwp_ovo,
                                                  rule_id_list)
            self._delete_all_rules_from_policy(context, fwp_ovo.id)
            self._set_rules_in_policy_rule_assoc(context, fwp_ovo,
                                                 rule_id_list)

    def _create_default_firewall_policy(self, context, project_id, policy_type,
                                        **kwargs):
        fwrs = kwargs.get('firewall_rules', [])
        description = kwargs.get('description', '')
        name = (const.DEFAULT_FWP_INGRESS
                if policy_type == 'ingress' else const.DEFAULT_FWP_EGRESS)
        firewall_policy = {
            'name': name,
            'description': description,
            'audited': False,
            'shared': False,
            'firewall_rules': fwrs,
            'project_id': project_id,
        }
        return self._do_create_firewall_policy(context, firewall_policy)

    def _do_create_firewall_policy(self, context, firewall_policy):
        fwp = firewall_policy
        with db_api.CONTEXT_WRITER.using(context):
            fwp_ovo = fw_obj.FirewallPolicy(
                context,
                id=uuidutils.generate_uuid(),
                project_id=fwp['project_id'],
                name=fwp['name'],
                description=fwp['description'],
                audited=fwp['audited'],
                shared=fwp['shared'])
            fwp_ovo.create()
            self._set_rules_for_policy(context, fwp_ovo, fwp)
            fwp_ovo = self.get_firewall_policy(context, fwp_ovo.id)
        return fwp_ovo

    def create_firewall_policy(self, context, firewall_policy):
        self._ensure_not_default_resource(firewall_policy, 'firewall_policy')
        return self._do_create_firewall_policy(context, firewall_policy)

    def update_firewall_policy(self, context, id, firewall_policy):
        fwp = firewall_policy
        with db_api.CONTEXT_WRITER.using(context):
            fwp_ovo = self.get_firewall_policy(context, id)
            self._ensure_not_default_resource(
                {'name': fwp_ovo.name, 'id': fwp_ovo.id},
                'firewall_policy', action="update")
            if not fwp.get('shared', True):
                self._check_fwgs_associated_with_policy_in_same_project(
                    context, id, fwp_ovo['project_id'])
            if 'shared' in fwp and 'firewall_rules' not in fwp:
                self._check_if_rules_shared_for_policy_shared(
                    context, fwp_ovo, fwp)
            if 'firewall_rules' in fwp:
                self._set_rules_for_policy(context, fwp_ovo, fwp)
                del fwp['firewall_rules']
                context.session.expire(fwp_ovo.db_obj)
            if 'audited' not in fwp:
                fwp['audited'] = False
            fwp_ovo.update_fields(fwp)
            fwp_ovo.update()
        return self.get_firewall_policy(context, id)

    def delete_firewall_policy(self, context, id):
        with db_api.CONTEXT_WRITER.using(context):
            fwp_ovo = self.get_firewall_policy(context, id)
            if fw_obj.FirewallGroup.get_objects(
                    context, ingress_firewall_policy_id=id):
                raise f_exc.FirewallPolicyInUse(firewall_policy_id=id)
            if fw_obj.FirewallGroup.get_objects(
                    context, egress_firewall_policy_id=id):
                raise f_exc.FirewallPolicyInUse(firewall_policy_id=id)
            self._delete_all_rules_from_policy(context, id)
            fwp_ovo.delete()

    @db_api.CONTEXT_READER
    def get_firewall_policy(self, context, id, fields=None):
        fwp = fw_obj.FirewallPolicy.get_object(context, id=id)
        if not fwp:
            raise f_exc.FirewallPolicyNotFound(firewall_policy_id=id)
        return fwp

    def get_firewall_policies(self, context, filters=None, fields=None):
        project_id = filters.get('project_id', [None])[0] if filters else None
        self._ensure_default_firewall_group(context, project_id)
        filters = dict(filters) if filters else {}
        rule_ids = filters.pop('firewall_rules', None)
        with db_api.CONTEXT_READER.using(context):
            if rule_ids:
                assocs = fw_obj.FirewallPolicyRuleAssociation.get_objects(
                    context, firewall_rule_id=rule_ids)
                fwp_ids = list({a.firewall_policy_id for a in assocs})
                if not fwp_ids:
                    return []
                filters['id'] = fwp_ids
            return fw_obj.FirewallPolicy.get_objects(
                context, validate_filters=False, **(filters or {}))

    def _set_ports_for_firewall_group(self, context, fwg_ovo, fwg):
        port_id_list = fwg['ports']
        if not port_id_list:
            return

        exc_ports = []
        for port_id in port_id_list:
            try:
                assoc = fw_obj.FirewallGroupPortAssociation(
                    context,
                    firewall_group_id=fwg_ovo.id,
                    port_id=port_id)
                assoc.create()
            except o_exc.NeutronDbObjectDuplicateEntry:
                exc_ports.append(port_id)
        if exc_ports:
            raise f_exc.FirewallGroupPortInUse(port_ids=exc_ports)

    def get_ports_in_firewall_group(self, context, firewall_group_id):
        """Get the Ports associated with the  firewall group."""
        with db_api.CONTEXT_READER.using(context):
            assocs = fw_obj.FirewallGroupPortAssociation.get_objects(
                context, firewall_group_id=firewall_group_id)
            return [assoc.port_id for assoc in assocs]

    def _delete_ports_in_firewall_group(self, context, firewall_group_id):
        """Delete the Ports associated with the  firewall group."""
        with db_api.CONTEXT_WRITER.using(context):
            fw_obj.FirewallGroupPortAssociation.delete_group_port_associations(
                context, firewall_group_id=firewall_group_id)

    @db_api.CONTEXT_READER
    def _get_default_fwg_id(self, context, project_id):
        """Returns an id of default firewall group for given project or None"""
        fwgs = fw_obj.FirewallGroup.get_objects(
            context.elevated(), project_id=project_id,
            name=const.DEFAULT_FWG)
        if fwgs:
            return fwgs[0].id
        return None

    def get_fwg_attached_to_port(self, context, port_id):
        """Return a firewall group ID that is attached to a given port"""
        with db_api.CONTEXT_READER.using(context):
            assocs = fw_obj.FirewallGroupPortAssociation.get_objects(
                context, port_id=port_id)
        if assocs:
            return assocs[0].firewall_group_id
        return None

    def get_fwg_ports_in_project(self, context, project_id):
        """Return a list of ports under a given project"""
        # Question: why don't we need to handle NoResultFound exception here?
        with db_api.CONTEXT_READER.using(context):
            fwgs = fw_obj.FirewallGroup.get_objects(
                context, project_id=project_id)
            ports = set()
            for fwg in fwgs:
                assocs = fw_obj.FirewallGroupPortAssociation.get_objects(
                    context, firewall_group_id=fwg.id)
                ports.update(a.port_id for a in assocs)
            return list(ports)

    def _ensure_default_firewall_group(self, context, project_id):
        """Create a default firewall group if one doesn't exist for a project

        Returns the default firewall group id for a given project.
        """
        project_id = project_id or context.project_id
        if not project_id:
            return
        exists = self._get_default_fwg_id(context, project_id)
        if exists:
            return exists

        try:
            # NOTE(cby): default fwg not created => we try to create it!
            ctx = lib_context.get_admin_context()
            with db_api.CONTEXT_WRITER.using(ctx):

                fwr_ids = self._create_default_firewall_rules(
                    ctx, project_id)
                ingress_fwp = {
                    'description': 'Ingress firewall policy',
                    'firewall_rules': [fwr_ids['in_ipv4'],
                                       fwr_ids['in_ipv6']],
                }
                egress_fwp = {
                    'description': 'Egress firewall policy',
                    'firewall_rules': [fwr_ids['eg_ipv4'],
                                       fwr_ids['eg_ipv6']],
                }
                ingress_fwp_db = self._create_default_firewall_policy(
                    ctx, project_id, 'ingress', **ingress_fwp)
                egress_fwp_db = self._create_default_firewall_policy(
                    ctx, project_id, 'egress', **egress_fwp)

                fwg = {
                    'name': const.DEFAULT_FWG,
                    'project_id': project_id,
                    'ingress_firewall_policy_id': ingress_fwp_db['id'],
                    'egress_firewall_policy_id': egress_fwp_db['id'],
                    'ports': [],
                    'shared': False,
                    'status': nl_constants.INACTIVE,
                    'admin_state_up': True,
                    'description': 'Default firewall group',
                }
                fwg_db = self._create_firewall_group(
                    ctx, fwg, default_fwg=True)
                dfwg = fw_obj.DefaultFirewallGroup(
                    ctx,
                    firewall_group_id=fwg_db['id'],
                    project_id=project_id)
                dfwg.create()

            return fwg_db['id']

        except o_exc.NeutronDbObjectDuplicateEntry:
            # NOTE(cby): default fwg created concurrently
            LOG.debug("Default FWG was concurrently created")
            return self._get_default_fwg_id(context, project_id)

    def _create_firewall_group(self, context, firewall_group,
                               default_fwg=False):
        """Create a firewall group

        If default_fwg is True then a default firewall group is being created
        for a given project.
        """
        fwg = firewall_group
        project_id = fwg['project_id']
        if firewall_group.get('status') is None:
            fwg['status'] = nl_constants.CREATED

        if default_fwg:
            # A default firewall group is being created.
            default_fwg_id = self._get_default_fwg_id(context, project_id)
            if default_fwg_id is not None:
                # Default fwg for a given project exists, fetch it and return
                return self.get_firewall_group(context, default_fwg_id)
        else:
            # An ordinary firewall group is being created BUT let's make sure
            # that a default firewall group for given project exists
            self._ensure_default_firewall_group(context, project_id)

        with db_api.CONTEXT_WRITER.using(context):
            fwg_ovo = fw_obj.FirewallGroup(
                context,
                id=uuidutils.generate_uuid(),
                project_id=project_id,
                name=fwg['name'],
                description=fwg['description'],
                status=fwg['status'],
                ingress_firewall_policy_id=fwg['ingress_firewall_policy_id'],
                egress_firewall_policy_id=fwg['egress_firewall_policy_id'],
                admin_state_up=fwg['admin_state_up'],
                shared=fwg['shared'])
            fwg_ovo.create()
            self._set_ports_for_firewall_group(context, fwg_ovo, fwg)
            fwg_ovo = self.get_firewall_group(context, fwg_ovo.id)
        return fwg_ovo

    def create_firewall_group(self, context, firewall_group):
        self._ensure_not_default_resource(firewall_group, 'firewall_group')
        return self._create_firewall_group(context, firewall_group)

    def update_firewall_group(self, context, id, firewall_group):
        fwg = firewall_group
        # make sure that no group can be updated to have name=default
        self._ensure_not_default_resource(fwg, 'firewall_group')
        with db_api.CONTEXT_WRITER.using(context):
            fwg_ovo = self.get_firewall_group(context, id)
            if _is_default(fwg_ovo):
                attrs = [
                    'name', 'description', 'admin_state_up',
                    'ingress_firewall_policy_id', 'egress_firewall_policy_id'
                ]
                if context.is_admin:
                    attrs = ['name']
                for attr in attrs:
                    if attr in fwg:
                        raise FirewallDefaultObjectUpdateRestricted(
                            resource_type='Firewall Group',
                            resource_id=fwg_ovo['id'])
            if 'ports' in fwg:
                LOG.debug("Ports are updated in Firewall Group")
                self._delete_ports_in_firewall_group(context, id)
                self._set_ports_for_firewall_group(context, fwg_ovo, fwg)
                del fwg['ports']
                context.session.expire(fwg_ovo.db_obj)
            fwg_update = {k: v for k, v in fwg.items()
                         if k in fw_obj.FirewallGroup.fields and
                         k not in fw_obj.FirewallGroup.fields_no_update and
                         k not in fw_obj.FirewallGroup.synthetic_fields}
            if fwg_update:
                fwg_ovo.update_fields(fwg_update)
                fwg_ovo.update()
        return self.get_firewall_group(context, id)

    def update_firewall_group_status(self, context, id, status, not_in=None):
        """Conditionally update firewall_group status.
        Status transition is performed only if firewall is not in the specified
        states as defined by 'not_in' list.
        """
        with db_api.CONTEXT_WRITER.using(context):
            return fw_obj.FirewallGroup.update_status(
                context, id, status, not_in)

    def delete_firewall_group(self, context, id):
        # Note: Plugin should ensure that it's okay to delete if the
        # firewall is active

        with db_api.CONTEXT_WRITER.using(context):
            # if no such group exists -> don't raise an exception according to
            # 80fe2ba1, return None
            try:
                fwg_ovo = self.get_firewall_group(context, id)
            except f_exc.FirewallGroupNotFound:
                return

            if _is_default(fwg_ovo):
                if context.is_admin:
                    # Like Rules in Default SG, when the Default FWG is deleted
                    # its associated Rules and policies would also be deleted.
                    # Delete fwg first and then associated policies
                    fwp_ids = [fwg_ovo['ingress_firewall_policy_id'],
                               fwg_ovo['egress_firewall_policy_id']]
                    fwg_ovo.delete()
                    for fwp_id in fwp_ids:
                        self.delete_firewall_policy(context, fwp_id)
                else:
                    # only admin can delete default fwg
                    raise f_exc.FirewallGroupCannotRemoveDefault()
            else:
                fwg_ovo.delete()

    def _ensure_not_default_resource(self, resource_dict, r_type, action=None):
        """Checks that a resource is not default by checking its name

        A resource_dict can be either a dictionary in form {r_type : {}} or a
        serialized object from db.

        Action is used to determine type of exception to be raised.
        """
        resource = resource_dict.get(r_type) or resource_dict
        if r_type == 'firewall_group':
            if resource.get('name', '') == const.DEFAULT_FWG:
                if action == "update":
                    raise FirewallDefaultObjectUpdateRestricted(
                        resource_type='Firewall Group',
                        resource_id=resource['id'])
                raise FirewallDefaultParameterExists(
                    resource_type='Firewall Group', name=resource['name'])
        elif r_type == 'firewall_policy':
            if resource.get('name', '') in [const.DEFAULT_FWP_INGRESS,
                                            const.DEFAULT_FWP_EGRESS]:
                if action == "update":
                    raise FirewallDefaultObjectUpdateRestricted(
                        resource_type='Firewall Group',
                        resource_id=resource['id'])
                raise FirewallDefaultParameterExists(
                    resource_type='Firewall Policy', name=resource['name'])

    @db_api.CONTEXT_READER
    def get_firewall_group(self, context, id, fields=None):
        fwg = fw_obj.FirewallGroup.get_object(context, id=id)
        if not fwg:
            raise f_exc.FirewallGroupNotFound(firewall_id=id)
        return fwg

    def get_firewall_groups(self, context, filters=None, fields=None):
        project_id = filters.get('project_id', [None])[0] if filters else None
        self._ensure_default_firewall_group(context, project_id)
        filters = dict(filters) if filters else {}
        port_ids = filters.pop('ports', None)
        with db_api.CONTEXT_READER.using(context):
            if port_ids:
                assocs = fw_obj.FirewallGroupPortAssociation.get_objects(
                    context, port_id=port_ids)
                fwg_ids = list({a.firewall_group_id for a in assocs})
                if not fwg_ids:
                    return []
                filters['id'] = fwg_ids
            return fw_obj.FirewallGroup.get_objects(
                context, validate_filters=False, **(filters or {}))


def _is_default(fwg):
    return fwg.name == const.DEFAULT_FWG
