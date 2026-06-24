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

from neutron_lib import constants as nl_constants

from neutron_fwaas.objects import firewall_v2 as fw_obj


FWAAS_RPC_VERSION_LEGACY = '1.0'
FWAAS_RPC_VERSION_OVO = '1.1'


def is_ovo_primitive(obj):
    return (isinstance(obj, dict) and
            'versioned_object.name' in obj)


def is_rpc_ovo_payload(payload):
    return (isinstance(payload, dict) and
            'firewall_group' in payload and
            is_ovo_primitive(payload['firewall_group']))


def build_firewall_group_rpc_payload(context, firewall_db, fwg_id, *,
                                     add_port_ids=None, del_port_ids=None,
                                     port_details=None, last_port=None):
    """Build an RPC payload using FWaaS OVO objects plus RPC metadata."""
    fwg_ovo = firewall_db.get_firewall_group(context, fwg_id)
    ingress_policy_id = fwg_ovo.ingress_firewall_policy_id
    egress_policy_id = fwg_ovo.egress_firewall_policy_id

    return {
        'firewall_group': fwg_ovo,
        'ingress_rules': (
            firewall_db._get_policy_ordered_rule_objects(
                context, ingress_policy_id)
            if ingress_policy_id else []),
        'egress_rules': (
            firewall_db._get_policy_ordered_rule_objects(
                context, egress_policy_id)
            if egress_policy_id else []),
        'add_port_ids': add_port_ids,
        'del_port_ids': del_port_ids,
        'port_details': port_details,
        'last_port': last_port,
    }


def build_firewall_group_rpc_payload_for_sync(context, firewall_db, fwg_ovo):
    """Build RPC payload for get_firewall_groups_for_project."""
    fwg_ports = firewall_db.get_ports_in_firewall_group(context, fwg_ovo.id)
    if fwg_ovo.status == nl_constants.PENDING_DELETE:
        add_port_ids = []
        del_port_ids = fwg_ports
    else:
        add_port_ids = fwg_ports
        del_port_ids = []
    return build_firewall_group_rpc_payload(
        context, firewall_db, fwg_ovo.id,
        add_port_ids=add_port_ids,
        del_port_ids=del_port_ids,
    )


def build_firewall_group_rpc_payload_for_port(context, firewall_db, fwg_ovo):
    """Build RPC payload for get_firewall_group_for_port."""
    return build_firewall_group_rpc_payload(context, firewall_db, fwg_ovo.id)


def rpc_payload_to_legacy_dict(payload):
    """Convert an RPC payload to the legacy agent dict format."""
    fwg = payload['firewall_group']
    result = {
        'id': fwg.id,
        'project_id': fwg.project_id,
        'name': fwg.name,
        'ingress_firewall_policy_id': fwg.ingress_firewall_policy_id,
        'egress_firewall_policy_id': fwg.egress_firewall_policy_id,
        'admin_state_up': fwg.admin_state_up,
        'status': fwg.status,
        'shared': fwg.shared,
        'ports': list(fwg.ports),
    }
    result['ingress_rule_list'] = [
        rule.to_dict() for rule in payload['ingress_rules']
    ]
    result['egress_rule_list'] = [
        rule.to_dict() for rule in payload['egress_rules']
    ]
    if payload.get('add_port_ids') is not None:
        result['add-port-ids'] = list(payload['add_port_ids'])
    if payload.get('del_port_ids') is not None:
        result['del-port-ids'] = list(payload['del_port_ids'])
    if payload.get('port_details') is not None:
        result['port_details'] = payload['port_details']
    if payload.get('last_port') is not None:
        result['last-port'] = payload['last_port']
    return result


def _serialize_ovo_payload(payload):
    wire = {
        'firewall_group': payload['firewall_group'].obj_to_primitive(),
        'ingress_rules': [
            rule.obj_to_primitive() for rule in payload['ingress_rules']],
        'egress_rules': [
            rule.obj_to_primitive() for rule in payload['egress_rules']],
    }
    for key in ('add_port_ids', 'del_port_ids', 'port_details', 'last_port'):
        if payload.get(key) is not None:
            wire[key] = payload[key]
    return wire


def _deserialize_ovo_payload(wire):
    payload = {
        'firewall_group': fw_obj.FirewallGroup.clean_obj_from_primitive(
            wire['firewall_group']),
        'ingress_rules': [
            fw_obj.FirewallRuleV2.clean_obj_from_primitive(rule)
            for rule in wire.get('ingress_rules', [])],
        'egress_rules': [
            fw_obj.FirewallRuleV2.clean_obj_from_primitive(rule)
            for rule in wire.get('egress_rules', [])],
    }
    for key in ('add_port_ids', 'del_port_ids', 'port_details', 'last_port'):
        if key in wire:
            payload[key] = wire[key]
    return payload


def serialize_firewall_group_for_rpc(payload, rpc_version):
    if rpc_version == FWAAS_RPC_VERSION_LEGACY:
        # TODO(slaweq): Remove legacy RPC dict format support when
        # minimum supported agent RPC version is 1.1.
        return rpc_payload_to_legacy_dict(payload)
    return _serialize_ovo_payload(payload)


def deserialize_firewall_group_from_rpc(payload):
    if is_rpc_ovo_payload(payload):
        return rpc_payload_to_legacy_dict(_deserialize_ovo_payload(payload))
    # TODO(slaweq): Remove legacy RPC dict format support when
    # minimum supported agent RPC version is 1.1.
    return payload


def deserialize_firewall_group_list_from_rpc(payload_list):
    return [deserialize_firewall_group_from_rpc(item)
            for item in (payload_list or [])]


def serialize_firewall_group_list_for_rpc(payload_list, rpc_version):
    return [serialize_firewall_group_for_rpc(payload, rpc_version)
            for payload in payload_list]
