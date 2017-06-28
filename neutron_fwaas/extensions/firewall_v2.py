# Copyright (c) 2016 Mirantis, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc

from debtcollector import moves

from neutron.api.v2 import resource_helper
from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib.db import constants as nl_db_constants
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.services import base as service_base
import six

# Import firewall v1 API to get the validators
# TODO(shpadubi): pull the validators out of fwaas v1 into a separate file
from neutron_fwaas.extensions import firewall as fwaas_v1

FIREWALL_PREFIX = '/fwaas'

FIREWALL_CONST = 'FIREWALL_V2'

FirewallGroupNotFound = moves.moved_class(
    f_exc.FirewallGroupNotFound, 'FirewallGroupNotFound', __name__)
FirewallGroupInUse = moves.moved_class(
    f_exc.FirewallGroupInUse, 'FirewallGroupInUse', __name__)
FirewallGroupInPendingState = moves.moved_class(
    f_exc.FirewallGroupInPendingState, 'FirewallGroupInPendingState', __name__)
FirewallGroupPortInvalid = moves.moved_class(
    f_exc.FirewallGroupPortInvalid, 'FirewallGroupPortInvalid', __name__)
FirewallGroupPortInvalidProject = moves.moved_class(
    f_exc.FirewallGroupPortInvalidProject, 'FirewallGroupPortInvalidProject',
    __name__)
FirewallGroupPortInUse = moves.moved_class(
    f_exc.FirewallGroupPortInUse, 'FirewallGroupPortInUse', __name__)
FirewallPolicyNotFound = moves.moved_class(
    f_exc.FirewallPolicyNotFound, 'FirewallPolicyNotFound', __name__)
FirewallPolicyInUse = moves.moved_class(
    f_exc.FirewallPolicyInUse, 'FirewallPolicyInUse', __name__)
FirewallPolicyConflict = moves.moved_class(
    f_exc.FirewallPolicyConflict, 'FirewallPolicyConflict', __name__)
FirewallRuleSharingConflict = moves.moved_class(
    f_exc.FirewallRuleSharingConflict, 'FirewallRuleSharingConflict',
    __name__)
FirewallPolicySharingConflict = moves.moved_class(
    f_exc.FirewallPolicySharingConflict, 'FirewallPolicySharingConflict',
    __name__)
FirewallRuleNotFound = moves.moved_class(
    f_exc.FirewallRuleNotFound, 'FirewallRuleNotFound', __name__)
FirewallRuleInUse = moves.moved_class(
    f_exc.FirewallRuleInUse, 'FirewallRuleInUse', __name__)
FirewallRuleNotAssociatedWithPolicy = moves.moved_class(
    f_exc.FirewallRuleNotAssociatedWithPolicy,
    'FirewallRuleNotAssociatedWithPolicy',
    __name__)
FirewallRuleInvalidProtocol = moves.moved_class(
    f_exc.FirewallRuleInvalidProtocol, 'FirewallRuleInvalidProtocol',
    __name__)
FirewallRuleInvalidAction = moves.moved_class(
    f_exc.FirewallRuleInvalidAction, 'FirewallRuleInvalidAction',
    __name__)
FirewallRuleInvalidICMPParameter = moves.moved_class(
    f_exc.FirewallRuleInvalidICMPParameter,
    'FirewallRuleInvalidICMPParameter', __name__)
FirewallRuleWithPortWithoutProtocolInvalid = moves.moved_class(
    f_exc.FirewallRuleWithPortWithoutProtocolInvalid,
    'FirewallRuleWithPortWithoutProtocolInvalid', __name__)
FirewallRuleInvalidPortValue = moves.moved_class(
    f_exc.FirewallRuleInvalidPortValue, 'FirewallRuleInvalidPortValue',
    __name__)
FirewallRuleInfoMissing = moves.moved_class(
    f_exc.FirewallRuleInfoMissing, 'FirewallRuleInfoMissing', __name__)
FirewallIpAddressConflict = moves.moved_class(
    f_exc.FirewallIpAddressConflict, 'FirewallIpAddressConflict', __name__)
FirewallInternalDriverError = moves.moved_class(
    f_exc.FirewallInternalDriverError, 'FirewallInternalDriverError', __name__)
FirewallRuleConflict = moves.moved_class(
    f_exc.FirewallRuleConflict, 'FirewallRuleConflict', __name__)
FirewallRuleAlreadyAssociated = moves.moved_class(
    f_exc.FirewallRuleAlreadyAssociated, 'FirewallRuleAlreadyAssociated',
    __name__)


RESOURCE_ATTRIBUTE_MAP = {
    'firewall_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string':
                                   nl_db_constants.UUID_FIELD_SIZE},
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': nl_db_constants.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                     nl_db_constants.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'firewall_policy_id': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'is_visible': True,
                   'convert_to': converters.convert_to_boolean,
                   'required_by_policy': True, 'enforce_policy': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': fwaas_v1.convert_protocol,
                     'validate': {'type:values':
                                  fwaas_v1.fw_valid_protocol_values}},
        'ip_version': {'allow_post': True, 'allow_put': True,
                       'default': 4, 'convert_to': converters.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
        'source_ip_address': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:ip_or_subnet_or_none': None},
                              'is_visible': True, 'default': None},
        'destination_ip_address': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:ip_or_subnet_or_none':
                                                None},
                                   'is_visible': True, 'default': None},
        'source_port': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:port_range': None},
                        'convert_to': fwaas_v1.convert_port_to_string,
                        'default': None, 'is_visible': True},
        'destination_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:port_range': None},
                             'convert_to': fwaas_v1.convert_port_to_string,
                             'default': None, 'is_visible': True},
        'position': {'allow_post': False, 'allow_put': False,
                     'default': None, 'is_visible': True},
        'action': {'allow_post': True, 'allow_put': True,
                   'convert_to': fwaas_v1.convert_action_to_case_insensitive,
                   'validate': {'type:values':
                                fwaas_v1.fw_valid_action_values},
                   'is_visible': True, 'default': 'deny'},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'convert_to': converters.convert_to_boolean,
                    'default': True, 'is_visible': True},
    },
    'firewall_groups': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': nl_db_constants.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                     nl_db_constants.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True, 'is_visible': True,
                           'convert_to': converters.convert_to_boolean},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True, 'default': False,
                   'convert_to': converters.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'ports': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:uuid_list': None},
                  'convert_to': converters.convert_none_to_empty_list,
                  'default': None, 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string':
                                   nl_db_constants.UUID_FIELD_SIZE},
                      'is_visible': True},
        'ingress_firewall_policy_id': {'allow_post': True,
                                       'allow_put': True,
                                       'validate': {'type:uuid_or_none':
                                                    None},
                                       'default': None, 'is_visible': True},
        'egress_firewall_policy_id': {'allow_post': True,
                                      'allow_put': True,
                                      'validate': {'type:uuid_or_none':
                                                   None},
                                      'default': None, 'is_visible': True},
    },
    'firewall_policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string':
                                   nl_db_constants.UUID_FIELD_SIZE},
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': nl_db_constants.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                     nl_db_constants.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'shared': {'allow_post': True, 'allow_put': True, 'default': False,
                   'convert_to': converters.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'firewall_rules': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': converters.convert_none_to_empty_list,
                           'default': None, 'is_visible': True},
        'audited': {'allow_post': True, 'allow_put': True, 'default': False,
                    'convert_to': converters.convert_to_boolean,
                    'is_visible': True},

    },
}


class Firewall_v2(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Firewall service v2"

    @classmethod
    def get_alias(cls):
        return "fwaas_v2"

    @classmethod
    def get_description(cls):
        return "Extension for Firewall service v2"

    @classmethod
    def get_updated(cls):
        return "2016-08-16T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        special_mappings = {'firewall_policies': 'firewall_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, RESOURCE_ATTRIBUTE_MAP)
        action_map = {'firewall_policy': {'insert_rule': 'PUT',
                                          'remove_rule': 'PUT'}}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   FIREWALL_CONST,
                                                   action_map=action_map)

    @classmethod
    def get_plugin_interface(cls):
        return Firewallv2PluginBase

    def update_attributes_map(self, attributes):
        super(Firewall_v2, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class Firewallv2PluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return FIREWALL_CONST

    def get_plugin_type(self):
        return FIREWALL_CONST

    def get_plugin_description(self):
        return 'Firewall Service v2 Plugin'

    @abc.abstractmethod
    def create_firewall_group(self, context, firewall_group):
        pass

    @abc.abstractmethod
    def delete_firewall_group(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_group(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_groups(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_firewall_group(self, context, id, firewall_group):
        pass

    @abc.abstractmethod
    def get_firewall_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_rule(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def update_firewall_rule(self, context, id, firewall_rule):
        pass

    @abc.abstractmethod
    def delete_firewall_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_policy(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def update_firewall_policy(self, context, id, firewall_policy):
        pass

    @abc.abstractmethod
    def delete_firewall_policy(self, context, id):
        pass

    @abc.abstractmethod
    def insert_rule(self, context, id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule(self, context, id, rule_info):
        pass
