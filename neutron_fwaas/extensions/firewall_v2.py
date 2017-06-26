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
from neutron_lib.api.definitions import constants as api_const
from neutron_lib.api.definitions import firewall_v2
from neutron_lib.api import extensions
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.services import base as service_base
import six

from neutron_fwaas.common import fwaas_constants


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


# TODO(Reedip): Remove the convert_to functionality after bug1706061 is fixed.
def convert_to_string(value):
    if value is not None:
        return str(value)
    return None

firewall_v2.RESOURCE_ATTRIBUTE_MAP[api_const.FIREWALL_RULES][
    'source_port']['convert_to'] = convert_to_string
firewall_v2.RESOURCE_ATTRIBUTE_MAP[api_const.FIREWALL_RULES][
    'destination_port']['convert_to'] = convert_to_string


class Firewall_v2(extensions.APIExtensionDescriptor):
    api_definition = firewall_v2

    @classmethod
    def get_resources(cls):
        special_mappings = {'firewall_policies': 'firewall_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, firewall_v2.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings, firewall_v2.RESOURCE_ATTRIBUTE_MAP,
            fwaas_constants.FIREWALL_V2, action_map=firewall_v2.ACTION_MAP,
            register_quota=True)

    @classmethod
    def get_plugin_interface(cls):
        return Firewallv2PluginBase


@six.add_metaclass(abc.ABCMeta)
class Firewallv2PluginBase(service_base.ServicePluginBase):

    def get_plugin_type(self):
        return fwaas_constants.FIREWALL_V2

    def get_plugin_description(self):
        return 'Firewall Service v2 Plugin'

    # Firewall Group
    @abc.abstractmethod
    def create_firewall_group(self, context, firewall_group):
        pass

    @abc.abstractmethod
    def delete_firewall_group(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_group(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_groups(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_firewall_group(self, context, id, firewall_group):
        pass

    # Firewall Policy
    @abc.abstractmethod
    def create_firewall_policy(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def delete_firewall_policy(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_firewall_policy(self, context, id, firewall_policy):
        pass

    # Firewall Rule
    @abc.abstractmethod
    def create_firewall_rule(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def delete_firewall_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_firewall_rule(self, context, id, firewall_rule):
        pass

    @abc.abstractmethod
    def insert_rule(self, context, id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule(self, context, id, rule_info):
        pass
