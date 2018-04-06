# Copyright 2013 Big Switch Networks, Inc.
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

import abc

from debtcollector import moves
from neutron.api.v2 import resource_helper
from neutron_lib.api.definitions import constants as api_const
from neutron_lib.api.definitions import firewall
from neutron_lib.api import extensions
from neutron_lib.exceptions import firewall_v1 as f_exc
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron_fwaas._i18n import _
from neutron_fwaas.common import fwaas_constants


LOG = logging.getLogger(__name__)

FirewallNotFound = moves.moved_class(
    f_exc.FirewallNotFound, 'FirewallNotFound', __name__)
FirewallInUse = moves.moved_class(
    f_exc.FirewallInUse, 'FirewallInUse', __name__)
FirewallPolicyNotFound = moves.moved_class(
    f_exc.FirewallPolicyNotFound, 'FirewallPolicyNotFound', __name__)
FirewallPolicyInUse = moves.moved_class(
    f_exc.FirewallPolicyInUse, 'FirewallPolicyInUse', __name__)
FirewallPolicyConflict = moves.moved_class(
    f_exc.FirewallPolicyConflict, 'FirewallPolicyConflict', __name__)
FirewallRuleSharingConflict = moves.moved_class(
    f_exc.FirewallRuleSharingConflict, 'FirewallRuleSharingConflict', __name__)
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
    f_exc.FirewallRuleInvalidAction, 'FirewallRuleInvalidAction', __name__)
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


firewall_quota_opts = [
    cfg.IntOpt('quota_firewall',
               default=10,
               help=_('Number of firewalls allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_firewall_policy',
               default=10,
               help=_('Number of firewall policies allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_firewall_rule',
               default=100,
               help=_('Number of firewall rules allowed per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(firewall_quota_opts, 'QUOTAS')


# TODO(Reedip): Remove the convert_to functionality after bug1706061 is fixed.
def convert_to_string(value):
    if value is not None:
        return str(value)
    return None

firewall.RESOURCE_ATTRIBUTE_MAP[api_const.FIREWALL_RULES][
    'source_port']['convert_to'] = convert_to_string
firewall.RESOURCE_ATTRIBUTE_MAP[api_const.FIREWALL_RULES][
    'destination_port']['convert_to'] = convert_to_string


class Firewall(extensions.APIExtensionDescriptor):
    api_definition = firewall

    @classmethod
    def get_resources(cls):
        special_mappings = {'firewall_policies': 'firewall_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, firewall.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings, firewall.RESOURCE_ATTRIBUTE_MAP,
            fwaas_constants.FIREWALL, action_map=firewall.ACTION_MAP,
            register_quota=True)

    @classmethod
    def get_plugin_interface(cls):
        return FirewallPluginBase


@six.add_metaclass(abc.ABCMeta)
class FirewallPluginBase(service_base.ServicePluginBase):

    def get_plugin_type(self):
        return fwaas_constants.FIREWALL

    def get_plugin_description(self):
        return 'Firewall service plugin'

    @abc.abstractmethod
    def get_firewalls(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall(self, context, firewall):
        pass

    @abc.abstractmethod
    def update_firewall(self, context, id, firewall):
        pass

    @abc.abstractmethod
    def delete_firewall(self, context, id):
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
