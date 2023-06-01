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

from neutron.api.v2 import resource_helper
from neutron_lib.api.definitions import constants as api_const
from neutron_lib.api.definitions import firewall_v2
from neutron_lib.api import extensions
from neutron_lib.services import base as service_base
from oslo_config import cfg

from neutron_fwaas._i18n import _
from neutron_fwaas.common import fwaas_constants


default_fwg_rules_opts = [
    cfg.StrOpt('ingress_action',
               default=api_const.FWAAS_DENY,
               help=_('Firewall group rule action allow or '
                      'deny or reject for ingress. '
                      'Default is deny.')),
    cfg.StrOpt('ingress_source_ipv4_address',
               default=None,
               help=_('IPv4 source address for ingress '
                      '(address or address/netmask). '
                      'Default is None.')),
    cfg.StrOpt('ingress_source_ipv6_address',
               default=None,
               help=_('IPv6 source address for ingress '
                      '(address or address/netmask). '
                      'Default is None.')),
    cfg.StrOpt('ingress_source_port',
               default=None,
               help=_('Source port number or range '
                      '(min:max) for ingress. '
                      'Default is None.')),
    cfg.StrOpt('ingress_destination_ipv4_address',
               default=None,
               help=_('IPv4 destination address for ingress '
                      '(address or address/netmask). '
                      'Default is None.')),
    cfg.StrOpt('ingress_destination_ipv6_address',
               default=None,
               help=_('IPv6 destination address for ingress '
                      '(address or address/netmask). '
                      'Default is deny.')),
    cfg.StrOpt('ingress_destination_port',
               default=None,
               help=_('Destination port number or range '
                      '(min:max) for ingress. '
                      'Default is None.')),
    cfg.StrOpt('egress_action',
               default=api_const.FWAAS_ALLOW,
               help=_('Firewall group rule action allow or '
                      'deny or reject for egress. '
                      'Default is allow.')),
    cfg.StrOpt('egress_source_ipv4_address',
               default=None,
               help=_('IPv4 source address for egress '
                      '(address or address/netmask). '
                      'Default is None.')),
    cfg.StrOpt('egress_source_ipv6_address',
               default=None,
               help=_('IPv6 source address for egress '
                      '(address or address/netmask). '
                      'Default is deny.')),
    cfg.StrOpt('egress_source_port',
               default=None,
               help=_('Source port number or range '
                      '(min:max) for egress. '
                      'Default is None.')),
    cfg.StrOpt('egress_destination_ipv4_address',
               default=None,
               help=_('IPv4 destination address for egress '
                      '(address or address/netmask). '
                      'Default is deny.')),
    cfg.StrOpt('egress_destination_ipv6_address',
               default=None,
               help=_('IPv6 destination address for egress '
                      '(address or address/netmask). '
                      'Default is deny.')),
    cfg.StrOpt('egress_destination_port',
               default=None,
               help=_('Destination port number or range '
                      '(min:max) for egress. '
                      'Default is None.')),
    cfg.BoolOpt('shared',
                default=False,
                help=_('Firewall group rule shared. '
                       'Default is False.')),
    cfg.StrOpt('protocol',
               default=None,
               help=_('Network protocols (tcp, udp, ...). '
                      'Default is None.')),
    cfg.BoolOpt('enabled',
                default=True,
                help=_('Firewall group rule enabled. '
                       'Default is True.')),
]
firewall_quota_opts = [
    cfg.IntOpt('quota_firewall_group',
               default=10,
               help=_('Number of firewall groups allowed per tenant. '
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
cfg.CONF.register_opts(default_fwg_rules_opts, 'default_fwg_rules')
cfg.CONF.register_opts(firewall_quota_opts, 'QUOTAS')


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


class Firewallv2PluginBase(
    service_base.ServicePluginBase,
    metaclass=abc.ABCMeta):

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
