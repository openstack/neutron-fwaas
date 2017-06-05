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

from neutron.api.v2 import resource_helper
from neutron_lib.api.definitions import firewall
from neutron_lib.api import extensions
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron_fwaas._i18n import _
from neutron_fwaas.common import fwaas_constants


LOG = logging.getLogger(__name__)

# A tenant may have a unique firewall and policy for each router
# when router insertion is used.
# Set default quotas to align with default l3 quota_router of 10
# though keep as separately controllable.

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


class Firewall(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return firewall.NAME

    @classmethod
    def get_alias(cls):
        return firewall.ALIAS

    @classmethod
    def get_description(cls):
        return firewall.DESCRIPTION

    @classmethod
    def get_updated(cls):
        return firewall.UPDATED_TIMESTAMP

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        special_mappings = {'firewall_policies': 'firewall_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, firewall.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            firewall.RESOURCE_ATTRIBUTE_MAP,
            firewall.ALIAS,
            action_map=firewall.ACTION_MAP,
            register_quota=True)

    @classmethod
    def get_plugin_interface(cls):
        return FirewallPluginBase

    def update_attributes_map(self, attributes):
        super(Firewall, self).update_attributes_map(
            attributes, extension_attrs_map=firewall.RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return firewall.RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class FirewallPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return fwaas_constants.FIREWALL

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
