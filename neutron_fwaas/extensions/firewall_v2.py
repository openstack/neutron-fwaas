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

from neutron_fwaas.common import fwaas_constants
from neutron_lib.api.definitions import firewall_v2
from neutron_lib.api import extensions
from neutron_lib.services import base as service_base

import six


class Firewall_v2(extensions.ExtensionDescriptor):

    api_definition = firewall_v2

    @classmethod
    def get_name(cls):
        return firewall_v2.NAME

    @classmethod
    def get_alias(cls):
        return firewall_v2.ALIAS

    @classmethod
    def get_description(cls):
        return firewall_v2.DESCRIPTION

    @classmethod
    def get_updated(cls):
        return firewall_v2.UPDATED_TIMESTAMP

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, firewall_v2.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            firewall_v2.RESOURCE_ATTRIBUTE_MAP,
            firewall_v2.ALIAS,
            action_map=firewall_v2.ACTION_MAP,
            register_quota=True)

    @classmethod
    def get_plugin_interface(cls):
        return Firewallv2PluginBase

    def update_attributes_map(self, attributes):
        super(Firewall_v2, self).update_attributes_map(
            attributes, extension_attrs_map=firewall_v2.RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return firewall_v2.RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class Firewallv2PluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return fwaas_constants.FIREWALL_V2

    def get_plugin_type(self):
        return fwaas_constants.FIREWALL_V2

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
