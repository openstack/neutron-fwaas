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
from neutron.services import service_base
from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib.db import constants as nl_db_constants
from neutron_lib import exceptions as nexception
import six

from neutron_fwaas._i18n import _

# Import firewall v1 API to get the validators
# TODO(shpadubi): pull the validators out of fwaas v1 into a separate file
from neutron_fwaas.extensions import firewall as fwaas_v1

FIREWALL_PREFIX = '/fwaas'

FIREWALL_CONST = 'FIREWALL_V2'


# Firewall Exceptions
class FirewallGroupNotFound(nexception.NotFound):
    message = _("Firewall Group %(firewall_id)s could not be found.")


class FirewallGroupInUse(nexception.InUse):
    message = _("Firewall %(firewall_id)s is still active.")


class FirewallGroupInPendingState(nexception.Conflict):
    message = _("Operation cannot be performed since associated Firewall "
                "%(firewall_id)s is in %(pending_state)s.")


class FirewallGroupPortInvalid(nexception.Conflict):
    message = _("Firewall Group Port %(port_id)s is invalid")


class FirewallGroupPortInvalidProject(nexception.Conflict):
    message = _("Operation cannot be performed as port %(port_id)s "
                "is in an invalid project %(tenant_id)s.")


class FirewallGroupPortInUse(nexception.InUse):
    message = _("Port(s) %(port_ids)s provided already associated with "
                "other Firewall Group(s). ")


class FirewallPolicyNotFound(nexception.NotFound):
    message = _("Firewall Policy %(firewall_policy_id)s could not be found.")


class FirewallPolicyInUse(nexception.InUse):
    message = _("Firewall Policy %(firewall_policy_id)s is being used.")


class FirewallPolicyConflict(nexception.Conflict):
    """FWaaS exception for firewall policy

    Occurs when admin policy tries to use another tenant's policy that
    is not public.
    """

    message = _("Operation cannot be performed since Firewall Policy "
                "%(firewall_policy_id)s is not public and does not belong to "
                "your tenant.")


class FirewallRuleSharingConflict(nexception.Conflict):
    """FWaaS exception for firewall rules

    This exception will be raised when a public policy is created or
    updated with rules that are not public.
    """

    message = _("Operation cannot be performed since Firewall Policy "
                "%(firewall_policy_id)s is public but Firewall Rule "
                "%(firewall_rule_id)s is not public")


class FirewallPolicySharingConflict(nexception.Conflict):
    """FWaaS exception for firewall policy

    When a policy is public without sharing its associated rules,
    this exception will be raised.
    """

    message = _("Operation cannot be performed. Before sharing Firewall "
                "Policy %(firewall_policy_id)s, share associated Firewall "
                "Rule %(firewall_rule_id)s")


class FirewallRuleNotFound(nexception.NotFound):
    message = _("Firewall Rule %(firewall_rule_id)s could not be found.")


class FirewallRuleInUse(nexception.InUse):
    message = _("Firewall Rule %(firewall_rule_id)s is being used.")


class FirewallRuleNotAssociatedWithPolicy(nexception.InvalidInput):
    message = _("Firewall Rule %(firewall_rule_id)s is not associated "
                "with Firewall Policy %(firewall_policy_id)s.")


class FirewallRuleInvalidProtocol(nexception.InvalidInput):
    message = _("Firewall Rule protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class FirewallRuleInvalidAction(nexception.InvalidInput):
    message = _("Firewall rule action %(action)s is not supported. "
                "Only action values %(values)s are supported.")


class FirewallRuleInvalidICMPParameter(nexception.InvalidInput):
    message = _("%(param)s are not allowed when protocol "
                "is set to ICMP.")


class FirewallRuleWithPortWithoutProtocolInvalid(nexception.InvalidInput):
    message = _("Source/destination port requires a protocol")


class FirewallRuleInvalidPortValue(nexception.InvalidInput):
    message = _("Invalid value for port %(port)s.")


class FirewallRuleInfoMissing(nexception.InvalidInput):
    message = _("Missing rule info argument for insert/remove "
                "rule operation.")


class FirewallIpAddressConflict(nexception.InvalidInput):
    message = _("Invalid input - IP addresses do not agree with IP Version")


class FirewallInternalDriverError(nexception.NeutronException):
    """Fwaas exception for all driver errors.

    On any failure or exception in the driver, driver should log it and
    raise this exception to the agent
    """

    message = _("%(driver)s: Internal driver error.")


class FirewallRuleConflict(nexception.Conflict):
    """Firewall rule conflict exception.

    Occurs when admin policy tries to use another tenant's rule that is
    not public
    """

    message = _("Operation cannot be performed since Firewall Rule "
                "%(firewall_rule_id)s is not public and belongs to "
                "another tenant %(tenant_id)s")


class FirewallRuleAlreadyAssociated(nexception.Conflict):
    """Firewall rule conflict exception.

    Occurs when there is an attempt to assign a rule to a policy that
    the rule is already associated with.
    """

    message = _("Operation cannot be performed since Firewall Rule "
                "%(firewall_rule_id)s is already associated with Firewall"
                "Policy %(firewall_policy_id)s")


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
        'public': {'allow_post': True, 'allow_put': True,
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
        'public': {'allow_post': True, 'allow_put': True, 'default': False,
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
        'public': {'allow_post': True, 'allow_put': True, 'default': False,
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
