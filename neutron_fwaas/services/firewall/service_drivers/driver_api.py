# Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
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
import copy

import six

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as nl_constants
from neutron_lib.plugins import directory
from oslo_log import log as logging

from neutron_fwaas.common import fwaas_constants as const
from neutron_fwaas.db.firewall.v2 import firewall_db_v2


LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class FirewallDriver(object):
    """Firewall v2 interface for driver

    That driver interface does not persist Firewall v2 data in any database.
    The driver needs to do it by itself.
    """

    def __init__(self, service_plugin):
        self.service_plugin = service_plugin

    @property
    def _core_plugin(self):
        return directory.get_plugin()

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
    def insert_rule(self, context, policy_id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule(self, context, policy_id, rule_info):
        pass


@six.add_metaclass(abc.ABCMeta)
class FirewallDriverDBMixin(FirewallDriver):
    """FirewallDriverDB mixin to provision the database on behalf of the driver

    That driver interface persists Firewall data in its database and forwards
    the result to pre and post commit methods.
    """

    def __init__(self, *args, **kwargs):
        super(FirewallDriverDBMixin, self).__init__(*args, **kwargs)
        self.firewall_db = firewall_db_v2.FirewallPluginDb()

    @staticmethod
    def _update_resource_status(context, resource_type, resource_dict):
        with context.session.begin(subtransactions=True):
            context.session.query(resource_type).\
                                  filter_by(id=resource_dict['id']).\
                                  update({'status': resource_dict['status']})

    # Firewall Group
    def create_firewall_group(self, context, firewall_group):
        request_body = firewall_group
        with context.session.begin(subtransactions=True):
            firewall_group = self.firewall_db.create_firewall_group(
                context, firewall_group)
            self.create_firewall_group_precommit(context, firewall_group)
            self._update_resource_status(context, firewall_db_v2.FirewallGroup,
                                         firewall_group)
        self.create_firewall_group_postcommit(context, firewall_group)

        payload = events.DBEventPayload(context=context,
                                        resource_id=firewall_group['id'],
                                        request_body=request_body,
                                        states=(firewall_group,))
        registry.publish(
            const.FIREWALL_GROUP, events.AFTER_CREATE, self, payload=payload)
        return firewall_group

    @abc.abstractmethod
    def create_firewall_group_precommit(self, context, firewall_group):
        pass

    @abc.abstractmethod
    def create_firewall_group_postcommit(self, context, firewall_group):
        pass

    def delete_firewall_group(self, context, id):
        firewall_group = self.firewall_db.get_firewall_group(context, id)
        if firewall_group['status'] == nl_constants.PENDING_DELETE:
            firewall_group['status'] = nl_constants.ERROR
        self.delete_firewall_group_precommit(context, firewall_group)
        if firewall_group['status'] != nl_constants.PENDING_DELETE:
            # lets driver deleting firewall group later
            self.firewall_db.delete_firewall_group(context, id)
        self.delete_firewall_group_postcommit(context, firewall_group)

        payload = events.DBEventPayload(context=context,
                                        resource_id=id,
                                        states=(firewall_group,))
        registry.publish(
            const.FIREWALL_GROUP, events.AFTER_DELETE, self, payload=payload)

    @abc.abstractmethod
    def delete_firewall_group_precommit(self, context, firewall_group):
        pass

    @abc.abstractmethod
    def delete_firewall_group_postcommit(self, context, firewall_group):
        pass

    def get_firewall_group(self, context, id, fields=None):
        return self.firewall_db.get_firewall_group(context, id, fields=fields)

    def get_firewall_groups(self, context, filters=None, fields=None):
        return self.firewall_db.get_firewall_groups(context, filters, fields)

    def update_firewall_group(self, context, id, firewall_group_delta):
        old_firewall_group = self.firewall_db.get_firewall_group(context, id)
        new_firewall_group = copy.deepcopy(old_firewall_group)
        new_firewall_group.update(firewall_group_delta)
        self.update_firewall_group_precommit(context, old_firewall_group,
                                             new_firewall_group)
        firewall_group_delta['status'] = new_firewall_group['status']
        firewall_group = self.firewall_db.update_firewall_group(
            context, id, firewall_group_delta)
        self.update_firewall_group_postcommit(context, old_firewall_group,
                                              firewall_group)

        payload = events.DBEventPayload(context=context,
                                        resource_id=id,
                                        states=(old_firewall_group,
                                                new_firewall_group))
        registry.publish(
            const.FIREWALL_GROUP, events.AFTER_UPDATE, self, payload=payload)

        return firewall_group

    @abc.abstractmethod
    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        pass

    @abc.abstractmethod
    def update_firewall_group_postcommit(self, context, old_firewall_group,
                                         new_firewall_group):
        pass

    # Firewall Policy
    def create_firewall_policy(self, context, firewall_policy):
        request_body = firewall_policy
        with context.session.begin(subtransactions=True):
            firewall_policy = self.firewall_db.create_firewall_policy(
                context, firewall_policy)
            self.create_firewall_policy_precommit(context, firewall_policy)
        self.create_firewall_policy_postcommit(context, firewall_policy)

        payload = events.DBEventPayload(context=context,
                                        resource_id=firewall_policy['id'],
                                        request_body=request_body,
                                        states=(firewall_policy,))
        registry.publish(
            const.FIREWALL_POLICY, events.AFTER_CREATE, self, payload=payload)
        return firewall_policy

    @abc.abstractmethod
    def create_firewall_policy_precommit(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def create_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    def delete_firewall_policy(self, context, id):
        firewall_policy = self.firewall_db.get_firewall_policy(context, id)
        self.delete_firewall_policy_precommit(context, firewall_policy)
        self.firewall_db.delete_firewall_policy(context, id)
        self.delete_firewall_policy_postcommit(context, firewall_policy)

        payload = events.DBEventPayload(context=context,
                                        resource_id=id,
                                        states=(firewall_policy,))
        registry.publish(
            const.FIREWALL_POLICY, events.AFTER_UPDATE, self, payload=payload)

    @abc.abstractmethod
    def delete_firewall_policy_precommit(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def delete_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    def get_firewall_policy(self, context, id, fields=None):
        return self.firewall_db.get_firewall_policy(context, id, fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        return self.firewall_db.get_firewall_policies(context, filters, fields)

    def update_firewall_policy(self, context, id, firewall_policy_delta):
        old_firewall_policy = self.firewall_db.get_firewall_policy(context, id)
        new_firewall_policy = copy.deepcopy(old_firewall_policy)
        new_firewall_policy.update(firewall_policy_delta)
        self.update_firewall_policy_precommit(context, old_firewall_policy,
                                              new_firewall_policy)
        firewall_policy = self.firewall_db.update_firewall_policy(
            context, id, firewall_policy_delta)
        self.update_firewall_policy_postcommit(context, old_firewall_policy,
                                               firewall_policy)

        payload = events.DBEventPayload(context=context,
                                        resource_id=id,
                                        states=(firewall_policy,))
        registry.publish(
            const.FIREWALL_POLICY, events.AFTER_UPDATE, self, payload=payload)
        return firewall_policy

    @abc.abstractmethod
    def update_firewall_policy_precommit(self, context, old_firewall_policy,
                                         new_firewall_policy):
        pass

    @abc.abstractmethod
    def update_firewall_policy_postcommit(self, context, old_firewall_policy,
                                          new_firewall_policy):
        pass

    # Firewall Rule
    def create_firewall_rule(self, context, firewall_rule):
        request_body = firewall_rule
        with context.session.begin(subtransactions=True):
            firewall_rule = self.firewall_db.create_firewall_rule(
                context, firewall_rule)
            self.create_firewall_rule_precommit(context, firewall_rule)
        self.create_firewall_rule_postcommit(context, firewall_rule)

        payload = events.DBEventPayload(context=context,
                                        resource_id=firewall_rule['id'],
                                        request_body=request_body,
                                        states=(firewall_rule,))
        registry.publish(
            const.FIREWALL_RULE, events.AFTER_CREATE, self, payload=payload)
        return firewall_rule

    @abc.abstractmethod
    def create_firewall_rule_precommit(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def create_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def delete_firewall_rule(self, context, id):
        firewall_rule = self.firewall_db.get_firewall_rule(context, id)
        self.delete_firewall_rule_precommit(context, firewall_rule)
        self.firewall_db.delete_firewall_rule(context, id)
        self.delete_firewall_rule_postcommit(context, firewall_rule)

        payload = events.DBEventPayload(context=context,
                                        resource_id=id,
                                        states=(firewall_rule,))
        registry.publish(
            const.FIREWALL_RULE, events.AFTER_DELETE, self, payload=payload)

    @abc.abstractmethod
    def delete_firewall_rule_precommit(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def delete_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def get_firewall_rule(self, context, id, fields=None):
        return self.firewall_db.get_firewall_rule(context, id, fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        return self.firewall_db.get_firewall_rules(context, filters, fields)

    def update_firewall_rule(self, context, id, firewall_rule_delta):
        old_firewall_rule = self.firewall_db.get_firewall_rule(context, id)
        new_firewall_rule = copy.deepcopy(old_firewall_rule)
        new_firewall_rule.update(firewall_rule_delta)
        self.update_firewall_rule_precommit(context, old_firewall_rule,
                                            new_firewall_rule)
        firewall_rule = self.firewall_db.update_firewall_rule(
            context, id, firewall_rule_delta)
        self.update_firewall_rule_postcommit(context, old_firewall_rule,
                                             firewall_rule)

        payload = events.DBEventPayload(context=context,
                                        resource_id=id,
                                        states=(firewall_rule,))
        registry.publish(
            const.FIREWALL_RULE, events.AFTER_UPDATE, self, payload=payload)

        return firewall_rule

    @abc.abstractmethod
    def update_firewall_rule_precommit(self, context, old_firewall_rule,
                                       new_firewall_rule):
        pass

    @abc.abstractmethod
    def update_firewall_rule_postcommit(self, context, old_firewall_rule,
                                        new_firewall_rule):
        pass

    def insert_rule(self, context, policy_id, rule_info):
        self.insert_rule_precommit(context, policy_id, rule_info)
        firewall_policy = self.firewall_db.insert_rule(context, policy_id,
                                                       rule_info)
        self.insert_rule_postcommit(context, policy_id, rule_info)
        payload = events.DBEventPayload(context=context,
                                        resource_id=policy_id,
                                        states=(firewall_policy,))
        registry.publish(
            const.FIREWALL_POLICY, events.AFTER_UPDATE, self, payload=payload)

        return firewall_policy

    @abc.abstractmethod
    def insert_rule_precommit(self, context, policy_id, rule_info):
        pass

    @abc.abstractmethod
    def insert_rule_postcommit(self, context, policy_id, rule_info):
        pass

    def remove_rule(self, context, policy_id, rule_info):
        self.remove_rule_precommit(context, policy_id, rule_info)
        firewall_policy = self.firewall_db.remove_rule(context, policy_id,
                                                       rule_info)
        self.remove_rule_postcommit(context, policy_id, rule_info)
        payload = events.DBEventPayload(context=context,
                                        resource_id=policy_id,
                                        states=(firewall_policy,))

        registry.publish(
            const.FIREWALL_POLICY, events.AFTER_UPDATE, self, payload=payload)
        return firewall_policy

    @abc.abstractmethod
    def remove_rule_precommit(self, context, policy_id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule_postcommit(self, context, policy_id, rule_info):
        pass


class FirewallDriverDB(FirewallDriverDBMixin):
    """FirewallDriverDBMixin interface for driver with database.

    Each firewall backend driver that needs a database persistency should
    inherit from this driver.
    It can overload needed methods from the following pre/postcommit methods.
    Any exception raised during a precommit method will result in not having
    related records in the databases.
    """

    #Firewal Group
    def create_firewall_group_precommit(self, context, firewall_group):
        pass

    def create_firewall_group_postcommit(self, context, firewall_group):
        pass

    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        pass

    def update_firewall_group_postcommit(self, context, old_firewall_group,
                                         new_firewall_group):
        pass

    def delete_firewall_group_precommit(self, context, firewall_group):
        pass

    def delete_firewall_group_postcommit(self, context, firewall_group):
        pass

    #Firewall Policy
    def create_firewall_policy_precommit(self, context, firewall_policy):
        pass

    def create_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    def update_firewall_policy_precommit(self, context, old_firewall_policy,
                                         new_firewall_policy):
        pass

    def update_firewall_policy_postcommit(self, context, old_firewall_policy,
                                          new_firewall_policy):
        pass

    def delete_firewall_policy_precommit(self, context, firewall_policy):
        pass

    def delete_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    #Firewall Rule
    def create_firewall_rule_precommit(self, context, firewall_rule):
        pass

    def create_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def update_firewall_rule_precommit(self, context, old_firewall_rule,
                                       new_firewall_rule):
        pass

    def update_firewall_rule_postcommit(self, context, old_firewall_rule,
                                        new_firewall_rule):
        pass

    def delete_firewall_rule_precommit(self, context, firewall_rule):
        pass

    def delete_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def insert_rule_precommit(self, context, policy_id, rule_info):
        pass

    def insert_rule_postcommit(self, context, policy_id, rule_info):
        pass

    def remove_rule_precommit(self, context, policy_id, rule_info):
        pass

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        pass


@six.add_metaclass(abc.ABCMeta)
class FirewallDriverRPCMixin(object):
    """FirewallAgent interface for driver with rpc callback listener.

    Each firewall backend driver that needs a rpc callback listener should
    inherit from this driver.
    """

    @abc.abstractmethod
    def start_rpc_listener(self):
        pass
