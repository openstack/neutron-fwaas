# Copyright (c) 2015 Midokura SARL
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

from tempest.lib import exceptions as lib_exc
from tempest.lib.services.network import base


class FirewallsClient(base.BaseNetworkClient):

    def create_firewall(self, **kwargs):
        uri = '/fw/firewalls'
        post_data = {'firewall': kwargs}
        return self.create_resource(uri, post_data)

    def update_firewall(self, firewall_id, **kwargs):
        uri = '/fw/firewalls/%s' % firewall_id
        post_data = {'firewall': kwargs}
        return self.update_resource(uri, post_data)

    def show_firewall(self, firewall_id, **fields):
        uri = '/fw/firewalls/%s' % firewall_id
        return self.show_resource(uri, **fields)

    def delete_firewall(self, firewall_id):
        uri = '/fw/firewalls/%s' % firewall_id
        return self.delete_resource(uri)

    def list_firewalls(self, **filters):
        uri = '/fw/firewalls'
        return self.list_resources(uri, **filters)

    def is_resource_deleted(self, id):
        try:
            self.show_firewall(id)
        except lib_exc.NotFound:
            return True
        return False

    @property
    def resource_type(self):
        """Returns the primary type of resource this client works with."""
        return 'firewall'


class FirewallRulesClient(base.BaseNetworkClient):

    def create_firewall_rule(self, **kwargs):
        uri = '/fw/firewall_rules'
        post_data = {'firewall_rule': kwargs}
        return self.create_resource(uri, post_data)

    def update_firewall_rule(self, firewall_rule_id, **kwargs):
        uri = '/fw/firewall_rules/%s' % firewall_rule_id
        post_data = {'firewall_rule': kwargs}
        return self.update_resource(uri, post_data)

    def show_firewall_rule(self, firewall_rule_id, **fields):
        uri = '/fw/firewall_rules/%s' % firewall_rule_id
        return self.show_resource(uri, **fields)

    def delete_firewall_rule(self, firewall_rule_id):
        uri = '/fw/firewall_rules/%s' % firewall_rule_id
        return self.delete_resource(uri)

    def list_firewall_rules(self, **filters):
        uri = '/fw/firewall_rules'
        return self.list_resources(uri, **filters)


class FirewallPoliciesClient(base.BaseNetworkClient):

    def create_firewall_policy(self, **kwargs):
        uri = '/fw/firewall_policies'
        post_data = {'firewall_policy': kwargs}
        return self.create_resource(uri, post_data)

    def update_firewall_policy(self, firewall_policy_id, **kwargs):
        uri = '/fw/firewall_policies/%s' % firewall_policy_id
        post_data = {'firewall_policy': kwargs}
        return self.update_resource(uri, post_data)

    def show_firewall_policy(self, firewall_policy_id, **fields):
        uri = '/fw/firewall_policies/%s' % firewall_policy_id
        return self.show_resource(uri, **fields)

    def delete_firewall_policy(self, firewall_policy_id):
        uri = '/fw/firewall_policies/%s' % firewall_policy_id
        return self.delete_resource(uri)

    def list_firewall_policies(self, **filters):
        uri = '/fw/firewall_policies'
        return self.list_resources(uri, **filters)

    def insert_firewall_rule_in_policy(self, firewall_policy_id,
                                       firewall_rule_id, insert_after='',
                                       insert_before=''):
        uri = '/fw/firewall_policies/%s/insert_rule' % firewall_policy_id
        data = {
            'firewall_rule_id': firewall_rule_id,
            'insert_after': insert_after,
            'insert_before': insert_before,
        }
        return self.update_resource(uri, data)

    def remove_firewall_rule_from_policy(self, firewall_policy_id,
                                         firewall_rule_id):
        uri = '/fw/firewall_policies/%s/remove_rule' % firewall_policy_id
        data = {
            'firewall_rule_id': firewall_rule_id,
        }
        return self.update_resource(uri, data)
