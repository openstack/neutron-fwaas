#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from neutron_lib import policy as base
from oslo_policy import policy


rules = [
    policy.RuleDefault(
        'shared_firewall_policies',
        'field:firewall_policies:shared=True',
        'Definition of shared firewall policies'
    ),

    policy.DocumentedRuleDefault(
        'create_firewall_policy',
        base.RULE_ANY,
        'Create a firewall policy',
        [
            {
                'method': 'POST',
                'path': '/fwaas/firewall_policies',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall_policy',
        base.RULE_ADMIN_OR_OWNER,
        'Update a firewall policy',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_firewall_policy',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a firewall policy',
        [
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_firewall_policy:shared',
        base.RULE_ADMIN_ONLY,
        'Create a shared firewall policy',
        [
            {
                'method': 'POST',
                'path': '/fwaas/firewall_policies',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall_policy:shared',
        base.RULE_ADMIN_ONLY,
        'Update ``shared`` attribute of a firewall policy',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ]
    ),
    # TODO(amotoki): Drop this rule as it has no effect.
    policy.DocumentedRuleDefault(
        'delete_firewall_policy:shared',
        base.RULE_ADMIN_ONLY,
        'Delete a shread firewall policy',
        [
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_firewall_policy',
        'rule:admin_or_owner or rule:shared_firewall_policies',
        'Get firewall policies',
        [
            {
                'method': 'GET',
                'path': '/fwaas/firewall_policies',
            },
            {
                'method': 'GET',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
