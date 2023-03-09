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
        'shared_firewall_rules',
        'field:firewall_rules:shared=True',
        'Definition of shared firewall rules'
    ),

    policy.DocumentedRuleDefault(
        'create_firewall_rule',
        base.RULE_ANY,
        'Create a firewall rule',
        [
            {
                'method': 'POST',
                'path': '/fwaas/firewall_rules',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Update a firewall rule',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_rules/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_firewall_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a firewall rule',
        [
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_rules/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_firewall_rule:shared',
        base.RULE_ADMIN_ONLY,
        'Create a shared firewall rule',
        [
            {
                'method': 'POST',
                'path': '/fwaas/firewall_rules',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall_rule:shared',
        base.RULE_ADMIN_ONLY,
        'Update ``shared`` attribute of a firewall rule',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_rules/{id}',
            },
        ]
    ),
    # TODO(amotoki): Drop this rule as it has no effect.
    policy.DocumentedRuleDefault(
        'delete_firewall_rule:shared',
        base.RULE_ADMIN_ONLY,
        'Delete a shread firewall rule',
        [
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_rules/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_firewall_rule',
        'rule:admin_or_owner or rule:shared_firewall_rules',
        'Get firewall rules',
        [
            {
                'method': 'GET',
                'path': '/fwaas/firewall_rules',
            },
            {
                'method': 'GET',
                'path': '/fwaas/firewall_rules/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'insert_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Insert rule into a firewall policy',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_policies/{id}/insert_rule',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'remove_rule',
        base.RULE_ADMIN_OR_OWNER,
        'Remove rule from a firewall policy',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_policies/{id}/remove_rule',
            },
        ]
    ),
]


def list_rules():
    return rules
