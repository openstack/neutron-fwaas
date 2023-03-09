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
        'shared_firewall_groups',
        'field:firewall_groups:shared=True',
        'Definition of shared firewall groups'
    ),

    policy.DocumentedRuleDefault(
        'create_firewall_group',
        base.RULE_ANY,
        'Create a firewall group',
        [
            {
                'method': 'POST',
                'path': '/fwaas/firewall_groups',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall_group',
        base.RULE_ADMIN_OR_OWNER,
        'Update a firewall group',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_groups/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_firewall_group',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a firewall group',
        [
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_groups/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_firewall_group:shared',
        base.RULE_ADMIN_ONLY,
        'Create a shared firewall group',
        [
            {
                'method': 'POST',
                'path': '/fwaas/firewall_groups',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall_group:shared',
        base.RULE_ADMIN_ONLY,
        'Update ``shared`` attribute of a firewall group',
        [
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_groups/{id}',
            },
        ]
    ),
    # TODO(amotoki): Drop this rule as it has no effect.
    policy.DocumentedRuleDefault(
        'delete_firewall_group:shared',
        base.RULE_ADMIN_ONLY,
        'Delete a shared firewall group',
        [
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_groups/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_firewall_group',
        'rule:admin_or_owner or rule:shared_firewall_groups',
        'Get firewall groups',
        [
            {
                'method': 'GET',
                'path': '/fwaas/firewall_groups',
            },
            {
                'method': 'GET',
                'path': '/fwaas/firewall_groups/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
