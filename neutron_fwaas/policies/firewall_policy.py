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

from neutron.conf.policies import base as neutron_base
from neutron_lib import policy as base
from oslo_policy import policy

DEPRECATED_REASON = """
The FWaaS API now supports Secure RBAC default roles.
"""


rules = [
    policy.RuleDefault(
        name='shared_firewall_policies',
        check_str='field:firewall_policies:shared=True',
        description='Definition of shared firewall policies'
    ),

    policy.DocumentedRuleDefault(
        name='create_firewall_policy',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a firewall policy',
        operations=[
            {
                'method': 'POST',
                'path': '/fwaas/firewall_policies',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_firewall_policy',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    policy.DocumentedRuleDefault(
        name='update_firewall_policy',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update a firewall policy',
        operations=[
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_firewall_policy',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    policy.DocumentedRuleDefault(
        name='delete_firewall_policy',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a firewall policy',
        operations=[
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_firewall_policy',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),

    policy.DocumentedRuleDefault(
        name='create_firewall_policy:shared',
        check_str=neutron_base.ADMIN,
        scope_types=['project'],
        description='Create a shared firewall policy',
        operations=[
            {
                'method': 'POST',
                'path': '/fwaas/firewall_policies',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_firewall_policy:shared',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    policy.DocumentedRuleDefault(
        name='update_firewall_policy:shared',
        check_str=neutron_base.ADMIN,
        scope_types=['project'],
        description='Update ``shared`` attribute of a firewall policy',
        operations=[
            {
                'method': 'PUT',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_firewall_policy:shared',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    # TODO(amotoki): Drop this rule as it has no effect.
    policy.DocumentedRuleDefault(
        name='delete_firewall_policy:shared',
        check_str=neutron_base.ADMIN,
        scope_types=['project'],
        description='Delete a shread firewall policy',
        operations=[
            {
                'method': 'DELETE',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_firewall_policy:shared',
            check_str=base.RULE_ADMIN_ONLY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),

    policy.DocumentedRuleDefault(
        name='get_firewall_policy',
        check_str=base.policy_or(
            neutron_base.ADMIN_OR_PROJECT_READER,
            'rule:shared_firewall_policies'),
        scope_types=['project'],
        description='Get firewall policies',
        operations=[
            {
                'method': 'GET',
                'path': '/fwaas/firewall_policies',
            },
            {
                'method': 'GET',
                'path': '/fwaas/firewall_policies/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_firewall_policy',
            check_str='rule:admin_or_owner or rule:shared_firewall_policies',
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
]


def list_rules():
    return rules
