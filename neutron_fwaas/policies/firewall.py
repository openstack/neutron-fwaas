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

from oslo_policy import policy

from neutron_fwaas.policies import base


rules = [
    policy.RuleDefault(
        'shared_firewalls',
        'field:firewalls:shared=True',
        '(FWaaS v1) Definition of shared firewalls'
    ),

    policy.DocumentedRuleDefault(
        'create_firewall',
        base.RULE_ANY,
        '(FWaaS v1) Create a firewall',
        [
            {
                'method': 'POST',
                'path': '/fw/firewalls',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall',
        base.RULE_ADMIN_OR_OWNER,
        '(FWaaS v1) Update a firewall',
        [
            {
                'method': 'PUT',
                'path': '/fw/firewalls/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_firewall',
        base.RULE_ADMIN_OR_OWNER,
        '(FWaaS v1) Delete a firewall',
        [
            {
                'method': 'DELETE',
                'path': '/fw/firewalls/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_firewall:shared',
        base.RULE_ADMIN_ONLY,
        '(FWaaS v1) Create a shared firewall',
        [
            {
                'method': 'POST',
                'path': '/fw/firewalls',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_firewall:shared',
        base.RULE_ADMIN_ONLY,
        '(FWaaS v1) Update ``shared`` attribute of a firewall',
        [
            {
                'method': 'PUT',
                'path': '/fw/firewalls/{id}',
            },
        ]
    ),
    # TODO(amotoki): Drop this rule as it has no effect.
    policy.DocumentedRuleDefault(
        'delete_firewall:shared',
        base.RULE_ADMIN_ONLY,
        '(FWaaS v1) Delete a shared firewall',
        [
            {
                'method': 'DELETE',
                'path': '/fw/firewalls/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'get_firewall',
        'rule:admin_or_owner or rule:shared_firewalls',
        '(FWaaS v1) Get firewalls',
        [
            {
                'method': 'GET',
                'path': '/fw/firewalls',
            },
            {
                'method': 'GET',
                'path': '/fw/firewalls/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
