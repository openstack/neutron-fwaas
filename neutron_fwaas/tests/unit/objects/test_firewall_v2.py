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

import random

from neutron_lib.api.definitions import constants as api_const

from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api

from neutron_fwaas.objects import firewall_v2


def get_random_firewall_rule_action():
    return random.choice(api_const.FW_VALID_ACTION_VALUES)


def get_random_firewall_group_status():
    return random.choice(firewall_v2.FW_VALID_STATUS_VALUES)


test_base.FIELD_TYPE_VALUE_GENERATOR_MAP[
    firewall_v2.FirewallRuleActionEnumField] = (
        get_random_firewall_rule_action)
test_base.FIELD_TYPE_VALUE_GENERATOR_MAP[
    firewall_v2.FirewallGroupStatusEnumField] = (
        get_random_firewall_group_status)


class _FirewallGroupRelatedObjectsMixin:
    """Mixin providing helpers to create dependent firewall objects in the DB.

    The FK dependencies are:
      FirewallPolicyRuleAssociation -> FirewallPolicy, FirewallRuleV2
      FirewallGroupPortAssociation -> FirewallGroup
      FirewallGroup -> FirewallPolicy (ingress/egress)
      DefaultFirewallGroup -> FirewallGroup
    """

    def _create_test_firewall_rule_id(self):
        obj_fields = self.get_random_object_fields(
            firewall_v2.FirewallRuleV2)
        rule = firewall_v2.FirewallRuleV2(self.context, **obj_fields)
        rule.create()
        return rule.id

    def _create_test_firewall_policy_id(self):
        obj_fields = self.get_random_object_fields(
            firewall_v2.FirewallPolicy)
        policy = firewall_v2.FirewallPolicy(self.context, **obj_fields)
        policy.create()
        return policy.id

    def _create_test_firewall_group_id(self):
        obj_fields = self.get_random_object_fields(
            firewall_v2.FirewallGroup)
        obj_fields['ingress_firewall_policy_id'] = None
        obj_fields['egress_firewall_policy_id'] = None
        group = firewall_v2.FirewallGroup(self.context, **obj_fields)
        group.create()
        return group.id


class FirewallRuleV2IfaceTestCase(test_base.BaseObjectIfaceTestCase):
    _test_class = firewall_v2.FirewallRuleV2


class FirewallRuleV2DbTestCase(test_base.BaseDbObjectTestCase,
                               testlib_api.SqlTestCase):
    _test_class = firewall_v2.FirewallRuleV2


class FirewallPolicyRuleAssociationIfaceTestCase(
        test_base.BaseObjectIfaceTestCase):
    _test_class = firewall_v2.FirewallPolicyRuleAssociation


class FirewallPolicyRuleAssociationDbTestCase(
        _FirewallGroupRelatedObjectsMixin,
        test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase):
    _test_class = firewall_v2.FirewallPolicyRuleAssociation

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'firewall_policy_id':
                    lambda: self._create_test_firewall_policy_id(),
                'firewall_rule_id':
                    lambda: self._create_test_firewall_rule_id(),
            })


class FirewallPolicyIfaceTestCase(test_base.BaseObjectIfaceTestCase):
    _test_class = firewall_v2.FirewallPolicy


class FirewallPolicyDbTestCase(test_base.BaseDbObjectTestCase,
                               testlib_api.SqlTestCase):
    _test_class = firewall_v2.FirewallPolicy


class FirewallGroupPortAssociationIfaceTestCase(
        test_base.BaseObjectIfaceTestCase):
    _test_class = firewall_v2.FirewallGroupPortAssociation


class FirewallGroupPortAssociationDbTestCase(
        _FirewallGroupRelatedObjectsMixin,
        test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase):
    _test_class = firewall_v2.FirewallGroupPortAssociation

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'firewall_group_id':
                    lambda: self._create_test_firewall_group_id(),
                'port_id':
                    lambda: self._create_test_port_id(),
            })


class FirewallGroupIfaceTestCase(test_base.BaseObjectIfaceTestCase):
    _test_class = firewall_v2.FirewallGroup


class FirewallGroupDbTestCase(
        _FirewallGroupRelatedObjectsMixin,
        test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase):
    _test_class = firewall_v2.FirewallGroup

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'ingress_firewall_policy_id':
                    lambda: self._create_test_firewall_policy_id(),
                'egress_firewall_policy_id':
                    lambda: self._create_test_firewall_policy_id(),
            })


class DefaultFirewallGroupIfaceTestCase(test_base.BaseObjectIfaceTestCase):
    _test_class = firewall_v2.DefaultFirewallGroup


class DefaultFirewallGroupDbTestCase(
        _FirewallGroupRelatedObjectsMixin,
        test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase):
    _test_class = firewall_v2.DefaultFirewallGroup

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'firewall_group_id':
                    lambda: self._create_test_firewall_group_id(),
            })
