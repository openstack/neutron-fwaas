# Copyright (c) 2016
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

from neutron_lib.api.definitions import constants as api_const
from neutron_lib.db import constants as db_constants
from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm


class FirewallRuleV2(standard_attr.HasStandardAttributes, model_base.BASEV2,
                     model_base.HasId, model_base.HasProject):
    __tablename__ = "firewall_rules_v2"
    name = sa.Column(sa.String(db_constants.NAME_FIELD_SIZE))
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(40))
    ip_version = sa.Column(sa.Integer)
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
    action = sa.Column(sa.Enum(*api_const.FW_VALID_ACTION_VALUES,
                               name='firewallrules_action'))
    enabled = sa.Column(sa.Boolean)
    api_collections = ['firewall_rules']
    collection_resource_map = {"firewall_rules": "firewall_rule"}
    tag_support = True


class FirewallGroup(standard_attr.HasStandardAttributes, model_base.BASEV2,
                    model_base.HasId, model_base.HasProject):
    __tablename__ = 'firewall_groups_v2'
    port_associations = orm.relationship(
        'FirewallGroupPortAssociation',
        backref=orm.backref('firewall_group_port_associations_v2',
                            cascade='all, delete'))
    name = sa.Column(sa.String(db_constants.NAME_FIELD_SIZE))
    ingress_firewall_policy_id = sa.Column(
        sa.String(db_constants.UUID_FIELD_SIZE),
        sa.ForeignKey('firewall_policies_v2.id'))
    egress_firewall_policy_id = sa.Column(
        sa.String(db_constants.UUID_FIELD_SIZE),
        sa.ForeignKey('firewall_policies_v2.id'))
    ingress_firewall_policy = orm.relationship(
        'FirewallPolicy',
        foreign_keys=[ingress_firewall_policy_id],
        lazy='joined')
    egress_firewall_policy = orm.relationship(
        'FirewallPolicy',
        foreign_keys=[egress_firewall_policy_id],
        lazy='joined')
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(db_constants.STATUS_FIELD_SIZE))
    shared = sa.Column(sa.Boolean)
    api_collections = ['firewall_groups']
    collection_resource_map = {"firewall_groups": "firewall_group"}
    tag_support = True


class DefaultFirewallGroup(model_base.BASEV2, model_base.HasProjectPrimaryKey):
    __tablename__ = "default_firewall_groups"
    firewall_group_id = sa.Column(sa.String(db_constants.UUID_FIELD_SIZE),
                                  sa.ForeignKey('firewall_groups_v2.id',
                                                ondelete="CASCADE"),
                                  nullable=False)
    firewall_group = orm.relationship(
        FirewallGroup, lazy='joined',
        backref=orm.backref('default_firewall_group', cascade='all,delete'),
        primaryjoin="FirewallGroup.id==DefaultFirewallGroup.firewall_group_id",
    )


class FirewallGroupPortAssociation(model_base.BASEV2):
    __tablename__ = 'firewall_group_port_associations_v2'
    firewall_group_id = sa.Column(sa.String(db_constants.UUID_FIELD_SIZE),
                                  sa.ForeignKey('firewall_groups_v2.id',
                                                ondelete="CASCADE"),
                                  primary_key=True)
    port_id = sa.Column(sa.String(db_constants.UUID_FIELD_SIZE),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        unique=True,
                        primary_key=True)


class FirewallPolicyRuleAssociation(model_base.BASEV2):

    """Tracks FW Policy and Rule(s) Association"""

    __tablename__ = 'firewall_policy_rule_associations_v2'

    firewall_policy_id = sa.Column(sa.String(db_constants.UUID_FIELD_SIZE),
                                   sa.ForeignKey('firewall_policies_v2.id',
                                                 ondelete="CASCADE"),
                                   primary_key=True)
    firewall_rule_id = sa.Column(sa.String(db_constants.UUID_FIELD_SIZE),
                                 sa.ForeignKey('firewall_rules_v2.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    position = sa.Column(sa.Integer)


class FirewallPolicy(standard_attr.HasStandardAttributes, model_base.BASEV2,
                     model_base.HasId, model_base.HasProject):
    __tablename__ = 'firewall_policies_v2'
    name = sa.Column(sa.String(db_constants.NAME_FIELD_SIZE))
    rule_count = sa.Column(sa.Integer)
    audited = sa.Column(sa.Boolean)
    rule_associations = orm.relationship(
        FirewallPolicyRuleAssociation,
        backref=orm.backref('firewall_policies_v2', cascade='all, delete'),
        order_by='FirewallPolicyRuleAssociation.position',
        collection_class=ordering_list('position', count_from=1))
    shared = sa.Column(sa.Boolean)
    api_collections = ['firewall_policies']
    collection_resource_map = {"firewall_policies": "firewall_policy"}
    tag_support = True
