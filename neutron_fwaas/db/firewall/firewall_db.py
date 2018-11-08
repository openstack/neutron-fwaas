# Copyright 2013 Big Switch Networks, Inc.
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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm


# Note(annp): Keep firewall db v1 structure for migration
class FirewallRule(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a Firewall rule."""
    __tablename__ = 'firewall_rules'
    __table_args__ = ({'mysql_collate': 'utf8_bin'})
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(40))
    ip_version = sa.Column(sa.Integer, nullable=False)
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
    action = sa.Column(sa.Enum('allow', 'deny', 'reject',
                               name='firewallrules_action'))
    enabled = sa.Column(sa.Boolean)
    position = sa.Column(sa.Integer)


class Firewall(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a Firewall resource."""
    __tablename__ = 'firewalls'
    __table_args__ = ({'mysql_collate': 'utf8_bin'})
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(16))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)


class FirewallPolicy(model_base.BASEV2, model_base.HasId,
                     model_base.HasProject):
    """Represents a Firewall Policy resource."""
    __tablename__ = 'firewall_policies'
    __table_args__ = ({'mysql_collate': 'utf8_bin'})
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    firewall_rules = orm.relationship(
        FirewallRule,
        backref=orm.backref('firewall_policies', cascade='all, delete'),
        order_by='FirewallRule.position',
        collection_class=ordering_list('position', count_from=1))
    audited = sa.Column(sa.Boolean)
    firewalls = orm.relationship(Firewall, backref='firewall_policies')


class FirewallRouterAssociation(model_base.BASEV2):

    """Tracks FW Router Association"""

    __tablename__ = 'firewall_router_associations'

    fw_id = sa.Column(sa.String(36),
        sa.ForeignKey('firewalls.id', ondelete="CASCADE"),
        primary_key=True)
    router_id = sa.Column(sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
