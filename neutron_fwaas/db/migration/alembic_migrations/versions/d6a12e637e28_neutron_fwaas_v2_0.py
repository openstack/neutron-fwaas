# Copyright 2016 OpenStack Foundation
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
#

"""neutron-fwaas v2.0

Revision ID: d6a12e637e28
Revises: kilo
Create Date: 2016-06-08 19:57:13.848855

"""

# revision identifiers, used by Alembic.
revision = 'd6a12e637e28'
down_revision = 'kilo'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'firewall_policies_v2',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=1024)),
        sa.Column('project_id', sa.String(length=36), index=True),
        sa.Column('audited', sa.Boolean),
        sa.Column('public', sa.Boolean),
        sa.Column('rule_count', sa.Integer))

    op.create_table(
        'firewall_rules_v2',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=1024)),
        sa.Column('project_id', sa.String(length=36), index=True),
        sa.Column('protocol', sa.String(length=40)),
        sa.Column('ip_version', sa.Integer, nullable=False),
        sa.Column('source_ip_address', sa.String(length=46)),
        sa.Column('destination_ip_address', sa.String(length=46)),
        sa.Column('source_port_range_min', sa.Integer),
        sa.Column('source_port_range_max', sa.Integer),
        sa.Column('destination_port_range_min', sa.Integer),
        sa.Column('destination_port_range_max', sa.Integer),
        sa.Column('action', sa.Enum('allow', 'deny', 'reject',
                                    name='firewallrules_action')),
        sa.Column('public', sa.Boolean),
        sa.Column('enabled', sa.Boolean))

    op.create_table(
        'firewall_groups_v2',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=1024)),
        sa.Column('project_id', sa.String(length=36), index=True),
        sa.Column('status', sa.String(length=255)),
        sa.Column('admin_state_up', sa.Boolean),
        sa.Column('public', sa.Boolean),
        sa.Column('egress_firewall_policy_id', sa.String(length=36)),
        sa.Column('ingress_firewall_policy_id', sa.String(length=36)))

    op.create_table(
        'firewall_group_port_associations_v2',
        sa.Column('firewall_group_id', sa.String(length=36),
                  sa.ForeignKey('firewall_groups_v2.id', ondelete='CASCADE'),
                  nullable=False, unique=True),
        sa.Column('port_id', sa.String(length=36),
                  sa.ForeignKey('ports.id', ondelete='CASCADE'),
                  nullable=False, unique=True))

    op.create_table(
        'firewall_policy_rule_associations_v2',
        sa.Column('firewall_policy_id', sa.String(length=36),
                  sa.ForeignKey('firewall_policies_v2.id', ondelete='CASCADE'),
                  nullable=False, unique=True, primary_key=True),
        sa.Column('firewall_rule_id', sa.String(length=36),
                  sa.ForeignKey('firewall_rules_v2.id', ondelete='CASCADE'),
                  nullable=False, unique=True, primary_key=True),
        sa.Column('position', sa.Integer))
