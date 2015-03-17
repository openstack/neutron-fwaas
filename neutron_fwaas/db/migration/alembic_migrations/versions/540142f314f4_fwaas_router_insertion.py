# Copyright 2014 OpenStack Foundation
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

"""FWaaS router insertion

Revision ID: 540142f314f4
Revises: 4202e3047e47
Create Date: 2015-02-06 17:02:24.279337

"""

# revision identifiers, used by Alembic.
revision = '540142f314f4'
down_revision = '4202e3047e47'

from alembic import op
import sqlalchemy as sa

SQL_STATEMENT = (
    "insert into firewall_router_associations "
    "select "
    "f.id as fw_id, r.id as router_id "
    "from firewalls f, routers r "
    "where "
    "f.tenant_id=r.tenant_id"
)


def upgrade():
    op.create_table('firewall_router_associations',
        sa.Column('fw_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['fw_id'], ['firewalls.id'],
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('fw_id', 'router_id'),
    )

    op.execute(SQL_STATEMENT)


def downgrade():
    op.drop_table('firewall_router_associations')
