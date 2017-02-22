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

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

# revision identifiers, used by Alembic.
revision = '540142f314f4'
down_revision = '4202e3047e47'

SQL_STATEMENT = (
    "insert into firewall_router_associations "
    "select "
    "f.id as fw_id, r.id as router_id "
    "from firewalls f, routers r "
    "where "
    "f.tenant_id=r.%s"
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

    # Depending on when neutron-fwaas is installed with neutron, this script
    # may be run before or after the neutron core tables have had their
    # tenant_id columns renamed to project_id. Account for both scenarios.
    bind = op.get_bind()
    insp = reflection.Inspector.from_engine(bind)
    columns = insp.get_columns('routers')
    if 'tenant_id' in [c['name'] for c in columns]:
        op.execute(SQL_STATEMENT % 'tenant_id')
    else:
        op.execute(SQL_STATEMENT % 'project_id')
