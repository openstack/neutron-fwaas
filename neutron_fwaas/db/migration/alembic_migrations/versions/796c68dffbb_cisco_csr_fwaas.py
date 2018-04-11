# Copyright 2015 OpenStack Foundation
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

"""cisco_csr_fwaas

Revision ID: 796c68dffbb
Revises: 540142f314f4
Create Date: 2015-02-02 13:11:55.184112

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '796c68dffbb'
down_revision = '540142f314f4'


def upgrade(active_plugins=None, options=None):

    op.create_table('cisco_firewall_associations',
        sa.Column('fw_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('direction', sa.String(length=16), nullable=True),
        sa.Column('acl_id', sa.String(length=36), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['fw_id'], ['firewalls.id'],
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('fw_id')
    )
