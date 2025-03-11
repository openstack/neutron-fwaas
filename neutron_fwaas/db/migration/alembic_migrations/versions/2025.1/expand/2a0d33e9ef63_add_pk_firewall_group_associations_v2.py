# Copyright 2019 Canonical Ltd.
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

"""add pk firewall_group_associations_v2

Revision ID: 2a0d33e9ef63
Revises: 6941ce70131e
Create Date: 2025-01-20 18:00:00.000000

"""

from alembic import op
from sqlalchemy.engine import reflection

from oslo_log import log as logging


# revision identifiers, used by Alembic.
revision = '2a0d33e9ef63'
down_revision = '6941ce70131e'

LOG = logging.getLogger(__name__)


def upgrade():
    bind = op.get_bind()
    insp = reflection.Inspector.from_engine(bind.engine)
    if 'firewall_group_port_associations_v2' not in insp.get_table_names():
        return
    pk = insp.get_pk_constraint('firewall_group_port_associations_v2')
    if not pk['constrained_columns']:
        op.create_primary_key(
            'pk_firewall_group_port_associations_v2',
            'firewall_group_port_associations_v2',
            ['firewall_group_id', 'port_id'])
    else:
        # Revision '6941ce70131e' has been updated to create the
        # missing PK. Depending whether the env is already deployed or
        # not we may or not have to add the primary key.
        LOG.info("The primary key in firewall_group_port_associations_v2 "
                 "already exists, continuing.")
