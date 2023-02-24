# Copyright 2017 FUJITSU LIMITED
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

"""create_default_firewall_groups_table

Revision ID: 876782258a43
Revises: d6a12e637e28
Create Date: 2017-01-26 23:47:42.795504

"""

from alembic import op
from neutron_lib.db import constants as db_constants
from neutron_lib import exceptions
import sqlalchemy as sa

from neutron_fwaas._i18n import _
from neutron_fwaas.common import fwaas_constants as const
from neutron_fwaas.common import resources

# revision identifiers, used by Alembic.
revision = '876782258a43'
down_revision = 'd6a12e637e28'


class DuplicateDefaultFirewallGroup(exceptions.Conflict):
    message = _("Duplicate Firewall group found named '%s'. "
                "Database cannot be upgraded. Please, remove all duplicates "
                "before upgrading the database.") % const.DEFAULT_FWG


def upgrade():
    op.create_table(
        'default_firewall_groups',
        sa.Column('project_id',
                  sa.String(length=db_constants.PROJECT_ID_FIELD_SIZE),
                  nullable=False),
        sa.Column('firewall_group_id',
                  sa.String(length=db_constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.PrimaryKeyConstraint('project_id'),
        sa.ForeignKeyConstraint(['firewall_group_id'],
                                ['firewall_groups_v2.id'], ondelete="CASCADE"))


def check_sanity(connection):
    # check for already existing firewall groups with name == DEFAULT_FWG
    insp = sa.engine.reflection.Inspector.from_engine(connection)
    if 'firewall_groups_v2' not in insp.get_table_names():
        return []
    session = sa.orm.Session(bind=connection)
    default_fwg = session.query(resources.FIREWALL_GROUP.name).filter(
        resources.FIREWALL_GROUP.name == const.DEFAULT_FWG).first()
    if default_fwg:
        raise DuplicateDefaultFirewallGroup()
