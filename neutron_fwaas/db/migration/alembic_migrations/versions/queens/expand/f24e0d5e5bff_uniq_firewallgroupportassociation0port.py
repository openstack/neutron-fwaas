# Copyright 2017 Fujitsu Limited
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

"""uniq_firewallgroupportassociation0port

Revision ID: f24e0d5e5bff
Revises: 876782258a43
Create Date: 2017-11-08 15:55:40.990272

"""

from alembic import op
from neutron_lib import exceptions
import sqlalchemy as sa

from neutron._i18n import _

# revision identifiers, used by Alembic.
revision = 'f24e0d5e5bff'
down_revision = '876782258a43'


fwg_port_association = sa.Table(
    'firewall_group_port_associations_v2', sa.MetaData(),
    sa.Column('firewall_group_id', sa.String(36)),
    sa.Column('port_id', sa.String(36)))


class DuplicatePortRecordinFirewallGroupPortAssociation(exceptions.Conflict):
    message = _("Duplicate port(s) %(port_id)s records exist in"
                "firewall_group_port_associations_v2 table. Database cannot"
                "be upgraded. Please remove all duplicated records before"
                "upgrading the database.")


def upgrade():
    op.create_unique_constraint(
        'uniq_firewallgroupportassociation0port_id',
        'firewall_group_port_associations_v2',
        ['port_id'])


def check_sanity(connection):
    duplicated_port_ids = (
        get_duplicate_port_records_in_fwg_port_association(connection))
    if duplicated_port_ids:
        raise DuplicatePortRecordinFirewallGroupPortAssociation(
            port_id=",".join(duplicated_port_ids))


def get_duplicate_port_records_in_fwg_port_association(connection):
    insp = sa.engine.reflection.Inspector.from_engine(connection)
    if 'firewall_group_port_associations_v2' not in insp.get_table_names():
        return []
    session = sa.orm.Session(bind=connection)
    query = (session.query(fwg_port_association.c.port_id)
             .group_by(fwg_port_association.c.port_id)
             .having(sa.func.count() > 1)).all()
    return [q[0] for q in query]
