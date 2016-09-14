# Copyright 2016 <PUT YOUR NAME/COMPANY HERE>
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

"""rename tenant to project

Revision ID: f83a0b2964d0
Revises: 458aa42b14b
Create Date: 2016-07-14 13:11:53.112622

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = 'f83a0b2964d0'
down_revision = '458aa42b14b'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.NEWTON]

_INSPECTOR = None


def get_inspector():
    """Reuse inspector"""

    global _INSPECTOR

    if _INSPECTOR:
        return _INSPECTOR

    else:
        bind = op.get_bind()
        _INSPECTOR = reflection.Inspector.from_engine(bind)

    return _INSPECTOR


def get_tables():
    """
    Returns hardcoded list of tables which have ``tenant_id`` column.

    The list is hardcoded to match the state of the schema when this
    upgrade script is run.
    """

    tables = [
        'firewalls',
        'firewall_policies',
        'firewall_rules',
    ]

    return tables


def get_columns(table):
    """Returns list of columns for given table."""
    inspector = get_inspector()
    return inspector.get_columns(table)


def get_data():
    """Returns combined list of tuples: [(table, column)].

    The list is built from tables with a tenant_id column.
    """

    output = []
    tables = get_tables()
    for table in tables:
        columns = get_columns(table)

        for column in columns:
            if column['name'] == 'tenant_id':
                output.append((table, column))

    return output


def alter_column(table, column):
    old_name = 'tenant_id'
    new_name = 'project_id'

    op.alter_column(
        table_name=table,
        column_name=old_name,
        new_column_name=new_name,
        existing_type=column['type'],
        existing_nullable=column['nullable']
    )


def recreate_index(index, table_name):
    old_name = index['name']
    new_name = old_name.replace('tenant', 'project')

    op.drop_index(op.f(old_name), table_name)
    op.create_index(new_name, table_name, ['project_id'])


def upgrade():
    """Code reused from

    Change-Id: I87a8ef342ccea004731ba0192b23a8e79bc382dc
    """

    inspector = get_inspector()

    data = get_data()
    for table, column in data:
        alter_column(table, column)

        indexes = inspector.get_indexes(table)
        for index in indexes:
            if 'tenant_id' in index['name']:
                recreate_index(index, table)


def contract_creation_exceptions():
    """Special migration for the blueprint to support Keystone V3.
    We drop all tenant_id columns and create project_id columns instead.
    """
    return {
        sa.Column: ['.'.join([table, 'project_id']) for table in get_tables()],
        sa.Index: get_tables()
    }
