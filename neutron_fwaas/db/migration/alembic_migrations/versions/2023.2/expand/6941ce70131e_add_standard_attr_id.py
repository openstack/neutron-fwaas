# Copyright 2023 EasyStack Limited
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

"""add standard attributes

Revision ID: 6941ce70131e
Revises: f24e0d5e5bff
Create Date: 2022-12-01 04:19:57.324584

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '6941ce70131e'
down_revision = 'f24e0d5e5bff'
tables = ['firewall_groups_v2', 'firewall_rules_v2', 'firewall_policies_v2']


standardattrs = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('resource_type', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True))


def generate_records_for_existing(table):
    model = sa.Table(table, sa.MetaData(),
                     sa.Column('id', sa.String(length=36), nullable=False),
                     sa.Column('description', sa.String(length=255),
                               nullable=True),
                     sa.Column('standard_attr_id', sa.BigInteger(),
                               nullable=True))
    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        for row in session.query(model):
            res = session.execute(
                standardattrs.insert().values(resource_type=table,
                                              description=row[1])
            )
            session.execute(
                model.update().values(
                    standard_attr_id=res.inserted_primary_key[0]).where(
                        model.c.id == row[0])
            )
    session.commit()


def upgrade():
    for table in tables:
        op.add_column(table, sa.Column('standard_attr_id', sa.BigInteger(),
                                       nullable=True))
        op.create_foreign_key(
            constraint_name=None, source_table=table,
            referent_table='standardattributes',
            local_cols=['standard_attr_id'], remote_cols=['id'],
            ondelete='CASCADE')
        generate_records_for_existing(table)
        op.alter_column(table, 'standard_attr_id', nullable=False,
                        existing_type=sa.BigInteger(), existing_nullable=True,
                        existing_server_default=False)
        op.create_unique_constraint(
            constraint_name='uniq_%s0standard_attr_id' % table,
            table_name=table, columns=['standard_attr_id'])
        op.drop_column(table, 'description')
