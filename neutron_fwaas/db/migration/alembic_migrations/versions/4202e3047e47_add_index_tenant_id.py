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

"""add_index_tenant_id

Revision ID: 4202e3047e47
Revises: start_neutron_fwaas
Create Date: 2015-02-10 17:17:47.846764

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '4202e3047e47'
down_revision = 'start_neutron_fwaas'

TABLES = ['firewall_rules', 'firewalls', 'firewall_policies']


def upgrade():
    for table in TABLES:
        op.create_index(op.f('ix_%s_tenant_id' % table),
                        table, ['tenant_id'], unique=False)
