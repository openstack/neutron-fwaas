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

"""change shared attribute for firewall resource

Revision ID: fd38cd995cc0
Revises: f83a0b2964d0
Create Date: 2017-03-31 14:22:21.063392

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fd38cd995cc0'
down_revision = 'f83a0b2964d0'
depends_on = ('d6a12e637e28',)


def upgrade():
    op.alter_column('firewall_rules_v2', 'public', new_column_name='shared',
                    existing_type=sa.Boolean)
    op.alter_column('firewall_groups_v2', 'public', new_column_name='shared',
                    existing_type=sa.Boolean)
    op.alter_column('firewall_policies_v2', 'public', new_column_name='shared',
                    existing_type=sa.Boolean)
