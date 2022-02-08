#Copyright 2015 OpenStack Foundation
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

"""fw_table_alter script to make <name> column case sensitive

Revision ID: 458aa42b14b
Revises: 67c8e8d61d5
Create Date: 2015-09-16 11:47:43.061649

"""

from alembic import op

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '458aa42b14b'
down_revision = '67c8e8d61d5'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.MITAKA]


FW_TAB_NAME = ['firewall_rules', 'firewall_policies', 'firewalls']
SQL_STATEMENT_UPDATE_CMD = (
    "alter table %s "
    "modify name varchar(255) "
    "CHARACTER SET utf8 COLLATE utf8_bin"
)


def upgrade():
    context = op.get_context()
    if context.bind.dialect.name == 'mysql':
        for table in FW_TAB_NAME:
            op.execute(SQL_STATEMENT_UPDATE_CMD % table)
