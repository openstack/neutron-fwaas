# Copyright 2025 NTT DATA Group
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

"""Drop v1

Revision ID: 1007f519ea46
Revises: fd38cd995cc0
Create Date: 2025-03-02 14:06:28.794129

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '1007f519ea46'
down_revision = 'fd38cd995cc0'


def upgrade():
    table_names = [
        'cisco_firewall_associations',
        'firewall_router_associations',
        'firewall_rules',
        'firewalls',
        'firewall_policies',
    ]
    for table_name in table_names:
        op.drop_table(table_name)
