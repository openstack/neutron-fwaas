# Copyright 2015 Red Hat Inc.
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

"""Initial Liberty no-op script.

Revision ID: 67c8e8d61d5
Revises: kilo
Create Date: 2015-07-28 22:18:13.330846

"""

from neutron.db import migration
from neutron_lib.db import constants


# revision identifiers, used by Alembic.
revision = '67c8e8d61d5'
down_revision = 'kilo'
branch_labels = (constants.CONTRACT_BRANCH,)

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY]


def upgrade():
    pass
