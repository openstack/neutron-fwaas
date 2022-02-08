# Copyright 2015 NEC Corporation.  All rights reserved.
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

"""add reject rule

Revision ID: 4b47ea298795
Revises: c40fbb377ad
Create Date: 2015-04-15 04:19:57.324584

"""

import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '4b47ea298795'
down_revision = 'c40fbb377ad'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY, migration.MITAKA]


new_action = sa.Enum('allow', 'deny', 'reject', name='firewallrules_action')


def upgrade():
    # NOTE: postgresql have a builtin ENUM type, so just altering the
    # column won't works
    # https://bitbucket.org/zzzeek/alembic/issues/270/altering-enum-type
    # alter_enum that was already invented for such case in neutron
    # https://github.com/openstack/neutron/blob/master/neutron/db/migration/__init__.py

    migration.alter_enum(
        'firewall_rules', 'action', enum_type=new_action, nullable=True)
