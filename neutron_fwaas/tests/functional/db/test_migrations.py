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

from alembic import script as alembic_script
from neutron.db.migration.alembic_migrations import external
from neutron.db.migration import cli as migration
from neutron.tests.functional.db import test_migrations
from neutron.tests.unit import testlib_api
from oslo_config import cfg
import sqlalchemy

from neutron_fwaas.db.models import head

# EXTERNAL_TABLES should contain all names of tables that are not related to
# current repo.
EXTERNAL_TABLES = set(external.TABLES) - set(external.FWAAS_TABLES)
# Model moved to vendor repo
EXTERNAL_TABLES.update({'cisco_firewall_associations'})

VERSION_TABLE = 'alembic_version_fwaas'


class _TestModelsMigrationsFWaaS(test_migrations._TestModelsMigrations):

    def db_sync(self, engine):
        cfg.CONF.set_override('connection', engine.url, group='database')
        for conf in migration.get_alembic_configs():
            self.alembic_config = conf
            self.alembic_config.neutron_config = cfg.CONF
            migration.do_alembic_command(conf, 'upgrade', 'heads')

    def get_metadata(self):
        return head.get_metadata()

    def include_object(self, object_, name, type_, reflected, compare_to):
        if type_ == 'table' and (name.startswith('alembic') or
                                 name == VERSION_TABLE or
                                 name in EXTERNAL_TABLES):
            return False
        if type_ == 'index' and reflected and name.startswith("idx_autoinc_"):
            return False
        return True


class TestModelsMigrationsMysql(testlib_api.MySQLTestCaseMixin,
                                _TestModelsMigrationsFWaaS,
                                testlib_api.SqlTestCaseLight):
    pass


class TestModelsMigrationsPostgresql(testlib_api.PostgreSQLTestCaseMixin,
                                     _TestModelsMigrationsFWaaS,
                                     testlib_api.SqlTestCaseLight):
    pass


class TestSanityCheck(testlib_api.SqlTestCaseLight):
    BUILD_SCHEMA = False

    def setUp(self):
        super(TestSanityCheck, self).setUp()

        for conf in migration.get_alembic_configs():
            self.alembic_config = conf
            self.alembic_config.neutron_config = cfg.CONF

    def _drop_table(self, table):
        with self.engine.begin() as conn:
            table.drop(conn)

    def test_check_sanity_f24e0d5e5bff(self):
        current_revision = "f24e0d5e5bff"
        fwg_port_association = sqlalchemy.Table(
            'firewall_group_port_associations_v2', sqlalchemy.MetaData(),
            sqlalchemy.Column('firewall_group_id', sqlalchemy.String(36)),
            sqlalchemy.Column('port_id', sqlalchemy.String(36)))

        with self.engine.connect() as conn:
            fwg_port_association.create(conn)
            self.addCleanup(self._drop_table, fwg_port_association)
            conn.execute(fwg_port_association.insert(), [
                {'firewall_group_id': '1234', 'port_id': '12345'},
                {'firewall_group_id': '12343', 'port_id': '12345'}
            ])
            script_dir = alembic_script.ScriptDirectory.from_config(
                self.alembic_config)
            script = script_dir.get_revision(current_revision).module
            self.assertRaises(
                script.DuplicatePortRecordinFirewallGroupPortAssociation,
                script.check_sanity, conn)
