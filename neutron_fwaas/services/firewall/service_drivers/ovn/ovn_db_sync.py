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

from datetime import datetime

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync \
    as base_ovn_db_sync
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from oslo_log import log

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    acl as ovn_acl
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    constants as ovn_fw_const
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    firewall_l3_driver as ovn_fwaas_driver


LOG = log.getLogger(__name__)


# TODO(slaweq): use base class from neutron-lib once
# https://review.opendev.org/c/openstack/neutron-lib/+/970267 will be merged
# and released
class OvnNbDbSync(base_ovn_db_sync.BaseOvnDbSynchronizer):

    _required_service_plugins = [
        "neutron_fwaas.services.firewall.fwaas_plugin_v2.FirewallPluginV2"
    ]

    def __init__(self, core_plugin, ovn_driver, mode, is_maintenance=False):
        super().__init__(core_plugin, ovn_driver, mode, is_maintenance)
        self.fwaas_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)
        self.fwaas_ovn_driver = self.fwaas_plugin.driver

    def do_sync(self):
        if not isinstance(self.fwaas_ovn_driver,
                          ovn_fwaas_driver.OVNFwaasDriver):
            LOG.warning("OVN FWaaS driver is required for OVN DB sync")
            return

        if self.mode == ovn_const.OVN_DB_SYNC_MODE_OFF:
            LOG.debug("Neutron sync mode is off, not checking OVN "
                      "Northbound DB for consistency")
            return
        elif self.mode == ovn_const.OVN_DB_SYNC_MODE_MIGRATE:
            LOG.debug("Neutron FWaaS OVN-Northbound DB sync do not support "
                      "migrate mode. Exiting...")
            return

        LOG.debug("FWaaS OVN-Northbound DB sync process started @ %s",
                  str(datetime.now()))

        ctx = context.get_admin_context()
        self._sync_firewall_groups(ctx)

        LOG.debug("FWaaS OVN-Northbound DB sync process completed @ %s",
                  str(datetime.now()))

    def _get_fw_port_groups_from_neutron_db(self, ctx):
        neutron_fwaas_groups = {}
        with db_api.CONTEXT_READER.using(ctx):
            for fwg in self.fwaas_ovn_driver.get_firewall_groups(ctx):
                if fwg['name'] == fwaas_constants.DEFAULT_FWG:
                    continue
                neutron_fwaas_groups[fwg['id']] = fwg
        return neutron_fwaas_groups

    def _get_fw_port_groups_from_ovn_db(self):
        ovn_port_groups = {}
        for pg in self.ovn_nb_api.db_list_rows('Port_Group').execute() or []:
            fwaas_group_id = pg.external_ids.get(
                ovn_fw_const.OVN_FWG_EXT_ID_KEY)
            if fwaas_group_id:
                ovn_port_groups[fwaas_group_id] = {
                    'id': fwaas_group_id,
                    'name': pg.name,
                    'acls': pg.acls,
                }
        return ovn_port_groups

    def _get_firewall_groups(self, ctx):
        neutron_fwaas_groups = self._get_fw_port_groups_from_neutron_db(ctx)
        ovn_port_groups = self._get_fw_port_groups_from_ovn_db()
        ids_to_remove = (
            set(ovn_port_groups.keys()) - set(neutron_fwaas_groups.keys()))
        groups_to_remove = {id: ovn_port_groups[id] for id in ids_to_remove}
        # Sync logic is implemented in a such way that it will try to sync all
        # Port Groups for firewall groups which exists in the Neutron DB, no
        # matter if PG exists in OVN DB or not. It is done that way as it is
        # easier to also sync ACLs which should be created for those PGs and
        # to update ports which are associated with those PGs.
        # As next step sync task is going to remove those PGs from OVN DB which
        # are not associated with any firewall group in Neutron DB.
        return neutron_fwaas_groups, groups_to_remove

    def _sync_acls_for_firewall_group(self, ctx, txn, fw_group):
        if (fw_group['ingress_firewall_policy_id'] or
                fw_group['egress_firewall_policy_id']):
            with db_api.CONTEXT_READER.using(ctx):
                self.fwaas_plugin.driver._add_rules_for_firewall_group(
                    ctx, txn, fw_group['id'])

    def _sync_firewall_groups(self, ctx):
        groups_to_sync, groups_to_remove = self._get_firewall_groups(ctx)
        if groups_to_sync or groups_to_remove:
            LOG.warning('Number of Port Groups to sync: %d, remove: %d',
                        len(groups_to_sync), len(groups_to_remove))
            LOG.warning('Port Groups to be synced in OVN: %s', groups_to_sync)
            LOG.warning('Port Groups to remove from OVN: %s',
                        groups_to_remove)

        if self.mode != ovn_const.OVN_DB_SYNC_MODE_REPAIR:
            return

        # Sync Port Groups for firewall groups which exists in the Neutron DB
        with self.ovn_nb_api.transaction(check_error=True) as txn:
            for fw_group in groups_to_sync.values():
                pg_name = ovn_utils.ovn_port_group_name(fw_group['id'])
                ovn_acl.create_pg_for_fwg(self.ovn_nb_api, fw_group['id'])
                ovn_acl.add_default_acls_for_pg(
                    self.ovn_nb_api, txn, pg_name)
                self._sync_acls_for_firewall_group(ctx, txn, fw_group)
                if fw_group['ports']:
                    ovn_acl.update_ports_for_pg(
                        self.ovn_nb_api, txn, pg_name, fw_group['ports'])

        # Remove Port Groups for firewall groups which do not exist in the
        # Neutron DB
        with self.ovn_nb_api.transaction(check_error=True) as txn:
            for fw_group in groups_to_remove.values():
                pg_name = ovn_utils.ovn_port_group_name(fw_group['id'])
                if self.ovn_nb_api.get_port_group(pg_name):
                    txn.add(
                        self.ovn_nb_api.pg_del(name=pg_name, if_exists=True))
