# Copyright 2015 Freescale, Inc.
# All Rights Reserved.
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

from neutron.common import rpc
from neutron.common import topics
from neutron.i18n import _LE
from neutron.plugins.common import constants as const
from neutron.plugins.ml2.drivers.freescale import config
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.orm import exc

from neutron_fwaas.db.firewall import firewall_db
from neutron_fwaas.services.firewall import fwaas_plugin

LOG = logging.getLogger(__name__)


class FirewallCallbacks(fwaas_plugin.FirewallCallbacks):

    """Callbacks to handle CRD notifications to amqp."""

    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin
        self._client = self.plugin._client

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Get all Firewalls and rules for a tenant from CRD.

        For all the firewalls created, check CRD for config_mode.
        If it is Network Node, prepare the list.
        Other config modes are handled by CRD internally.
        """

        fw_list = []
        for fw in self.plugin.get_firewalls(context):
            fw_id = fw['id']
            # get the firewall details from CRD service.
            crd_fw_details = self._client.show_firewall(fw_id)
            config_mode = crd_fw_details['firewall']['config_mode']
            # get those FWs with config mode NetworkNode (NN) or None
            if config_mode in ('NN', None):
                fw_list.append(self.plugin._make_firewall_dict_with_rules(
                    context, fw_id))
        return fw_list


class FirewallPlugin(firewall_db.Firewall_db_mixin):

    """Implementation of the Freescale Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Existing Firewall database is used.
    """
    supported_extension_aliases = ["fwaas"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""

        self._client = config.get_crdclient()
        self.endpoints = [FirewallCallbacks(self)]

        self.conn = rpc.create_connection()
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    def _update_firewall_status(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        super(FirewallPlugin, self).update_firewall(context, firewall_id,
                                                    status_update)
        try:
            self._client.update_firewall(firewall_id, status_update)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update firewall status (%s)."),
                          firewall_id)

    def _update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._update_firewall_status(context, firewall_id)

    # Firewall Management
    def create_firewall(self, context, firewall):
        """Create Firewall.

        'PENDING' status updates are handled by CRD by posting messages
        to AMQP (topics.FIREWALL_PLUGIN) that Firewall consumes to
        update its status.
        """
        firewall['firewall']['status'] = const.PENDING_CREATE
        fw = super(FirewallPlugin, self).create_firewall(context, firewall)
        try:
            crd_firewall = {'firewall': fw}
            self._client.create_firewall(crd_firewall)
        except Exception:
            with excutils.save_and_reraise_exception():
                fw_id = fw['firewall']['id']
                LOG.error(_LE("Failed to create firewall (%s)."),
                          fw_id)
                super(FirewallPlugin, self).delete_firewall(context, fw_id)
        return fw

    def update_firewall(self, context, fw_id, firewall=None):
        firewall['firewall']['status'] = const.PENDING_UPDATE
        fw = super(FirewallPlugin,
                   self).update_firewall(context, fw_id, firewall)
        try:
            crd_firewall = {'firewall': fw}
            self._client.update_firewall(fw_id, crd_firewall)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to update firewall (%s)."), fw_id)
                # TODO(trinaths):do rollback on error
        return fw

    def delete_db_firewall_object(self, context, fw_id):
        firewall = self.get_firewall(context, fw_id)
        if firewall['status'] in [const.PENDING_DELETE]:
            try:
                super(FirewallPlugin, self).delete_firewall(context, fw_id)
            except exc.NoResultFound:
                LOG.error(_LE("Delete Firewall (%s) DB object failed."),
                          fw_id)

    def delete_firewall(self, context, fw_id):
        status_update = {"firewall": {"status": const.PENDING_DELETE}}
        super(FirewallPlugin, self).update_firewall(context, fw_id,
                                                    status_update)
        try:
            self._client.delete_firewall(fw_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete firewall (%s)."), fw_id)
                # TODO(trinaths):do rollback on error

    # Firewall Policy Management
    def create_firewall_policy(self, context, firewall_policy):
        fw_policy = super(FirewallPlugin, self).create_firewall_policy(
            context,
            firewall_policy)
        fw_policy.pop('firewall_list')
        try:
            crd_firewall_policy = {'firewall_policy': fw_policy}
            self._client.create_firewall_policy(crd_firewall_policy)
        except Exception:
            with excutils.save_and_reraise_exception():
                fwp_id = fw_policy['firewall_policy']['id']
                LOG.error(_LE("Failed to create firewall policy (%s)."),
                          fwp_id)
                super(FirewallPlugin, self).delete_firewall_policy(context,
                                                                   fwp_id)
        return fw_policy

    def update_firewall_policy(self, context, fp_id, firewall_policy):
        fw_policy = super(FirewallPlugin,
                          self).update_firewall_policy(context, fp_id,
                                                       firewall_policy)
        self._update_firewall_policy(context, fp_id)
        fw_policy.pop('firewall_list')
        try:
            crd_firewall_policy = {'firewall_policy': fw_policy}
            self._client.update_firewall_policy(fp_id, crd_firewall_policy)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Update firewall policy failed (%s)."), fp_id)
                # TODO(trinaths):do rollback on error
        return fw_policy

    def delete_firewall_policy(self, context, fp_id):
        super(FirewallPlugin, self).delete_firewall_policy(context, fp_id)
        try:
            self._client.delete_firewall_policy(fp_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Delete Firewall Policy (%s) failed."),
                          fp_id)
                # TODO(trinaths):do rollback on error

    # Firewall Rule management
    def create_firewall_rule(self, context, firewall_rule):
        fw_rule = super(FirewallPlugin,
                        self).create_firewall_rule(context, firewall_rule)
        try:
            crd_firewall_rule = {'firewall_rule': fw_rule}
            self._client.create_firewall_rule(crd_firewall_rule)
        except Exception:
            with excutils.save_and_reraise_exception():
                fwr_id = fw_rule['firewall_rule']['id']
                LOG.error(_LE("Failed to create firewall rule (%s)."),
                          fwr_id)
                super(FirewallPlugin, self).delete_firewall_rule(context,
                                                                 fwr_id)
        return fw_rule

    def update_firewall_rule(self, context, fr_id, firewall_rule):
        fw_rule = super(FirewallPlugin,
                        self).update_firewall_rule(context, fr_id,
                                                   firewall_rule)
        if fw_rule['firewall_policy_id']:
            self._update_firewall_policy(
                context,
                fw_rule['firewall_policy_id'])
        try:
            crd_firewall_rule = {'firewall_rule': fw_rule}
            self._client.update_firewall_rule(fr_id, crd_firewall_rule)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to update firewall rule (%s)."), fr_id)
                # TODO(trinaths):do rollback on error
        return fw_rule

    def delete_firewall_rule(self, context, fr_id):
        fw_rule = self.get_firewall_rule(context, fr_id)
        super(FirewallPlugin, self).delete_firewall_rule(context, fr_id)
        if fw_rule['firewall_policy_id']:
            self._update_firewall_policy(context,
                                         fw_rule['firewall_policy_id'])
        try:
            self._client.delete_firewall_rule(fr_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete firewall rule (%s)."),
                          fr_id)
                # TODO(trinaths):do rollback on error

    def insert_rule(self, context, rid, rule_info):
        rule = super(FirewallPlugin,
                     self).insert_rule(context, rid, rule_info)
        try:
            self._client.firewall_policy_insert_rule(rid, rule_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to insert rule %(rule)s into "
                              "firewall policy %(fwpid)s."),
                          {'rule': rule_info,
                           'fwpid': rid})
                super(FirewallPlugin, self).remove_rule(context, rid,
                                                        rule_info)
        self._update_firewall_policy(context, rid)
        return rule

    def remove_rule(self, context, rid, rule_info):
        rule = super(FirewallPlugin,
                     self).remove_rule(context, rid, rule_info)
        try:
            self._client.firewall_policy_remove_rule(rid, rule_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to remove rule %(rule)s from "
                              "firewall policy %(fwpid)s."),
                          {'rule': rule_info,
                           'fwpid': rid})
        self._update_firewall_policy(context, rid)
        return rule
