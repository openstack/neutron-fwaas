# Copyright 2015 OpenStack Foundation.
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

import urllib

from neutron import context as neutron_context
from neutron.i18n import _LW
from novaclient import client as nova_client
from oslo_log import log as logging
from vyatta.common import config as vyatta_config
from vyatta.vrouter import client as vyatta_client

from neutron_fwaas.services.firewall.agents.vyatta import vyatta_utils
from neutron_fwaas.services.firewall.drivers import fwaas_base


LOG = logging.getLogger(__name__)

FW_NAME = 'firewall/name/{0}'
FW_DESCRIPTION = 'firewall/name/{0}/description/{1}'

FW_ESTABLISHED_ACCEPT = 'firewall/state-policy/established/action/accept'
FW_RELATED_ACCEPT = 'firewall/state-policy/related/action/accept'

FW_RULE_DESCRIPTION = 'firewall/name/{0}/rule/{1}/description/{2}'
FW_RULE_PROTOCOL = 'firewall/name/{0}/rule/{1}/protocol/{2}'
FW_RULE_SRC_PORT = 'firewall/name/{0}/rule/{1}/source/port/{2}'
FW_RULE_DEST_PORT = 'firewall/name/{0}/rule/{1}/destination/port/{2}'
FW_RULE_SRC_ADDR = 'firewall/name/{0}/rule/{1}/source/address/{2}'
FW_RULE_DEST_ADDR = 'firewall/name/{0}/rule/{1}/destination/address/{2}'
FW_RULE_ACTION = 'firewall/name/{0}/rule/{1}/action/{2}'

NOVACLIENT_VERSION = '2'


class VyattaFirewallDriver(fwaas_base.FwaasDriverBase):
    def __init__(self):
        LOG.debug("Vyatta vRouter Fwaas:: Initializing fwaas driver")
        compute_client = nova_client.Client(
            NOVACLIENT_VERSION,
            vyatta_config.VROUTER.tenant_admin_name,
            vyatta_config.VROUTER.tenant_admin_password,
            auth_url=vyatta_config.CONF.nova_admin_auth_url,
            service_type="compute",
            tenant_id=vyatta_config.VROUTER.tenant_id)
        self._vyatta_clients_pool = vyatta_client.ClientsPool(compute_client)

    def create_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug('Vyatta vRouter Fwaas::Create_firewall (%s)', firewall)

        return self.update_firewall(agent_mode, apply_list, firewall)

    def update_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug('Vyatta vRouter Fwaas::Update_firewall (%s)', firewall)

        if firewall['admin_state_up']:
            return self._update_firewall(apply_list, firewall)
        else:
            return self.apply_default_policy(agent_mode, apply_list, firewall)

    def delete_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug('Vyatta vRouter Fwaas::Delete_firewall (%s)', firewall)

        return self.apply_default_policy(agent_mode, apply_list, firewall)

    def apply_default_policy(self, agent_mode, apply_list, firewall):
        LOG.debug('Vyatta vRouter Fwaas::apply_default_policy (%s)',
                  firewall)

        for ri in apply_list:
            self._delete_firewall(ri, firewall)

        return True

    def _update_firewall(self, apply_list, firewall):
        LOG.debug("Updating firewall (%s)", firewall['id'])

        for ri in apply_list:
            self._delete_firewall(ri, firewall)
            self._setup_firewall(ri, firewall)

        return True

    def _setup_firewall(self, ri, fw):
        client = self._get_vyatta_client(ri.router)

        fw_cmd_list = []

        # Create firewall
        fw_name = vyatta_utils.get_firewall_name(ri, fw)
        fw_cmd_list.append(
            vyatta_client.SetCmd(
                FW_NAME.format(urllib.quote_plus(fw_name))))

        if fw.get('description'):
            fw_cmd_list.append(vyatta_client.SetCmd(
                FW_DESCRIPTION.format(
                    urllib.quote_plus(fw_name),
                    urllib.quote_plus(fw['description']))))

        # Set firewall state policy
        fw_cmd_list.append(vyatta_client.SetCmd(FW_ESTABLISHED_ACCEPT))
        fw_cmd_list.append(vyatta_client.SetCmd(FW_RELATED_ACCEPT))

        # Create firewall rules
        rule_num = 0
        for rule in fw['firewall_rule_list']:
            if not rule['enabled']:
                continue
            if rule['ip_version'] == 4:
                rule_num += 1
                fw_cmd_list += self._set_firewall_rule(fw_name, rule_num, rule)
            else:
                LOG.warn(_LW("IPv6 rules are not supported."))

        # Configure router zones
        zone_cmd_list = vyatta_utils.get_zone_cmds(client, ri, fw_name)
        client.exec_cmd_batch(fw_cmd_list + zone_cmd_list)

    def _delete_firewall(self, ri, fw):
        client = self._get_vyatta_client(ri.router)

        cmd_list = []

        # Delete zones
        cmd_list.append(vyatta_client.DeleteCmd("zone-policy"))

        # Delete firewall
        fw_name = vyatta_utils.get_firewall_name(ri, fw)
        cmd_list.append(vyatta_client.DeleteCmd(
            FW_NAME.format(urllib.quote_plus(fw_name))))

        # Delete firewall state policy
        cmd_list.append(vyatta_client.DeleteCmd("firewall/state-policy"))

        client.exec_cmd_batch(cmd_list)

    def _set_firewall_rule(self, fw_name, rule_num, rule):
        cmd_list = []

        if 'description' in rule and len(rule['description']) > 0:
            cmd_list.append(vyatta_client.SetCmd(
                FW_RULE_DESCRIPTION.format(
                    urllib.quote_plus(fw_name), rule_num,
                    urllib.quote_plus(rule['description']))))

        rules = [
            ('protocol', FW_RULE_PROTOCOL),
            ('source_port', FW_RULE_SRC_PORT),
            ('destination_port', FW_RULE_DEST_PORT),
            ('source_ip_address', FW_RULE_SRC_ADDR),
            ('destination_ip_address', FW_RULE_DEST_ADDR),
        ]

        for key, url in rules:
            field = rule.get(key)
            if field is None:
                continue

            # For safety and extensibility we need to use quote_plus
            # for all data retrieved from external sources.
            cmd_list.append(vyatta_client.SetCmd(
                url.format(
                    urllib.quote_plus(fw_name), rule_num,
                    urllib.quote_plus(field))))

        if 'action' in rule:
            if rule['action'] == 'allow':
                action = 'accept'
            else:
                action = 'drop'
            cmd_list.append(vyatta_client.SetCmd(
                FW_RULE_ACTION.format(
                    urllib.quote_plus(fw_name), rule_num,
                    action)))
        return cmd_list

    def _get_vyatta_client(self, router):
        ctx = neutron_context.Context(None, router['tenant_id'])
        return self._vyatta_clients_pool.get_by_db_lookup(router['id'], ctx)
