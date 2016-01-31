# Copyright 2014 Cisco Systems, Inc.
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

import requests

from networking_cisco.plugins.cisco.cfg_agent.device_drivers import (
    cisco_csr_rest_client)
from oslo_log import log as logging

from neutron_fwaas._i18n import _LE
from neutron_fwaas.services.firewall.drivers import fwaas_base


LOG = logging.getLogger(__name__)

#----- ACL REST URL definitions -------------------------------------------
ACL_API = 'acl'
ACL_API_ACLID = 'acl/%s'                            # ACLID
ACL_API_ACLID_IF = 'acl/%s/interfaces'              # ACLID
ACL_API_ACLID_IFID_DIR = 'acl/%s/interfaces/%s_%s'  # ACLID, IF_DIRECTION


class CsrAclDriver(fwaas_base.FwaasDriverBase):
    """Cisco CSR ACL driver for FWaaS.

    This driver will send ACL configuration via RESTAPI to CSR1kv.
    This driver will return error to the caller function in case of
    error such as validation failures, sending configuration failures.
    The caller function will handle the error return properly.
    """

    def __init__(self):
        LOG.debug("Initializing fwaas CSR ACL driver")

    def _get_csr_host(self, firewall_vendor_ext):
        settings = {
            'rest_mgmt_ip': firewall_vendor_ext['host_mngt_ip'],
            'username': firewall_vendor_ext['host_usr_nm'],
            'password': firewall_vendor_ext['host_usr_pw'],
            'timeout': 30,
        }
        return cisco_csr_rest_client.CsrRestClient(settings)

    def _validate_firewall_rule_data(self, firewall):
        if 'firewall_rule_list' not in firewall:
            LOG.error(_LE("no rule list"))
            return False
        for rule in firewall['firewall_rule_list']:
            if 'name' not in rule:
                LOG.error(_LE("CsrAcl: no rule name"))
                return False
            ip_version = rule.get('ip_version')
            if ip_version != 4:
                LOG.error(_LE("invalid ip version %(ip_version)s in "
                    "rule %(rule)s"),
                    {'ip_version': ip_version, 'rule': rule['name']})
                return False
            if 'protocol' not in rule:
                LOG.error(_LE("no protocol in rule [%s]"), rule['name'])
                return False
            if rule.get('action', '').lower() not in ('allow', 'deny'):
                LOG.error(_LE("invalid action in rule [%s]"), rule['name'])
                return False

        return True

    def _validate_firewall_data(self, firewall):
        data = ('admin_state_up', 'vendor_ext')
        is_valid = all(x in firewall for x in data)
        if not is_valid:
            LOG.error(_LE("missing data in firewall"))
            return is_valid

        data = ('host_mngt_ip', 'host_usr_nm', 'host_usr_pw', 'if_list')
        is_valid = all(x in firewall['vendor_ext'] for x in data)
        if not is_valid:
            LOG.error(_LE("missing data in firewall vendor_ext"))
            return is_valid

        for firewall_interface in firewall['vendor_ext']['if_list']:
            if firewall_interface.get('direction', '') not in (
                'inside', 'outside', 'both'):
                LOG.error(_LE("invalid direction"))
                return False
            if 'port' not in firewall_interface:
                LOG.error(_LE("no port"))
                return False
            port = firewall_interface['port']
            if 'id' not in port:
                LOG.error(_LE("no port id"))
                return False
            if 'hosting_info' not in port:
                LOG.error(_LE("no hosting_info"))
                return False
            if 'segmentation_id' not in port['hosting_info']:
                LOG.error(_LE("no segmentation_id"))
                return False
            if 'hosting_port_name' not in port['hosting_info']:
                LOG.error(_LE("hosting_port_name"))
                return False
            interface_type = port['hosting_info'][
                'hosting_port_name'].split(':')[0] + ':'
            if interface_type not in ('t1_p:', 't2_p:'):
                LOG.error(_LE("invalide interface type %s"), interface_type)
                return False

        return True

    def _get_acl_l4_port(self, rule_port_name, rule, l4_opt):
        if rule.get(rule_port_name):
            ports = rule[rule_port_name].split(':')
            if rule_port_name == 'source_port':
                port_prefix = 'src'
            else:
                port_prefix = 'dest'
            l4_opt[port_prefix + '-port-start'] = ports[0]
            if len(ports) == 2:
                l4_opt[port_prefix + '-port-end'] = ports[1]

    def _get_acl_rule_data(self, firewall):
        """Get ACL RESTAPI request data from firewall dictionary.

        :return: ACL RESTAPI request data based on data from plugin.
        :return: {} if there is any error.
        """

        acl_rules_list = []
        seq = 100
        for rule in firewall['firewall_rule_list']:
            if not rule['enabled']:
                continue
            ace_rule = {'sequence': str(seq)}
            seq += 1

            if rule.get('protocol'):
                ace_rule['protocol'] = rule['protocol']
            else:
                ace_rule['protocol'] = 'all'

            if rule['action'].lower() == 'allow':
                ace_rule['action'] = 'permit'
            else:
                ace_rule['action'] = 'deny'

            if rule.get('source_ip_address'):
                ace_rule['source'] = rule['source_ip_address']
            else:
                ace_rule['source'] = 'any'

            if rule.get('destination_ip_address'):
                ace_rule['destination'] = rule['destination_ip_address']
            else:
                ace_rule['destination'] = 'any'

            l4_opt = {}
            self._get_acl_l4_port('source_port', rule, l4_opt)
            self._get_acl_l4_port('destination_port', rule, l4_opt)
            if l4_opt:
                ace_rule['l4-options'] = l4_opt

            acl_rules_list.append(ace_rule)

        return {'rules': acl_rules_list}

    def _get_interface_name_from_hosting_port(self, port):
        vlan = port['hosting_info']['segmentation_id']
        interface_type, interface_num = port[
            'hosting_info']['hosting_port_name'].split(':')
        offset = 0 if interface_type == 't1_p' else 1
        interface_num = str(int(interface_num) * 2 + offset)
        return 'GigabitEthernet%s.%s' % (interface_num, vlan)

    def _post_acl_to_interfaces(self, firewall, csr, acl_id, status_data):
        acl_interface_url = ACL_API_ACLID_IF % acl_id
        for firewall_interface in firewall['vendor_ext']['if_list']:
            if_name = self._get_interface_name_from_hosting_port(
                firewall_interface['port'])
            acl_interface_req = {
                'if-id': if_name,
                'direction': firewall_interface['direction']
            }
            LOG.debug("acl_interface_url %s", acl_interface_url)
            csr.post_request(acl_interface_url, acl_interface_req)
            if csr.status == requests.codes.CREATED:
                status_data['if_list'].append(
                    {'port_id': firewall_interface['port']['id'],
                     'status': 'OK'})
            else:
                LOG.error(_LE("status %s"), csr.status)
                status_data['if_list'].append(
                    {'port_id': firewall_interface['port']['id'],
                     'status': 'ERROR'})

    def _delete_acl_on_interface(self, csr, acl_id,
                                 csr_firewall_interface_list):
        for interface in csr_firewall_interface_list:
            my_api = ACL_API_ACLID_IFID_DIR % (
                acl_id, interface['if-id'], interface['direction'])
            csr.delete_request(my_api)
            if csr.status != requests.codes.NO_CONTENT:
                LOG.error(_LE("status %s"), csr.status)

    def _get_acl_interface(self, csr, acl_id):
        my_api = ACL_API_ACLID_IF % acl_id
        response = csr.get_request(my_api)
        if csr.status == requests.codes.OK:
            return response['items']

        LOG.error(_LE("status %s"), csr.status)
        return ''

    def _post_acl(self, csr, acl_data):
        response = csr.post_request(ACL_API, acl_data)
        if csr.status == requests.codes.CREATED:
            return response[response.rfind('/') + 1:]

        LOG.error(_LE("status %s"), csr.status)
        return ''

    def _delete_acl(self, csr, acl_id):
        my_api = ACL_API_ACLID % acl_id
        csr.delete_request(my_api)
        if csr.status == requests.codes.NO_CONTENT:
            return True

        LOG.error(_LE("status %s"), csr.status)
        return False

    def _put_acl(self, csr, acl_id, acl_data):
        my_api = ACL_API_ACLID % acl_id
        csr.put_request(my_api, acl_data)
        if csr.status == requests.codes.NO_CONTENT:
            return True

        LOG.error(_LE("status %s"), csr.status)
        return False

    def _create_firewall(self, firewall):
        """Create ACL and apply ACL to interfaces.

        :param firewall: firewall dictionary
        :return: True and status_data if OK
        :return: False and status_data if there is an error
        """

        LOG.debug("firewall %s", firewall)
        if not self._validate_firewall_data(firewall):
            return False, {}
        if not self._validate_firewall_rule_data(firewall):
            return False, {}

        csr = self._get_csr_host(firewall['vendor_ext'])
        acl_data = self._get_acl_rule_data(firewall)
        LOG.debug("acl_data %s", acl_data)

        acl_id = self._post_acl(csr, acl_data)
        if not acl_id:
            LOG.debug("No acl_id created, acl_data %s", acl_data)
            return False, {}
        LOG.debug("new ACL ID: %s", acl_id)

        status_data = {
            'fw_id': firewall['id'],
            'acl_id': acl_id,
            'if_list': []
        }

        if not firewall['admin_state_up']:
            LOG.debug("status %s", status_data)
            return True, status_data

        # apply ACL to interfaces
        self._post_acl_to_interfaces(firewall, csr, acl_id, status_data)

        LOG.debug("status %s", status_data)
        return True, status_data

    def _delete_firewall(self, firewall):
        """Delete ACL.

        :param firewall: firewall dictionary
        :return: True if OK
        :return: False if there is an error
        """

        if not self._validate_firewall_data(firewall):
            return False

        acl_id = firewall['vendor_ext'].get('acl_id')
        if not acl_id:
            LOG.error(_LE("firewall (%s) has no acl_id"), firewall['id'])
            return False

        csr = self._get_csr_host(firewall['vendor_ext'])
        return self._delete_acl(csr, acl_id)

    def _update_firewall(self, firewall):
        """Update ACL and associated interfaces.

        :param firewall: firewall dictionary
        :return: True and status_data if OK
        :return: False and {} if there is an error
        """

        if not self._validate_firewall_data(firewall):
            return False, {}
        if not self._validate_firewall_rule_data(firewall):
            return False, {}

        acl_id = firewall['vendor_ext'].get('acl_id')
        if not acl_id:
            LOG.error(_LE("firewall (%s) has no acl_id"), firewall['id'])
            return False, {}

        csr = self._get_csr_host(firewall['vendor_ext'])
        rest_acl_rules = self._get_acl_rule_data(firewall)
        rest_acl_rules['acl-id'] = acl_id

        # update ACL rules
        response = self._put_acl(csr, acl_id, rest_acl_rules)
        if not response:
            return False, {}

        status_data = {
            'fw_id': firewall['id'],
            'acl_id': acl_id,
            'if_list': []
        }

        # update ACL interface
        # get all interfaces with this acl_id
        csr_fw_interface_list = self._get_acl_interface(csr, acl_id)
        self._delete_acl_on_interface(csr, acl_id, csr_fw_interface_list)

        if not firewall['admin_state_up']:
            return True, status_data

        self._post_acl_to_interfaces(firewall, csr, acl_id, status_data)
        return True, status_data

    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create firewall on CSR."""
        LOG.debug("create_firewall: firewall %s", firewall)
        return self._create_firewall(firewall)

    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall on CSR."""
        LOG.debug("delete_firewall: firewall %s", firewall)
        return self._delete_firewall(firewall)

    def update_firewall(self, agent_mode, apply_list, firewall):
        """Update firewall on CSR."""
        LOG.debug("update_firewall: firewall %s", firewall)
        return self._update_firewall(firewall)

    def apply_default_policy(self, agent_mode, apply_list, firewall):
        # CSR firewall driver does not support this for now
        LOG.debug("apply_default_policy")
