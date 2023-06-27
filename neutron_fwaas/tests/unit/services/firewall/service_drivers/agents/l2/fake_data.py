# Copyright 2017 FUJITSU LIMITED
# All Rights Reserved
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

import copy

from unittest import mock

from neutron_lib import constants as nl_consts
from oslo_utils import uuidutils

TENANT_UUID = uuidutils.generate_uuid()
TENANT_ID = TENANT_UUID
PROJECT_ID = TENANT_UUID
NETWORK_ID = uuidutils.generate_uuid()
SUBNET_ID = uuidutils.generate_uuid()
DEVICE_ID = uuidutils.generate_uuid()
PORT1 = uuidutils.generate_uuid()
PORT2 = uuidutils.generate_uuid()
PORT3 = uuidutils.generate_uuid()
PORT4 = uuidutils.generate_uuid()
HOST = 'fake_host'


class FakeFWaaSL2Agent(object):

    def __init__(self):
        super(FakeFWaaSL2Agent, self).__init__()

    def create(self, resource, attrs=None, minimal=False):
        """Create a fake fwaas v2 resources

        :param resource: A dictionary with all attributes
        :type resource: string
        :param attrs: A dictionary of each attribute you need to modify
        :type attrs: dictionary
        :param minimal: True if minimal port_detail is necessary
                        otherwise False
        :type minimal: boolean
        :return:
            A OrderedDict faking the fwaas v2 resource
        """
        target = getattr(self, "_" + resource)
        return copy.deepcopy(target(attrs=attrs, minimal=minimal))

    def _fwg(self, **kwargs):

        fwg = {
            'id': uuidutils.generate_uuid(),
            'name': 'my-group-' + uuidutils.generate_uuid(),
            'ingress_firewall_policy_id': uuidutils.generate_uuid(),
            'egress_firewall_policy_id': uuidutils.generate_uuid(),
            'description': 'my firewall group',
            'status': nl_consts.PENDING_CREATE,
            'ports': [PORT3, PORT4],
            'admin_state_up': True,
            'shared': False,
            'tenant_id': TENANT_ID,
            'project_id': PROJECT_ID
        }
        attrs = kwargs.get('attrs', None)
        if attrs:
            fwg.update(attrs)
        return fwg

    def _fwg_with_rule(self, **kwargs):

        fwg_with_rule = self.create('fwg', attrs={'ports': [PORT1, PORT2]})
        rules = {
            'ingress_rule_list': [mock.Mock()],
            'egress_rule_list': [mock.Mock()],
            'add-port-ids': [PORT1],
            'del-port-ids': [PORT2],
            'port_details': {
                PORT1: {
                    'device': uuidutils.generate_uuid(),
                    'device_owner': 'compute:nova',
                    'host': HOST,
                    'network_id': NETWORK_ID,
                    'fixed_ips': [
                        {'subnet_id': SUBNET_ID, 'ip_address': '172.24.4.5'}],
                    'allowed_address_pairs': [],
                    'port_security_enabled': True,
                    'id': PORT1
                },
                PORT2: {
                    'device': uuidutils.generate_uuid(),
                    'device_owner': 'compute:nova',
                    'host': HOST,
                    'network_id': NETWORK_ID,
                    'fixed_ips': [
                        {'subnet_id': SUBNET_ID, 'ip_address': '172.24.4.6'}],
                    'allowed_address_pairs': [],
                    'port_security_enabled': True,
                    'id': PORT2
                }
            },
        }
        fwg_with_rule.update(rules)

        if kwargs.get('minimal', None):
            fwg_with_rule.update({'ports': []})
            fwg_with_rule.update({'add-port-ids': []})
            fwg_with_rule.update({'del-port-ids': []})
            fwg_with_rule.update({'port_details': {}})

        attrs = kwargs.get('attrs', None)
        if attrs:
            fwg_with_rule.update(attrs)
        return fwg_with_rule

    def _port(self, **kwargs):

        if kwargs.get('minimal', None):
            return {'port_id': uuidutils.generate_uuid()}

        port_detail = {
            'profile': {},
            'network_qos_policy_id': None,
            'qos_policy_id': None,
            'allowed_address_pairs': [],
            'admin_state_up': True,
            'network_id': NETWORK_ID,
            'segmentation_id': None,
            'fixed_ips': [
                {'subnet_id': SUBNET_ID, 'ip_address': '172.24.4.5'}],
            'vif_port': mock.Mock(),
            'device_owner': 'compute:node',
            'physical_network': 'physnet',
            'mac_address': 'fa:16:3e:8a:80:2b',
            'device': DEVICE_ID,
            'port_security_enabled': True,
            'port_id': uuidutils.generate_uuid(),
            'network_type': 'flat',
            'security_groups': []
        }

        attrs = kwargs.get('attrs', None)

        if attrs:
            port_detail.update(attrs)
        return port_detail
