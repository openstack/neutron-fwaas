# Copyright (c) 2015 Thales Services SAS
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
import functools

import netaddr

import fixtures
from neutron_lib import constants
from neutronclient.common import exceptions

from neutron.common import utils
from neutron.extensions import portbindings


def _safe_method(f):
    @functools.wraps(f)
    def delete(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except exceptions.NotFound:
            pass
    return delete


class ClientFixture(fixtures.Fixture):
    """Manage and cleanup neutron resources."""

    def __init__(self, client):
        super().__init__()
        self.client = client

    def _create_resource(self, resource_type, spec):
        create = getattr(self.client, 'create_%s' % resource_type)
        delete = getattr(self.client, 'delete_%s' % resource_type)

        body = {resource_type: spec}
        resp = create(body=body)
        data = resp[resource_type]
        self.addCleanup(_safe_method(delete), data['id'])
        return data

    def create_router(self, tenant_id, name=None, ha=False,
                      external_network=None):
        resource_type = 'router'

        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name, 'ha': ha}
        if external_network:
            spec['external_gateway_info'] = {"network_id": external_network}

        return self._create_resource(resource_type, spec)

    def create_network(self, tenant_id, name=None, external=False):
        resource_type = 'network'

        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name}
        spec['router:external'] = external
        return self._create_resource(resource_type, spec)

    def create_subnet(self, tenant_id, network_id,
                      cidr, gateway_ip=None, name=None, enable_dhcp=True,
                      ipv6_address_mode='slaac', ipv6_ra_mode='slaac'):
        resource_type = 'subnet'

        name = name or utils.get_rand_name(prefix=resource_type)
        ip_version = netaddr.IPNetwork(cidr).version
        spec = {'tenant_id': tenant_id, 'network_id': network_id, 'name': name,
                'cidr': cidr, 'enable_dhcp': enable_dhcp,
                'ip_version': ip_version}
        if ip_version == constants.IP_VERSION_6:
            spec['ipv6_address_mode'] = ipv6_address_mode
            spec['ipv6_ra_mode'] = ipv6_ra_mode

        if gateway_ip:
            spec['gateway_ip'] = gateway_ip

        return self._create_resource(resource_type, spec)

    def create_port(self, tenant_id, network_id, hostname=None,
                    qos_policy_id=None, **kwargs):
        spec = {
            'network_id': network_id,
            'tenant_id': tenant_id,
        }
        spec.update(kwargs)
        if hostname is not None:
            spec[portbindings.HOST_ID] = hostname
        if qos_policy_id:
            spec['qos_policy_id'] = qos_policy_id
        return self._create_resource('port', spec)

    def create_floatingip(self, tenant_id, floating_network_id,
                          fixed_ip_address, port_id):
        spec = {
            'floating_network_id': floating_network_id,
            'tenant_id': tenant_id,
            'fixed_ip_address': fixed_ip_address,
            'port_id': port_id
        }

        return self._create_resource('floatingip', spec)

    def add_router_interface(self, router_id, subnet_id):
        body = {'subnet_id': subnet_id}
        router_interface_info = self.client.add_interface_router(
            router=router_id, body=body)
        self.addCleanup(_safe_method(self.client.remove_interface_router),
                        router=router_id, body=body)
        return router_interface_info

    def create_qos_policy(self, tenant_id, name, description, shared):
        policy = self.client.create_qos_policy(
            body={'policy': {'name': name,
                             'description': description,
                             'shared': shared,
                             'tenant_id': tenant_id}})

        def detach_and_delete_policy():
            qos_policy_id = policy['policy']['id']
            ports_with_policy = self.client.list_ports(
                qos_policy_id=qos_policy_id)['ports']
            for port in ports_with_policy:
                self.client.update_port(
                    port['id'],
                    body={'port': {'qos_policy_id': None}})
            self.client.delete_qos_policy(qos_policy_id)

        # NOTE: We'll need to add support for detaching from network once
        # create_network() supports qos_policy_id.
        self.addCleanup(_safe_method(detach_and_delete_policy))

        return policy['policy']

    def create_bandwidth_limit_rule(self, tenant_id, qos_policy_id, limit=None,
                                    burst=None):
        rule = {'tenant_id': tenant_id}
        if limit:
            rule['max_kbps'] = limit
        if burst:
            rule['max_burst_kbps'] = burst
        rule = self.client.create_bandwidth_limit_rule(
            policy=qos_policy_id,
            body={'bandwidth_limit_rule': rule})

        self.addCleanup(_safe_method(self.client.delete_bandwidth_limit_rule),
                        rule['bandwidth_limit_rule']['id'],
                        qos_policy_id)

        return rule['bandwidth_limit_rule']

    def create_dscp_marking_rule(self, tenant_id, qos_policy_id, dscp_mark=0):
        rule = {'tenant_id': tenant_id}
        if dscp_mark:
            rule['dscp_mark'] = dscp_mark
        rule = self.client.create_dscp_marking_rule(
            policy=qos_policy_id,
            body={'dscp_marking_rule': rule})

        self.addCleanup(_safe_method(self.client.delete_dscp_marking_rule),
                        rule['dscp_marking_rule']['id'],
                        qos_policy_id)

        return rule['dscp_marking_rule']

    def create_trunk(self, tenant_id, port_id, name=None,
                     admin_state_up=None, sub_ports=None):
        """Create a trunk via API.

        :param tenant_id: ID of the tenant.
        :param port_id: Parent port of trunk.
        :param name: Name of the trunk.
        :param admin_state_up: Admin state of the trunk.
        :param sub_ports: List of subport dictionaries in format
                {'port_id': <ID of neutron port for subport>,
                 'segmentation_type': 'vlan',
                 'segmentation_id': <VLAN tag>}

        :return: Dictionary with trunk's data returned from Neutron API.
        """
        spec = {
            'port_id': port_id,
            'tenant_id': tenant_id,
        }
        if name is not None:
            spec['name'] = name
        if sub_ports is not None:
            spec['sub_ports'] = sub_ports
        if admin_state_up is not None:
            spec['admin_state_up'] = admin_state_up

        trunk = self.client.create_trunk({'trunk': spec})['trunk']

        if sub_ports:
            self.addCleanup(
                _safe_method(self.trunk_remove_subports),
                tenant_id, trunk['id'], trunk['sub_ports'])
        self.addCleanup(_safe_method(self.client.delete_trunk), trunk['id'])

        return trunk

    def trunk_add_subports(self, tenant_id, trunk_id, sub_ports):
        """Add subports to the trunk.

        :param tenant_id: ID of the tenant.
        :param trunk_id: ID of the trunk.
        :param sub_ports: List of subport dictionaries to be added in format
                {'port_id': <ID of neutron port for subport>,
                 'segmentation_type': 'vlan',
                 'segmentation_id': <VLAN tag>}
        """
        spec = {
            'tenant_id': tenant_id,
            'sub_ports': sub_ports,
        }
        trunk = self.client.trunk_add_subports(trunk_id, spec)

        sub_ports_to_remove = [
            sub_port for sub_port in trunk['sub_ports']
            if sub_port in sub_ports]
        self.addCleanup(
            _safe_method(self.trunk_remove_subports), tenant_id, trunk_id,
            sub_ports_to_remove)

    def trunk_remove_subports(self, tenant_id, trunk_id, sub_ports):
        """Remove subports from the trunk.

        :param trunk_id: ID of the trunk.
        :param sub_ports: List of subport port IDs.
        """
        spec = {
            'tenant_id': tenant_id,
            'sub_ports': sub_ports,
        }
        return self.client.trunk_remove_subports(trunk_id, spec)
