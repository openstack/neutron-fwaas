# Copyright (c) 2015 Midokura SARL
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

from tempest import config
from tempest import test

from neutron_fwaas.tests.tempest_plugin.tests.scenario import base

CONF = config.CONF


class TestFWaaS(base.FWaaSScenarioTest):

    @classmethod
    def resource_setup(cls):
        super(TestFWaaS, cls).resource_setup()
        for ext in ['fwaas', 'security-group', 'router']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s Extension not enabled." % ext
                raise cls.skipException(msg)

    def _create_server(self, network, security_group=None):
        keys = self.create_keypair()
        kwargs = {
            'networks': [
                {'uuid': network['id']},
            ],
            'key_name': keys['name'],
        }
        if security_group is not None:
            kwargs['security_groups'] = [{'name': security_group['name']}]
        server = self.create_server(create_kwargs=kwargs)
        return server, keys

    @test.idempotent_id('f970f6b3-6541-47ac-a9ea-f769be1e21a8')
    def test_firewall_basic(self):
        ssh_login = CONF.compute.image_ssh_user
        public_network_id = CONF.network.public_network_id

        network1, subnet1, router1 = self.create_networks()
        security_group = self._create_security_group()
        server1, keys1 = self._create_server(network1,
                                             security_group=security_group)
        private_key = keys1['private_key']
        server1_floating_ip = self.create_floating_ip(server1,
                                                      public_network_id)
        server1_ip = server1_floating_ip.floating_ip_address

        self.check_vm_connectivity(server1_ip, username=ssh_login,
                                   private_key=private_key,
                                   should_connect=True)

        # Create a firewall to block traffic.
        fw_rule = self.create_firewall_rule(
            source_ip_address=server1_ip,
            action="deny")
        fw_policy = self.create_firewall_policy(firewall_rules=[fw_rule['id']])
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'])
        self.check_vm_connectivity(server1_ip, username=ssh_login,
                                   private_key=private_key,
                                   should_connect=False)

        # Remove the firewall so that the VM is reachable again.
        self.firewalls_client.delete_firewall(fw['id'])
        self.check_vm_connectivity(server1_ip, username=ssh_login,
                                   private_key=private_key,
                                   should_connect=True)
