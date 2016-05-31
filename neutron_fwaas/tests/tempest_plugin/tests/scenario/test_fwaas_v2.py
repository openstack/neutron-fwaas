# Copyright (c) 2016 Juniper Networks
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


import testscenarios

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron_fwaas.tests.tempest_plugin.tests.scenario import base


CONF = config.CONF
LOG = logging.getLogger(__name__)
load_tests = testscenarios.load_tests_apply_scenarios


class TestFWaaS_v2(base.FWaaSScenarioTest_V2):
    """
    Config Requirement in tempest.conf:
    - project_network_cidr_bits- specifies the subnet range for each network
    - project_network_cidr
    - public_network_id
    """

    def setUp(self):
        LOG.debug("Initializing FWaaSScenarioTest Setup")
        super(TestFWaaS_v2, self).setUp()
        required_exts = ['fwaas_v2', 'security-group', 'router']
        # if self.router_insertion:
        #    required_exts.append('fwaasrouterinsertion')
        for ext in required_exts:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s Extension not enabled." % ext
                raise self.skipException(msg)
        LOG.debug("FWaaSScenarioTest Setup done.")

    def _create_server(self, network, security_group=None):
        keys = self.create_keypair()
        kwargs = {}
        if security_group is not None:
            kwargs['security_groups'] = [{'name': security_group['name']}]
        server = self.create_server(
            key_name=keys['name'],
            networks=[{'uuid': network['id']}],
            wait_until='ACTIVE',
            **kwargs)
        return server, keys

    def _check_connectivity_between_internal_networks(
            self, floating_ip1, keys1, network2, server2, should_connect=True):
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self.os_admin.ports_client.list_ports(
                            tenant_id=server2['tenant_id'],
                            network_id=network2['id'])['ports']
                        if p['device_owner'].startswith('network'))
        self._check_server_connectivity(
            floating_ip1, keys1, internal_ips, should_connect)

    def _check_server_connectivity(self, floating_ip, keys1, address_list,
                                   should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = keys1
        ssh_source = self.get_remote_client(
            ip_address, private_key=private_key)

        for remote_ip in address_list:
            if should_connect:
                msg = ("Timed out waiting for %s to become "
                       "reachable") % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "floating-ip {src}".format(dest=remote_ip,
                                                         src=floating_ip))
                raise

    def _check_remote_connectivity(self, source, dest, should_succeed=True,
                                   nic=None):
        """check ping server via source ssh connection

        :param source: RemoteClient: an ssh connection from which to ping
        :param dest: and IP to ping against
        :param should_succeed: boolean should ping succeed or not
        :param nic: specific network interface to ping from
        :returns: boolean -- should_succeed == ping
        :returns: ping is false if ping failed
        """
        def ping_remote():
            try:
                source.ping_host(dest, nic=nic)
            except lib_exc.SSHExecCommandFailed:
                LOG.warning('Failed to ping IP: %s via a ssh connection '
                            'from: %s.', dest, source.ssh_client.host)
                return not should_succeed
            return should_succeed

        return test_utils.call_until_true(ping_remote,
                                          CONF.validation.ping_timeout,
                                          1)

    def _add_router_interface(self, router_id, subnet_id):
        resp = self.routers_client.add_router_interface(
            router_id, subnet_id=subnet_id)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.routers_client.remove_router_interface, router_id,
                        subnet_id=subnet_id)
        return resp

    def _create_network_subnet(self):
        network = self._create_network()
        subnet_kwargs = dict(network=network)
        subnet = self._create_subnet(**subnet_kwargs)
        return network, subnet

    def _create_test_server(self, network, security_group):
        pub_network_id = CONF.network.public_network_id
        server, keys = self._create_server(
            network, security_group=security_group)
        private_key = keys['private_key']
        server_floating_ip = self.create_floating_ip(server, pub_network_id)
        fixed_ip = server['addresses'].values()[0][0]['addr']
        return server, private_key, fixed_ip, server_floating_ip

    def _create_topology(self):
        """
        +--------+             +-------------+
        |"server"|             | "subnet"    |
        |   VM-1 +-------------+ "network-1" |
        +--------+             +----+--------+
                                    |
                                    | router interface port
                               +----+-----+
                               | "router" |
                               +----+-----+
                                    | router interface port
                                    |
                                    |
        +--------+             +-------------+
        |"server"|             | "subnet"    |
        |   VM-2 +-------------+ "network-2" |
        +--------+             +----+--------+
        """
        LOG.debug('Starting Topology Creation')
        resp = {}
        # Create Network1 and Subnet1.
        network1, subnet1 = self._create_network_subnet()
        resp['network1'] = network1
        resp['subnet1'] = subnet1

        # Create Network2 and Subnet2.
        network2, subnet2 = self._create_network_subnet()
        resp['network2'] = network2
        resp['subnet2'] = subnet2

        # Create a router and attach Network1, Network2 and External Networks
        # to it.
        router = self._create_router(namestart='SCENARIO-TEST-ROUTER')
        pub_network_id = CONF.network.public_network_id
        kwargs = {'external_gateway_info': dict(network_id=pub_network_id)}
        router = self.routers_client.update_router(
            router['id'], **kwargs)['router']
        router_id = router['id']
        resp_add_intf = self._add_router_interface(
            router_id, subnet_id=subnet1['id'])
        router_portid_1 = resp_add_intf['port_id']
        resp_add_intf = self._add_router_interface(
            router_id, subnet_id=subnet2['id'])
        router_portid_2 = resp_add_intf['port_id']
        resp['router'] = router
        resp['router_portid_1'] = router_portid_1
        resp['router_portid_2'] = router_portid_2

        # Create a VM on each of the network and assign it a floating IP.
        security_group = self._create_security_group()
        server1, private_key1, server_fixed_ip_1, server_floating_ip_1 = (
            self._create_test_server(network1, security_group))
        server2, private_key2, server_fixed_ip_2, server_floating_ip_2 = (
            self._create_test_server(network2, security_group))
        resp['server1'] = server1
        resp['private_key1'] = private_key1
        resp['server_fixed_ip_1'] = server_fixed_ip_1
        resp['server_floating_ip_1'] = server_floating_ip_1
        resp['server2'] = server2
        resp['private_key2'] = private_key2
        resp['server_fixed_ip_2'] = server_fixed_ip_2
        resp['server_floating_ip_2'] = server_floating_ip_2

        return resp

    @decorators.idempotent_id('77fdf3ea-82c1-453d-bfec-f7efe335625d')
    def test_icmp_reachability_scenarios(self):
        topology = self._create_topology()
        ssh_login = CONF.validation.image_ssh_user

        self.check_vm_connectivity(
            ip_address=topology['server_floating_ip_1']['floating_ip_address'],
            username=ssh_login,
            private_key=topology['private_key1'])
        self.check_vm_connectivity(
            ip_address=topology['server_floating_ip_2']['floating_ip_address'],
            username=ssh_login,
            private_key=topology['private_key2'])

        # Scenario 1: Add allow ICMP rules between the two VMs.
        fw_allow_icmp_rule = self.create_firewall_rule(action="allow",
                                                       protocol="icmp")
        fw_allow_ssh_rule = self.create_firewall_rule(action="allow",
                                                      protocol="tcp",
                                                      destination_port=22)
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_allow_icmp_rule['id'], fw_allow_ssh_rule['id']])
        fw_group = self.create_firewall_group(
            ports=[
                topology['router_portid_1'],
                topology['router_portid_2']],
            ingress_firewall_policy_id=fw_policy['id'],
            egress_firewall_policy_id=fw_policy['id'])
        self._wait_firewall_group_ready(fw_group['id'])
        LOG.debug('fw_allow_icmp_rule: %s\nfw_allow_ssh_rule: %s\n'
                  'fw_policy: %s\nfw_group: %s\n',
                  fw_allow_icmp_rule, fw_allow_ssh_rule, fw_policy, fw_group)

        # Check the connectivity between VM1 and VM2. It should Pass.
        self._check_server_connectivity(
            topology['server_floating_ip_1'],
            topology['private_key1'],
            address_list=[topology['server_fixed_ip_2']],
            should_connect=True)

        # Scenario 2: Now remove the allow_icmp rule add a deny_icmp rule and
        # check that ICMP gets blocked
        fw_deny_icmp_rule = self.create_firewall_rule(action="deny",
                                                      protocol="icmp")
        self.remove_firewall_rule_from_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_deny_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self._check_server_connectivity(
            topology['server_floating_ip_1'],
            topology['private_key1'],
            address_list=[topology['server_fixed_ip_2']],
            should_connect=False)

        # Scenario 3: Create a rule allowing ICMP only from server_fixed_ip_1
        # to server_fixed_ip_2 and check that traffic from opposite direction
        # is blocked.
        fw_allow_unidirectional_icmp_rule = self.create_firewall_rule(
            action="allow", protocol="icmp",
            source_ip_address=topology['server_fixed_ip_1'],
            destination_ip_address=topology['server_fixed_ip_2'])

        self.remove_firewall_rule_from_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_deny_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_unidirectional_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])

        self._check_server_connectivity(
            topology['server_floating_ip_1'],
            topology['private_key1'],
            address_list=[topology['server_fixed_ip_2']],
            should_connect=True)
        self._check_server_connectivity(
            topology['server_floating_ip_2'],
            topology['private_key2'],
            address_list=[topology['server_fixed_ip_1']],
            should_connect=False)

        # Disassociate ports of this firewall group for cleanup resources
        self.firewall_groups_client.update_firewall_group(
            fw_group['id'], ports=[])
