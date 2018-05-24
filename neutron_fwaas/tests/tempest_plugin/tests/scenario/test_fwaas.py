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

import testscenarios

from tempest import config
from tempest.lib import decorators
from tempest import test

from neutron_fwaas.tests.tempest_plugin.tests.scenario import base

CONF = config.CONF

load_tests = testscenarios.load_tests_apply_scenarios


class TestFWaaS(base.FWaaSScenarioTest):
    scenarios = [
        ('without router insersion', {
            'router_insertion': False,
        }),
        ('with router insersion', {
            'router_insertion': True,
        }),
    ]

    def setUp(self):
        super(TestFWaaS, self).setUp()
        required_exts = ['fwaas', 'security-group', 'router']
        if self.router_insertion:
            required_exts.append('fwaasrouterinsertion')
        for ext in required_exts:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s Extension not enabled." % ext
                raise self.skipException(msg)
        self._router_ids = None

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

    def _create_firewall(self, **kwargs):
        if self._router_ids is not None:
            kwargs['router_ids'] = self._router_ids
        return self.create_firewall(**kwargs)

    def _empty_policy(self, **kwargs):
        # NOTE(yamamoto): an empty policy would deny all
        fw_policy = self.create_firewall_policy(firewall_rules=[])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
        }

    def _all_disabled_rules(self, **kwargs):
        # NOTE(yamamoto): a policy whose rules are all disabled would deny all
        fw_rule = self.create_firewall_rule(action="allow", enabled=False)
        fw_policy = self.create_firewall_policy(firewall_rules=[fw_rule['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _block_ip(self, server1_fixed_ip, server2_fixed_ip, **kwargs):
        rules = [
            # NOTE(yamamoto): The filtering is taken place after
            # destination ip is rewritten to fixed-ip.
            self.create_firewall_rule(destination_ip_address=server1_fixed_ip,
                                      action="deny"),
            self.create_firewall_rule(destination_ip_address=server2_fixed_ip,
                                      action="deny"),
            self.create_firewall_rule(action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'server1_fixed_ip': server1_fixed_ip,
            'server2_fixed_ip': server2_fixed_ip,
        }

    def _block_icmp(self, **kwargs):
        fw_rule = self.create_firewall_rule(
            protocol="icmp",
            action="deny")
        fw_rule_allow = self.create_firewall_rule(
            action="allow")
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_allow['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _block_all_with_default_allow(self, **kwargs):
        fw_rule = self.create_firewall_rule(
            action="deny")
        fw_rule_allow = self.create_firewall_rule(
            action="allow")
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_allow['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _admin_disable(self, **kwargs):
        # NOTE(yamamoto): A firewall with admin_state_up=False would block all
        fw_rule = self.create_firewall_rule(action="allow")
        fw_policy = self.create_firewall_policy(firewall_rules=[fw_rule['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'],
                                  admin_state_up=False)
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _allow_ssh_and_icmp(self, ctx):
        fw_ssh_rule = self.create_firewall_rule(
            protocol="tcp",
            destination_port=22,
            action="allow")
        fw_icmp_rule = self.create_firewall_rule(
            protocol="icmp",
            action="allow")
        for rule in [fw_ssh_rule, fw_icmp_rule]:
            self.firewall_policies_client.insert_firewall_rule_in_policy(
                firewall_policy_id=ctx['fw_policy']['id'],
                firewall_rule_id=rule['id'],
                insert_before=ctx['fw_rule']['id'])
            self.addCleanup(
                self._remove_rule_and_wait,
                firewall_id=ctx['fw']['id'],
                firewall_policy_id=ctx['fw_policy']['id'],
                firewall_rule_id=rule['id'])
            self._wait_firewall_ready(ctx['fw']['id'])

    def _remove_rule_and_wait(self, firewall_id, firewall_policy_id,
                              firewall_rule_id):
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        self._wait_firewall_ready(firewall_id)

    def _delete_fw(self, ctx):
        self.delete_firewall_and_wait(ctx['fw']['id'])

    def _set_admin_up(self, firewall_id, up):
        self.firewalls_client.update_firewall(firewall_id=firewall_id,
                                              admin_state_up=up)
        self._wait_firewall_ready(firewall_id=firewall_id)

    def _admin_enable(self, ctx):
        self._set_admin_up(ctx['fw']['id'], up=True)

    def _remove_rule(self, ctx):
        self._remove_rule_and_wait(
            firewall_id=ctx['fw']['id'],
            firewall_policy_id=ctx['fw_policy']['id'],
            firewall_rule_id=ctx['fw_rule']['id'])

    def _disable_rule(self, ctx):
        self.firewall_rules_client.update_firewall_rule(
            firewall_rule_id=ctx['fw_rule']['id'],
            enabled=False)
        self._wait_firewall_ready(ctx['fw']['id'])

    def _allow_ip(self, ctx):
        self._delete_fw(ctx)
        server1_fixed_ip = ctx['server1_fixed_ip']
        server2_fixed_ip = ctx['server2_fixed_ip']
        rules = [
            # NOTE(yamamoto): The filtering is taken place after
            # destination ip is rewritten to fixed-ip.
            # The return traffic should be allowed regardless
            # of firewall rules.
            self.create_firewall_rule(
                destination_ip_address=server1_fixed_ip,
                action="allow"),
            self.create_firewall_rule(
                destination_ip_address=server2_fixed_ip,
                action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])

    def _confirm_allowed(self, **kwargs):
        self.check_connectivity(check_reverse_icmp_ip=self._public_gateway_ip,
                                **kwargs)

    def _confirm_allowed_oneway(self, **kwargs):
        # Can ping and ssh, but can't ping back to the public gateway.
        # Same as _confirm_allowed if _public_gateway_ip is None.
        self.check_connectivity(check_reverse_icmp_ip=self._public_gateway_ip,
                                should_reverse_connect=False, **kwargs)

    def _confirm_blocked(self, **kwargs):
        self.check_connectivity(should_connect=False, **kwargs)

    def _confirm_icmp_blocked_but_tcp(self, **kwargs):
        self.check_connectivity(should_connect=False, check_ssh=False,
                                **kwargs)
        self.check_connectivity(check_icmp=False, **kwargs)

    def _create_topology(self):
        """Create a topology for testing

        +--------+             +-----------+
        |"server"|             | "subnet"  |
        |   VM   +-------------+ "network" |
        +--------+             +----+------+
                                    |
                                    | router interface port
                               +----+-----+
                               | "router" |
                               +----+-----+
                                    | router gateway port
                                    |
                                    |
                               +----+------------------+
                               | existing network      |
                               | ("public_network_id") |
                               +-----------------------+
        """
        public_network_id = CONF.network.public_network_id
        network, subnet, router = self.create_networks()
        security_group = self._create_security_group()
        server, keys = self._create_server(network,
                                           security_group=security_group)
        private_key = keys['private_key']
        server_floating_ip = self.create_floating_ip(server, public_network_id)
        fixed_ip = list(server['addresses'].values())[0][0]['addr']
        floating_ip = server_floating_ip['floating_ip_address']
        return fixed_ip, floating_ip, private_key, router

    def _get_public_gateway_ip(self):
        self._public_gateway_ip = None
        router = self._get_router()
        ext_gw_info = router['external_gateway_info']
        ext_fixed_ips = ext_gw_info['external_fixed_ips']
        for ip in ext_fixed_ips:
            subnet_id = ip['subnet_id']
            res = self.os_admin.subnets_client.show_subnet(subnet_id)
            subnet = res['subnet']
            # REVISIT(yamamoto): IPv4 assumption
            if subnet['ip_version'] == 4:
                self._public_gateway_ip = subnet['gateway_ip']
                return

    def _test_firewall_basic(self, block, allow=None,
                             confirm_allowed=None, confirm_blocked=None):
        if allow is None:
            allow = self._delete_fw
        if confirm_allowed is None:
            confirm_allowed = self._confirm_allowed
        if confirm_blocked is None:
            confirm_blocked = self._confirm_blocked
        ssh_login = CONF.validation.image_ssh_user

        if self.router_insertion and CONF.network.public_router_id:
            # NOTE(yamamoto): If public_router_id is configured
            # router1 and router2 will be the same router.
            msg = "This test assumes no public_router_id configured"
            raise self.skipException(msg)

        server1_fixed_ip, server1_floating_ip, private_key1, router1 = \
            self._create_topology()
        server2_fixed_ip, server2_floating_ip, private_key2, router2 = \
            self._create_topology()
        self._get_public_gateway_ip()
        if self.router_insertion:
            # Specify the router when creating a firewall and ensures that
            # the other router (router2) is not affected by the firewall
            self._router_ids = [router1['id']]
            confirm_allowed2 = self.check_connectivity
            confirm_blocked2 = self.check_connectivity
        else:
            # Without router insertion, all routers should be affected
            # equally
            confirm_allowed2 = confirm_allowed
            confirm_blocked2 = confirm_blocked
        self.check_connectivity(ip_address=server1_floating_ip,
                                username=ssh_login,
                                private_key=private_key1)
        self.check_connectivity(ip_address=server2_floating_ip,
                                username=ssh_login,
                                private_key=private_key2)
        ctx = block(server1_fixed_ip=server1_fixed_ip,
                    server1_floating_ip=server1_floating_ip,
                    server2_fixed_ip=server2_fixed_ip,
                    server2_floating_ip=server2_floating_ip)
        confirm_blocked(ip_address=server1_floating_ip, username=ssh_login,
                        private_key=private_key1)
        confirm_blocked2(ip_address=server2_floating_ip, username=ssh_login,
                         private_key=private_key2)
        allow(ctx)
        confirm_allowed(ip_address=server1_floating_ip, username=ssh_login,
                        private_key=private_key1)
        confirm_allowed2(ip_address=server2_floating_ip, username=ssh_login,
                         private_key=private_key2)

    @decorators.idempotent_id('f970f6b3-6541-47ac-a9ea-f769be1e21a8')
    def test_firewall_block_ip(self):
        self._test_firewall_basic(block=self._block_ip, allow=self._allow_ip,
                                  confirm_allowed=self._confirm_allowed_oneway)

    @decorators.idempotent_id('b985d010-994a-4055-bd5c-9e961464ccde')
    def test_firewall_block_icmp(self):
        self._test_firewall_basic(
            block=self._block_icmp,
            confirm_blocked=self._confirm_icmp_blocked_but_tcp)

    @decorators.idempotent_id('ca473af0-26f9-4fad-9550-1c34371c900e')
    def test_firewall_insert_rule(self):
        self._test_firewall_basic(
            block=self._block_icmp,
            allow=self._allow_ssh_and_icmp,
            confirm_blocked=self._confirm_icmp_blocked_but_tcp)

    @decorators.idempotent_id('54a937a6-cecf-444c-b3f9-b67a1c1b7411')
    def test_firewall_remove_rule(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._remove_rule)

    @decorators.idempotent_id('12a18776-9b60-4479-9988-f45971c96a92')
    def test_firewall_disable_rule(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._disable_rule)

    @decorators.idempotent_id('a2a58c1f-49ad-4b5f-9463-e746b9efe08a')
    def test_firewall_empty_policy(self):
        self._test_firewall_basic(block=self._empty_policy)

    @decorators.idempotent_id('477a47e0-5156-4784-9417-f77970d85c36')
    def test_firewall_all_disabled_rules(self):
        self._test_firewall_basic(block=self._all_disabled_rules)

    @decorators.idempotent_id('a83f51c5-1a18-4d2a-a778-c368e4d95c29')
    def test_firewall_admin_disable(self):
        self._test_firewall_basic(block=self._admin_disable,
                                  allow=self._admin_enable)
