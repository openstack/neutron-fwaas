# Copyright 2016
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

import netaddr
import six

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.tests.tempest_plugin.tests.api import v2_base

CONF = config.CONF


class FWaaSv2ExtensionTestJSON(v2_base.BaseFWaaSTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        List firewall rules
        Create firewall rule
        Update firewall rule
        Delete firewall rule
        Show firewall rule
        List firewall policies
        Create firewall policy
        Update firewall policy
        Insert firewall rule to policy
        Remove firewall rule from policy
        Insert firewall rule after/before rule in policy
        Update firewall policy audited attribute
        Delete firewall policy
        Show firewall policy
        List firewall group
        Create firewall group
        Update firewall group
        Delete firewall group
        Show firewall group
    """

    @classmethod
    def resource_setup(cls):
        super(FWaaSv2ExtensionTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('fwaas_v2', 'network'):
            msg = "FWaaS v2  Extension not enabled."
            raise cls.skipException(msg)

    def setUp(self):
        super(FWaaSv2ExtensionTestJSON, self).setUp()
        self.fw_rule_1 = self.create_firewall_rule(action="allow",
                                                 protocol="tcp")
        self.fw_rule_2 = self.create_firewall_rule(action="deny",
                                                 protocol="udp")
        self.fw_policy_1 = self.create_firewall_policy(
            firewall_rules=[self.fw_rule_1['id']])
        self.fw_policy_2 = self.create_firewall_policy(
            firewall_rules=[self.fw_rule_2['id']])

    def _create_router_interfaces(self):
        network_1 = self.create_network()
        network_2 = self.create_network()

        cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
        mask_bits = CONF.network.project_network_mask_bits

        subnet_cidr_1 = list(cidr.subnet(mask_bits))[-1]
        subnet_cidr_2 = list(cidr.subnet(mask_bits))[-2]
        subnet_1 = self.create_subnet(network_1, cidr=subnet_cidr_1,
            mask_bits=mask_bits)
        subnet_2 = self.create_subnet(network_2, cidr=subnet_cidr_2,
            mask_bits=mask_bits)

        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        self.addCleanup(self._try_delete_router, router)

        intf_1 = self.routers_client.add_router_interface(router['id'],
            subnet_id=subnet_1['id'])
        intf_2 = self.routers_client.add_router_interface(router['id'],
            subnet_id=subnet_2['id'])

        return intf_1, intf_2

    def _try_delete_router(self, router):
        # delete router, if it exists
        try:
            self.delete_router(router)
        # if router is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_policy(self, policy_id):
        # delete policy, if it exists
        try:
            self.firewall_policies_client.delete_firewall_policy(policy_id)
        # if policy is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_rule(self, rule_id):
        # delete rule, if it exists
        try:
            self.firewall_rules_client.delete_firewall_rule(rule_id)
        # if rule is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_firewall_group(self, fwg_id):
        # delete firewall group, if it exists
        try:
            self.firewall_groups_client.delete_firewall_group(fwg_id)
        # if firewall group is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

        self.firewall_groups_client.wait_for_resource_deletion(fwg_id)

    def _wait_until_ready(self, fwg_id):
        target_states = ('ACTIVE', 'CREATED')

        def _wait():
            firewall_group = self.firewall_groups_client.show_firewall_group(
                fwg_id)
            firewall_group = firewall_group['firewall_group']
            return firewall_group['status'] in target_states

        if not test_utils.call_until_true(_wait, CONF.network.build_timeout,
                                          CONF.network.build_interval):
            m = ("Timed out waiting for firewall_group %s to reach %s "
                 "state(s)" %
                 (fwg_id, target_states))
            raise lib_exc.TimeoutException(m)

    def _wait_until_deleted(self, fwg_id):
        def _wait():
            try:
                fwg = self.firewall_groups_client.show_firewall_group(fwg_id)
            except lib_exc.NotFound:
                return True

            fwg_status = fwg['firewall_group']['status']
            if fwg_status == 'ERROR':
                raise lib_exc.DeleteErrorException(resource_id=fwg_id)

        if not test_utils.call_until_true(_wait, CONF.network.build_timeout,
                                          CONF.network.build_interval):
            m = ("Timed out waiting for firewall_group %s deleted" % fwg_id)
            raise lib_exc.TimeoutException(m)

    @decorators.idempotent_id('ddccfa87-4af7-48a6-9e50-0bd0ad1348cb')
    def test_list_firewall_rules(self):
        # List firewall rules
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        fw_rules = fw_rules['firewall_rules']
        self.assertIn((self.fw_rule_1['id'],
                       self.fw_rule_1['name'],
                       self.fw_rule_1['action'],
                       self.fw_rule_1['protocol'],
                       self.fw_rule_1['ip_version'],
                       self.fw_rule_1['enabled']),
                      [(m['id'],
                        m['name'],
                        m['action'],
                        m['protocol'],
                        m['ip_version'],
                        m['enabled']) for m in fw_rules])

    @decorators.idempotent_id('ffc009fa-cd17-4029-8025-c4b81a7dd923')
    def test_create_update_delete_firewall_rule(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id)

        # Update firewall rule
        body = self.firewall_rules_client.update_firewall_rule(fw_rule_id,
                                                               action="deny")
        self.assertEqual("deny", body["firewall_rule"]['action'])

        # Delete firewall rule
        self.firewall_rules_client.delete_firewall_rule(fw_rule_id)
        # Confirm deletion
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        self.assertNotIn(fw_rule_id,
                         [m['id'] for m in fw_rules['firewall_rules']])

    @decorators.idempotent_id('76b07afc-444e-4bb9-abec-9b8c5f994dcd')
    def test_show_firewall_rule(self):
        # show a created firewall rule
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            self.fw_rule_1['id'])
        for key, value in six.iteritems(fw_rule['firewall_rule']):
            if key != 'firewall_policy_id':
                self.assertEqual(self.fw_rule_1[key], value)
            # This check is placed because we cannot modify policy during
            # Create/Update of Firewall Rule but we can see the association
            # of a Firewall Rule with the policies it belongs to.

    @decorators.idempotent_id('f6b83902-746f-4e74-9403-2ec9899583a3')
    def test_list_firewall_policies(self):
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertIn((self.fw_policy_1['id'],
                       self.fw_policy_1['name'],
                       self.fw_policy_1['firewall_rules']),
                      [(m['id'],
                        m['name'],
                        m['firewall_rules']) for m in fw_policies])

    @decorators.idempotent_id('6ef9bd02-7349-4d61-8d1f-80479f64d904')
    def test_create_update_delete_firewall_policy(self):
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Update firewall policy
        body = self.firewall_policies_client.update_firewall_policy(
            fw_policy_id,
            name="updated_policy")
        updated_fw_policy = body["firewall_policy"]
        self.assertEqual("updated_policy", updated_fw_policy['name'])

        # Delete firewall policy
        self.firewall_policies_client.delete_firewall_policy(fw_policy_id)
        # Confirm deletion
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertNotIn(fw_policy_id, [m['id'] for m in fw_policies])

    @decorators.idempotent_id('164381de-61f4-483f-9a5a-48105b8e70e2')
    def test_show_firewall_policy(self):
        # show a created firewall policy
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            self.fw_policy_1['id'])
        fw_policy = fw_policy['firewall_policy']
        for key, value in six.iteritems(fw_policy):
            self.assertEqual(self.fw_policy_1[key], value)

    @decorators.idempotent_id('48dfcd75-3924-479d-bb65-b3ed33397663')
    def test_create_show_delete_firewall_group(self):
        # create router and add interfaces
        intf_1, intf_2 = self._create_router_interfaces()

        # Create firewall_group
        body = self.firewall_groups_client.create_firewall_group(
            name=data_utils.rand_name("firewall_group"),
            ingress_firewall_policy_id=self.fw_policy_1['id'],
            egress_firewall_policy_id=self.fw_policy_2['id'],
            ports=[intf_1['port_id'], intf_2['port_id']])
        created_firewall_group = body['firewall_group']
        fwg_id = created_firewall_group['id']

        # Wait for the firewall resource to become ready
        self._wait_until_ready(fwg_id)

        # show created firewall_group
        firewall_group = self.firewall_groups_client.show_firewall_group(
            fwg_id)
        fwg = firewall_group['firewall_group']

        for key, value in six.iteritems(fwg):
            if key == 'status':
                continue
            self.assertEqual(created_firewall_group[key], value)

        # list firewall_groups
        firewall_groups = self.firewall_groups_client.list_firewall_groups()
        fwgs = firewall_groups['firewall_groups']
        self.assertIn((created_firewall_group['id'],
                       created_firewall_group['name'],
                       created_firewall_group['ingress_firewall_policy_id'],
                       created_firewall_group['egress_firewall_policy_id']),
                      [(m['id'],
                        m['name'],
                        m['ingress_firewall_policy_id'],
                        m['egress_firewall_policy_id']) for m in fwgs])

        # Disassociate all port with this firewall group
        self.firewall_groups_client.update_firewall_group(fwg_id, ports=[])
        # Delete firewall_group
        self.firewall_groups_client.delete_firewall_group(fwg_id)

        # Wait for the firewall group to be deleted
        self._wait_until_deleted(fwg_id)

        # Confirm deletion
        firewall_groups = self.firewall_groups_client.list_firewall_groups()
        fwgs = firewall_groups['firewall_groups']
        self.assertNotIn(fwg_id, [m['id'] for m in fwgs])

    @decorators.idempotent_id('e021baab-d4f7-4bad-b382-bde4946e0e0b')
    def test_update_firewall_group(self):
        # create router and add interfaces
        intf_1, intf_2 = self._create_router_interfaces()

        # Create firewall_group
        body = self.firewall_groups_client.create_firewall_group(
            name=data_utils.rand_name("firewall_group"),
            ingress_firewall_policy_id=self.fw_policy_1['id'],
            egress_firewall_policy_id=self.fw_policy_2['id'],
            ports=[intf_1['port_id']])
        created_firewall_group = body['firewall_group']
        fwg_id = created_firewall_group['id']
        self.addCleanup(self._try_delete_firewall_group, fwg_id)

        # Wait for the firewall resource to become ready
        self._wait_until_ready(fwg_id)

        # Update firewall group
        body = self.firewall_groups_client.update_firewall_group(
            fwg_id,
            ports=[intf_2['port_id']])
        updated_fwg = body["firewall_group"]
        self.assertEqual([intf_2['port_id']], updated_fwg['ports'])

        # Delete firewall_group
        self.firewall_groups_client.delete_firewall_group(fwg_id)

    @decorators.idempotent_id('a1f524d8-5336-4769-aa7b-0830bb4df6c8')
    def test_error_on_create_firewall_group_name_default(self):
        try:
            # Create firewall_group with name == reserved default fwg
            self.firewall_groups_client.create_firewall_group(
                name=fwaas_constants.DEFAULT_FWG)
        except lib_exc.Conflict:
            pass

    @decorators.idempotent_id('fd24db16-c8cb-4cb4-ba60-b0cd18a66b83')
    def test_default_fwg_created_on_list_firewall_groups(self):
        fw_groups = self.firewall_groups_client.list_firewall_groups()
        fw_groups = fw_groups['firewall_groups']
        self.assertIn(fwaas_constants.DEFAULT_FWG,
                      [g['name'] for g in fw_groups])
