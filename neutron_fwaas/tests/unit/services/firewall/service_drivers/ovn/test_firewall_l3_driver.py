# Copyright 2022 EasyStack, Inc.
# All rights reserved.
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

from unittest import mock

from neutron import extensions as neutron_extensions
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import fake_resources as fakes
from neutron_lib import constants as nl_constants
from neutron_lib import context

from neutron_fwaas.services.firewall.service_drivers import driver_api
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    firewall_l3_driver as ovn_driver
from neutron_fwaas.tests.unit.services.firewall import test_fwaas_plugin_v2


OVN_FWAAS_DRIVER = ('neutron_fwaas.services.firewall.service_drivers.'
                    'ovn.firewall_l3_driver.OVNFwaasDriver')


class TestOVNFwaasDriver(test_fwaas_plugin_v2.FirewallPluginV2TestCase,
                         test_l3.L3NatTestCaseMixin):

    def setUp(self):
        l3_plugin_str = ('neutron.tests.unit.extensions.test_l3.'
                         'TestL3NatServicePlugin')
        l3_plugin = {'l3_plugin_name': l3_plugin_str}
        super(TestOVNFwaasDriver, self).setUp(
            service_provider=OVN_FWAAS_DRIVER,
            extra_service_plugins=l3_plugin,
            extra_extension_paths=neutron_extensions.__path__)
        self.db = self.plugin.driver.firewall_db
        self.mech_driver = mock.MagicMock()
        self.nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.mech_driver._nb_ovn = self.nb_ovn
        self.mech_driver._sb_ovn = self.sb_ovn

    @property
    def _self_context(self):
        return context.Context('', self._tenant_id)

    def test_create_firewall_group_ports_not_specified(self):
        with self.firewall_policy(as_admin=True) as fwp, \
            mock.patch.object(driver_api.FirewallDriver,
                              '_core_plugin') as mock_ml2:
            fwp_id = fwp['firewall_policy']['id']
            mock_ml2.mechanism_manager = mock.MagicMock()
            mock_ml2.mechanism_manager.mech_drivers = {
                'ovn': self.mech_driver}
            with self.firewall_group(
                    name='test',
                    ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id,
                    admin_state_up=True,
                    as_admin=True) as fwg1:
                self.assertEqual(nl_constants.INACTIVE,
                    fwg1['firewall_group']['status'])

    def test_create_firewall_group_with_ports(self):
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id, as_admin=True) as r, \
                self.subnet(as_admin=True) as s1, \
                self.subnet(cidr='20.0.0.0/24', as_admin=True) as s2:
            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None,
                as_admin=True)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None,
                as_admin=True)
            port_id2 = body['port_id']
            fwg_ports = [port_id1, port_id2]
            with self.firewall_policy(do_delete=False,
                                      as_admin=True) as fwp, \
                mock.patch.object(ovn_driver.OVNFwaasDriver,
                                  '_nb_ovn') as mock_nb_ovn:
                fwp_id = fwp['firewall_policy']['id']
                mock_nb_ovn.return_value = self.nb_ovn
                with self.firewall_group(
                        name='test',
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        ports=fwg_ports, admin_state_up=True,
                        do_delete=False, as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.ACTIVE,
                                     fwg1['firewall_group']['status'])

    def test_update_firewall_group_with_new_ports(self):
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id, as_admin=True) as r, \
                self.subnet(as_admin=True) as s1, \
                self.subnet(cidr='20.0.0.0/24', as_admin=True) as s2, \
                self.subnet(cidr='30.0.0.0/24', as_admin=True) as s3:
            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None,
                as_admin=True)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None,
                as_admin=True)
            port_id2 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s3['subnet']['id'],
                None,
                as_admin=True)
            port_id3 = body['port_id']
            fwg_ports = [port_id1, port_id2]
            with self.firewall_policy(do_delete=False,
                                      as_admin=True) as fwp, \
                mock.patch.object(ovn_driver.OVNFwaasDriver,
                                  '_nb_ovn') as mock_nb_ovn:
                fwp_id = fwp['firewall_policy']['id']
                mock_nb_ovn.return_value = self.nb_ovn
                with self.firewall_group(
                        name='test',
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        ports=fwg_ports, admin_state_up=True,
                        do_delete=False, as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.ACTIVE,
                         fwg1['firewall_group']['status'])
                    data = {'firewall_group': {'ports': [port_id2, port_id3]}}
                    req = self.new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'],
                                                  context=self._self_context,
                                                  as_admin=True)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual(sorted([port_id2, port_id3]),
                                     sorted(res['firewall_group']['ports']))

                    self.assertEqual(nl_constants.ACTIVE,
                                     res['firewall_group']['status'])

    def test_update_firewall_group_with_ports_and_policy(self):
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=self._tenant_id, as_admin=True) as r, \
                self.subnet(as_admin=True) as s1, \
                self.subnet(cidr='20.0.0.0/24', as_admin=True) as s2:
            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None,
                as_admin=True)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None,
                as_admin=True)
            port_id2 = body['port_id']

            fwg_ports = [port_id1, port_id2]
            with self.firewall_rule(do_delete=False, as_admin=True) as fwr, \
                mock.patch.object(ovn_driver.OVNFwaasDriver,
                                  '_nb_ovn') as mock_nb_ovn:
                mock_nb_ovn.return_value = self.nb_ovn
                with self.firewall_policy(
                        firewall_rules=[fwr['firewall_rule']['id']],
                        do_delete=False,
                        as_admin=True) as fwp:
                    with self.firewall_group(
                            name='test',
                            default_policy=False,
                            ports=fwg_ports,
                            admin_state_up=True,
                            do_delete=False,
                            as_admin=True) as fwg1:
                        self.assertEqual(nl_constants.ACTIVE,
                             fwg1['firewall_group']['status'])

                        fwp_id = fwp["firewall_policy"]["id"]
                        data = {'firewall_group': {'ports': fwg_ports}}
                        req = (self.
                               new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'],
                                                  context=self._self_context,
                                                  as_admin=True))
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        self.assertEqual(nl_constants.ACTIVE,
                                         res['firewall_group']['status'])

                        data = {'firewall_group': {
                            'ingress_firewall_policy_id': fwp_id}}
                        req = (self.
                               new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'],
                                                  context=self._self_context,
                                                  as_admin=True))
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        self.assertEqual(nl_constants.ACTIVE,
                                         res['firewall_group']['status'])

    def test_update_firewall_policy_with_new_rules(self):
        with self.firewall_rule(do_delete=False, as_admin=True) as fwr, \
            self.firewall_rule(name='firewall_rule2', action='reject',
                               do_delete=False, as_admin=True) as fwr2, \
            self.firewall_rule(name='firewall_rule3', action='deny',
                               do_delete=False, as_admin=True) as fwr3, \
            mock.patch.object(ovn_driver.OVNFwaasDriver,
                              '_nb_ovn') as mock_nb_ovn:
            mock_nb_ovn.return_value = self.nb_ovn
            fwr_id = fwr['firewall_rule']['id']
            fwr2_id = fwr2['firewall_rule']['id']
            fwr3_id = fwr3['firewall_rule']['id']
            with self.firewall_policy(
                    firewall_rules=[fwr_id],
                    do_delete=False,
                    as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                        name='test',
                        default_policy=False,
                        admin_state_up=True,
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        do_delete=False,
                        as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.INACTIVE,
                         fwg1['firewall_group']['status'])

                    new_rules = [fwr_id, fwr2_id, fwr3_id]
                    data = {'firewall_policy': {'firewall_rules':
                                                new_rules}}
                    req = (self.
                           new_update_request('firewall_policies', data,
                                              fwp_id,
                                              context=self._self_context,
                                              as_admin=True))
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual(new_rules,
                                     res['firewall_policy']['firewall_rules'])

    def test_disable_firewall_rule(self):
        with self.firewall_rule(do_delete=False, as_admin=True) as fwr, \
            mock.patch.object(ovn_driver.OVNFwaasDriver,
                              '_nb_ovn') as mock_nb_ovn:
            mock_nb_ovn.return_value = self.nb_ovn
            fwr_id = fwr['firewall_rule']['id']
            with self.firewall_policy(
                    firewall_rules=[fwr_id],
                    do_delete=False,
                    as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                        name='test',
                        default_policy=False,
                        admin_state_up=True,
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        do_delete=False,
                        as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.INACTIVE,
                         fwg1['firewall_group']['status'])

                    data = {'firewall_rule': {'enabled': False}}
                    req = (self.
                           new_update_request('firewall_rules', data,
                                              fwr_id,
                                              context=self._self_context,
                                              as_admin=True))
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual(False,
                                     res['firewall_rule']['enabled'])

    def test_enable_firewall_rule(self):
        with self.firewall_rule(enabled=False, do_delete=False,
                                as_admin=True) as fwr, \
            mock.patch.object(ovn_driver.OVNFwaasDriver,
                              '_nb_ovn') as mock_nb_ovn:
            mock_nb_ovn.return_value = self.nb_ovn
            fwr_id = fwr['firewall_rule']['id']
            with self.firewall_policy(
                    firewall_rules=[fwr_id],
                    do_delete=False,
                    as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                        name='test',
                        default_policy=False,
                        admin_state_up=True,
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        do_delete=False,
                        as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.INACTIVE,
                         fwg1['firewall_group']['status'])

                    data = {'firewall_rule': {'enabled': True}}
                    req = (self.
                           new_update_request('firewall_rules', data,
                                              fwr_id,
                                              context=self._self_context,
                                              as_admin=True))
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual(True,
                                     res['firewall_rule']['enabled'])

    def test_update_firewall_rule_with_action(self):
        with self.firewall_rule(source_port=None, destination_port=None,
                                protocol='icmp', do_delete=False,
                                as_admin=True) as fwr, \
            mock.patch.object(ovn_driver.OVNFwaasDriver,
                              '_nb_ovn') as mock_nb_ovn:
            mock_nb_ovn.return_value = self.nb_ovn
            fwr_id = fwr['firewall_rule']['id']
            with self.firewall_policy(
                    firewall_rules=[fwr_id],
                    do_delete=False,
                    as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                        name='test',
                        default_policy=False,
                        admin_state_up=True,
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        do_delete=False,
                        as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.INACTIVE,
                         fwg1['firewall_group']['status'])

                    data = {'firewall_rule': {'action': 'deny'}}
                    req = (self.
                           new_update_request('firewall_rules', data,
                                              fwr_id,
                                              context=self._self_context,
                                              as_admin=True))
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual('deny',
                                     res['firewall_rule']['action'])

    def test_insert_rule_into_firewall_policy(self):
        with self.firewall_rule(do_delete=False, as_admin=True) as fwr, \
            self.firewall_rule(name='firewall_rule2', action='reject',
                               do_delete=False, as_admin=True) as fwr2, \
            mock.patch.object(ovn_driver.OVNFwaasDriver,
                              '_nb_ovn') as mock_nb_ovn:
            mock_nb_ovn.return_value = self.nb_ovn
            fwr_id = fwr['firewall_rule']['id']
            fwr2_id = fwr2['firewall_rule']['id']
            with self.firewall_policy(
                    firewall_rules=[fwr_id],
                    do_delete=False,
                    as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                        name='test',
                        default_policy=False,
                        admin_state_up=True,
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        do_delete=False,
                        as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.INACTIVE,
                         fwg1['firewall_group']['status'])

                    data = {'firewall_rule_id': fwr2_id,
                            'insert_after': fwr_id}
                    req = (self.
                           new_update_request('firewall_policies', data,
                                              fwp_id,
                                              subresource='insert_rule',
                                              context=self._self_context,
                                              as_admin=True))
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual([fwr_id, fwr2_id],
                                     res['firewall_rules'])

    def test_remove_rules_from_firewall_policy(self):
        with self.firewall_rule(do_delete=False, as_admin=True) as fwr, \
            self.firewall_rule(name='firewall_rule2', action='reject',
                               do_delete=False, as_admin=True) as fwr2, \
            mock.patch.object(ovn_driver.OVNFwaasDriver,
                              '_nb_ovn') as mock_nb_ovn:
            mock_nb_ovn.return_value = self.nb_ovn
            fwr_id = fwr['firewall_rule']['id']
            fwr2_id = fwr2['firewall_rule']['id']
            with self.firewall_policy(
                    firewall_rules=[fwr_id, fwr2_id],
                    do_delete=False, as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                        name='test',
                        default_policy=False,
                        admin_state_up=True,
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        do_delete=False,
                        as_admin=True) as fwg1:
                    self.assertEqual(nl_constants.INACTIVE,
                         fwg1['firewall_group']['status'])

                    data = {'firewall_rule_id': fwr2_id}
                    req = (self.
                           new_update_request('firewall_policies', data,
                                              fwp_id,
                                              subresource='remove_rule',
                                              context=self._self_context,
                                              as_admin=True))
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))

                    self.assertEqual([fwr_id],
                                     res['firewall_rules'])
