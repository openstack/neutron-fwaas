# Copyright 2016
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import mock
from neutron.tests import fake_notifier
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
import six

from neutron_fwaas.db.firewall.v2 import firewall_db_v2
import neutron_fwaas.extensions
from neutron_fwaas.extensions import firewall_v2
from neutron_fwaas.services.firewall import fwaas_plugin_v2
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.db.firewall.v2 import (
    test_firewall_db_v2 as test_db_firewall)


extensions_path = neutron_fwaas.extensions.__path__[0]

FW_PLUGIN_KLASS = (
    "neutron_fwaas.services.firewall.fwaas_plugin_v2.FirewallPluginV2"
)


class FirewallTestExtensionManager(test_l3_plugin.L3TestExtensionManager):

    def get_resources(self):
        res = super(FirewallTestExtensionManager, self).get_resources()
        res = res + firewall_v2.Firewall_v2.get_resources()
        return res

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFirewallAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallAgentApi, self).setUp()

        self.api = fwaas_plugin_v2.FirewallAgentApi('topic', 'host')

    def test_init(self):
        self.assertEqual('topic', self.api.client.target.topic)
        self.assertEqual('host', self.api.host)

    def _call_test_helper(self, method_name):
        with mock.patch.object(self.api.client, 'cast') as rpc_mock, \
                mock.patch.object(self.api.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = self.api.client
            getattr(self.api, method_name)(mock.sentinel.context, 'test')

        prepare_args = {'fanout': True}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method_name,
                                         firewall_group='test', host='host')

    def test_create_firewall_group(self):
        self._call_test_helper('create_firewall_group')

    def test_update_firewall_group(self):
        self._call_test_helper('update_firewall_group')

    def test_delete_firewall_group(self):
        self._call_test_helper('delete_firewall_group')


class TestFirewallRouterPortBase(
        test_db_firewall.FirewallPluginV2DbTestCase):

    def setUp(self, core_plugin=None, fw_plugin=None, ext_mgr=None):
        self.agentapi_del_fw_p = mock.patch(test_db_firewall.DELETEFW_PATH,
            create=True,
            new=test_db_firewall.FakeAgentApi().delete_firewall_group)
        self.agentapi_del_fw_p.start()

        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatServicePlugin')

        cfg.CONF.set_override('api_extensions_path', extensions_path)
        if not fw_plugin:
            fw_plugin = FW_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin,
            'fw_plugin_name': fw_plugin}

        if not ext_mgr:
            ext_mgr = FirewallTestExtensionManager()
        super(test_db_firewall.FirewallPluginV2DbTestCase, self).setUp(
            plugin=plugin, service_plugins=service_plugins, ext_mgr=ext_mgr)

        self.setup_notification_driver()

        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.plugin = directory.get_plugin('FIREWALL_V2')
        self.callbacks = self.plugin.endpoints[0]


class TestFirewallCallbacks(TestFirewallRouterPortBase):

    def setUp(self):
        super(TestFirewallCallbacks, self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.endpoints[0]

    def test_set_firewall_group_status(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                ingress_firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                res = self.callbacks.set_firewall_group_status(ctx, fwg_id,
                                                         nl_constants.ACTIVE)
                fwg_db = self.plugin.get_firewall_group(ctx, fwg_id)
                self.assertEqual(nl_constants.ACTIVE, fwg_db['status'])
                self.assertTrue(res)
                res = self.callbacks.set_firewall_group_status(ctx, fwg_id,
                                                         nl_constants.ERROR)
                fwg_db = self.plugin.get_firewall_group(ctx, fwg_id)
                self.assertEqual(nl_constants.ERROR, fwg_db['status'])
                self.assertFalse(res)

    def test_firewall_group_deleted(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                ingress_firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                do_delete=False
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                with ctx.session.begin(subtransactions=True):
                    fwg_db = self.plugin._get_firewall_group(ctx, fwg_id)
                    fwg_db['status'] = nl_constants.PENDING_DELETE

                observed = self.callbacks.firewall_group_deleted(ctx, fwg_id)
                self.assertTrue(observed)

            self.assertRaises(f_exc.FirewallGroupNotFound,
                              self.plugin.get_firewall_group,
                              ctx, fwg_id)

    def test_firewall_group_deleted_concurrently(self):
        ctx = context.get_admin_context()
        alt_ctx = context.get_admin_context()

        _get_firewall_group = self.plugin._get_firewall_group

        def getdelete(context, fwg_id):
            fwg_db = _get_firewall_group(context, fwg_id)
            # NOTE(cby): Use a different session to simulate a concurrent del
            with mock.patch.object(
                    firewall_db_v2.Firewall_db_mixin_v2,
                    'delete_firewall_group',
                    return_value=None):
                self.plugin.delete_db_firewall_group_object(alt_ctx, fwg_id)
            return fwg_db

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                do_delete=False
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                with ctx.session.begin(subtransactions=True):
                    fwg_db = self.plugin._get_firewall_group(ctx, fwg_id)
                    fwg_db['status'] = nl_constants.PENDING_DELETE
                    ctx.session.flush()
                with mock.patch.object(
                    self.plugin, '_get_firewall_group', side_effect=getdelete
                ):
                    observed = self.callbacks.firewall_group_deleted(
                        ctx, fwg_id)
                    self.assertTrue(observed)

                self.assertRaises(f_exc.FirewallGroupNotFound,
                                  self.plugin.get_firewall_group,
                                  ctx, fwg_id)

    def test_firewall_group_deleted_not_found(self):
        ctx = context.get_admin_context()
        observed = self.callbacks.firewall_group_deleted(
            ctx, 'notfound')
        self.assertTrue(observed)

    def test_firewall_group_deleted_error(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                observed = self.callbacks.firewall_group_deleted(
                    ctx, fwg_id)
                self.assertFalse(observed)
                fwg_db = self.plugin._get_firewall_group(ctx, fwg_id)
                self.assertEqual(nl_constants.ERROR, fwg_db['status'])


class TestFirewallPluginBasev2(TestFirewallRouterPortBase,
                               test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        super(TestFirewallPluginBasev2, self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        fake_notifier.reset()
        mock.patch.object(self.plugin, '_is_supported_by_fw_l2_driver',
                          return_value=True).start()

    @property
    def _self_context(self):
        return context.Context('', self._tenant_id)

    def test_create_firewall_group_ports_not_specified(self):
        """neutron firewall-create test-policy """
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                name='test',
                ingress_firewall_policy_id=fwp_id,
                egress_firewall_policy_id=fwp_id,
                admin_state_up=True) as fwg1:
                self.assertEqual(nl_constants.INACTIVE,
                    fwg1['firewall_group']['status'])

    def test_create_firewall_group_with_ports(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']
            fwg_ports = [port_id1, port_id2]
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                    name='test',
                    ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id, ports=fwg_ports,
                    admin_state_up=True) as fwg1:
                    self.assertEqual(nl_constants.PENDING_CREATE,
                         fwg1['firewall_group']['status'])

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_create_firewall_group_with_ports_on_diff_routers(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2:
            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']
            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']

            with self.router(name='router1', admin_state_up=True,
                tenant_id=self._tenant_id) as r2, \
                    self.subnet() as s3:

                body = self._router_interface_action(
                    'add',
                    r2['router']['id'],
                    s3['subnet']['id'],
                    None)
                port_id3 = body['port_id']

                fwg_ports = [port_id1, port_id2, port_id3]
                with self.firewall_policy() as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    with self.firewall_group(
                        name='test',
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        ports=fwg_ports,
                        admin_state_up=True) as fwg1:
                        self.assertEqual(nl_constants.PENDING_CREATE,
                            fwg1['firewall_group']['status'])

                self._router_interface_action('remove',
                    r2['router']['id'],
                    s3['subnet']['id'],
                    None)

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_create_firewall_group_with_ports_no_policy(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']
            fwg_ports = [port_id1, port_id2]
            with self.firewall_group(
                name='test',
                default_policy=False,
                ports=fwg_ports,
                admin_state_up=True) as fwg1:
                self.assertEqual(nl_constants.INACTIVE,
                     fwg1['firewall_group']['status'])

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_update_firewall_group_with_new_ports_no_polcy(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2, \
                self.subnet(cidr='30.0.0.0/24') as s3:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s3['subnet']['id'],
                None)
            port_id3 = body['port_id']

            fwg_ports = [port_id1, port_id2]
            with self.firewall_group(
                name='test',
                default_policy=False,
                ports=fwg_ports,
                admin_state_up=True) as fwg1:
                self.assertEqual(nl_constants.INACTIVE,
                     fwg1['firewall_group']['status'])
                data = {'firewall_group': {'ports': [port_id2, port_id3]}}
                req = self.new_update_request('firewall_groups', data,
                                              fwg1['firewall_group']['id'],
                                              context=self._self_context)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))

                self.assertEqual(sorted([port_id2, port_id3]),
                                 sorted(res['firewall_group']['ports']))

                self.assertEqual(nl_constants.INACTIVE,
                                 res['firewall_group']['status'])

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_update_firewall_group_with_new_ports_status_pending(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2, \
                self.subnet(cidr='30.0.0.0/24') as s3:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']
            fwg_ports = [port_id1, port_id2]

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s3['subnet']['id'],
                None)
            port_id3 = body['port_id']

            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                    name='test',
                    ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id, ports=fwg_ports,
                    admin_state_up=True) as fwg1:
                    self.assertEqual(nl_constants.PENDING_CREATE,
                         fwg1['firewall_group']['status'])
                    data = {'firewall_group': {'ports': [port_id2, port_id3]}}
                    req = self.new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'])
                    res = req.get_response(self.ext_api)
                    self.assertEqual(409, res.status_int)
            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_update_firewall_group_with_new_ports_status_active(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2, \
                self.subnet(cidr='30.0.0.0/24') as s3:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']
            fwg_ports = [port_id1, port_id2]

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s3['subnet']['id'],
                None)
            port_id3 = body['port_id']

            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                    name='test',
                    ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id, ports=fwg_ports,
                    admin_state_up=True) as fwg1:
                    self.assertEqual(nl_constants.PENDING_CREATE,
                         fwg1['firewall_group']['status'])

                    ctx = context.get_admin_context()
                    self.callbacks.set_firewall_group_status(ctx,
                        fwg1['firewall_group']['id'], nl_constants.ACTIVE)
                    data = {'firewall_group': {'ports': [port_id2, port_id3]}}
                    req = self.new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'],
                                                  context=self._self_context)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    self.assertEqual(sorted([port_id2, port_id3]),
                                     sorted(res['firewall_group']['ports']))

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_update_firewall_rule_on_active_fwg(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']
            with self.firewall_rule() as fwr:
                with self.firewall_policy(
                    firewall_rules=[fwr['firewall_rule']['id']]) as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    with self.firewall_group(
                        name='test',
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id, ports=[port_id1],
                        admin_state_up=True) as fwg1:
                        self.assertEqual(nl_constants.PENDING_CREATE,
                             fwg1['firewall_group']['status'])

                        ctx = context.get_admin_context()
                        self.callbacks.set_firewall_group_status(ctx,
                            fwg1['firewall_group']['id'], nl_constants.ACTIVE)
                        data = {'firewall_rule': {'name': name}}
                        req = self.new_update_request('firewall_rules', data,
                            fwr['firewall_rule']['id'])
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        for k, v in six.iteritems(attrs):
                            self.assertEqual(v, res['firewall_rule'][k])

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)

    def test_update_firewall_rule_on_pending_create_fwg(self):
        """update should fail"""
        name = "new_firewall_rule1"
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as r, \
                self.subnet() as s1:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']
            with self.firewall_rule() as fwr:
                with self.firewall_policy(
                    firewall_rules=[fwr['firewall_rule']['id']]) as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    with self.firewall_group(
                        name='test',
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id, ports=[port_id1],
                        admin_state_up=True) as fwg1:
                        self.assertEqual(nl_constants.PENDING_CREATE,
                             fwg1['firewall_group']['status'])

                        data = {'firewall_rule': {'name': name}}
                        req = self.new_update_request('firewall_rules', data,
                            fwr['firewall_rule']['id'])
                        res = req.get_response(self.ext_api)
                        self.assertEqual(409, res.status_int)

            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)

    def test_update_firewall_group_with_non_exist_ports(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=self._tenant_id) as r, \
                self.subnet(cidr='30.0.0.0/24') as s:
            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s['subnet']['id'],
                None)
            port_id1 = body['port_id']
            foo_port_id = 'caef152d-b118-4b9b-bc77-800661bf082d'
            fwg_ports = [port_id1]
            with self.firewall_group(
                    name='test',
                    default_policy=False,
                    ports=fwg_ports,
                    admin_state_up=True) as fwg1:
                self.assertEqual(nl_constants.INACTIVE,
                                 fwg1['firewall_group']['status'])
                data = {'firewall_group': {'ports': [foo_port_id]}}
                req = self.new_update_request('firewall_groups', data,
                                              fwg1['firewall_group']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual('PortNotFound',
                                 res['NeutronError']['type'])

            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s['subnet']['id'],
                                          None)

    def _get_user_context(self, user_id="a_user", tenant_id="some_tenant",
                          is_admin=False):
        return context.Context(user_id=user_id, tenant_id=tenant_id,
                               is_admin=is_admin)

    def test_update_firewall_group_with_invalid_project(self):
        with self.router(name='router1',
                         admin_state_up=True,
                         tenant_id=self._tenant_id) as r, \
                self.subnet(cidr='30.0.0.0/24') as s:
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 s['subnet']['id'],
                                                 None)
            port_id = body['port_id']
            with self.firewall_group(name='test',
                                     default_policy=False,
                                     ports=[],
                                     admin_state_up=True,
                                     ctx=self._get_user_context()) as fwg1:
                data = {'firewall_group': {'ports': [port_id]}}
                # make sure that an exception is raised when admin tries to
                # update ports of another tenant
                req = self.new_update_request(
                    'firewall_groups', data, fwg1['firewall_group']['id'],
                    context=context.get_admin_context())
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual('FirewallGroupPortInvalidProject',
                                 res['NeutronError']['type'])

            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s['subnet']['id'],
                                          None)

    def test_update_firewall_group_with_ports_and_polcy(self):
        """neutron firewall_group create test-policy """
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=self._tenant_id) as r,\
                self.subnet() as s1,\
                self.subnet(cidr='20.0.0.0/24') as s2:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']

            fwg_ports = [port_id1, port_id2]
            with self.firewall_rule() as fwr:
                with self.firewall_policy(
                        firewall_rules=[fwr['firewall_rule']['id']]) as fwp:
                    with self.firewall_group(
                            name='test',
                            default_policy=False,
                            ports=fwg_ports,
                            admin_state_up=True) as fwg1:
                        self.assertEqual(nl_constants.INACTIVE,
                             fwg1['firewall_group']['status'])
                        fwp_id = fwp["firewall_policy"]["id"]

                        data = {'firewall_group': {'ports': fwg_ports}}
                        req = (self.
                               new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'],
                                                  context=self._self_context))
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        self.assertEqual(nl_constants.INACTIVE,
                                         res['firewall_group']['status'])

                        data = {'firewall_group': {
                            'ingress_firewall_policy_id': fwp_id}}
                        req = (self.
                               new_update_request('firewall_groups', data,
                                                  fwg1['firewall_group']['id'],
                                                  context=self._self_context))
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        self.assertEqual(nl_constants.PENDING_UPDATE,
                                         res['firewall_group']['status'])

                    self._router_interface_action('remove',
                        r['router']['id'],
                        s1['subnet']['id'],
                        None)
                    self._router_interface_action(
                        'remove',
                        r['router']['id'],
                        s2['subnet']['id'],
                        None)


class TestAutomaticAssociation(TestFirewallPluginBasev2):

    def setUp(self):
        # TODO(yushiro): Replace constant value for this test class
        # Set auto association fwg
        super(TestAutomaticAssociation, self).setUp()
        self.agent_rpc = self.plugin.agent_rpc
        self.plugin.set_port_for_default_firewall_group = mock.Mock()
        self.plugin._get_fwg_port_details = mock.Mock()

    def test_vm_port(self):
        self.plugin._get_fwg_port_details = mock.Mock()
        kwargs = {
            "context": mock.ANY,
            "port": {"id": "fake_port",
                     "device_owner": "compute:nova",
                     "binding:vif_type": "ovs",
                     "project_id": "fake_project"},
            "original_port": {"binding:vif_type": "unbound"}
        }
        self.plugin.handle_update_port(
            "PORT", "after_update", "test_plugin", **kwargs)
        self.plugin.set_port_for_default_firewall_group.\
            assert_called_once_with(mock.ANY,
                                    kwargs['port']['id'],
                                    kwargs['port']['project_id'])

    def test_vm_port_not_newly_created(self):
        # Just updated for VM port(name or description...etc.)
        kwargs = {
            "context": mock.ANY,
            "port": {
                "id": "fake_port",
                "device_owner": "compute:nova",
                "binding:vif_type": "ovs",
                "project_id": "fake_project"
            },
            "original_port": {
                "device_owner": "compute:nova",
                "binding:vif_type": "ovs",
                "project_id": "fake_project"
            }
        }
        self.plugin.handle_update_port(
            "PORT", "after_update", "test_plugin", **kwargs)
        self.plugin.set_port_for_default_firewall_group.assert_not_called()

    def test_not_vm_port(self):
        for device_owner in ["network:router_interface",
                             "network:router_gateway",
                             "network:dhcp"]:
            kwargs = {
                "context": mock.ANY,
                "port": {"id": "fake_port",
                         "device_owner": device_owner,
                         "project_id": "fake_project"},
                "original_port": {"device_owner": device_owner,
                                  "binding:vif_type": "unbound",
                                  "project_id": "fake_project"}
            }
            self.plugin.handle_update_port(
                "PORT", "after_update", "test_plugin", **kwargs)
            self.plugin.set_port_for_default_firewall_group.assert_not_called()
