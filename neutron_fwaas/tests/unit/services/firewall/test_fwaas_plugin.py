# Copyright 2013 Big Switch Networks, Inc.
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
from neutron.api import extensions as api_ext
from neutron.common import config
from neutron.tests.common import helpers
from neutron.tests import fake_notifier
from neutron.tests.unit.extensions import test_agent
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron_lib.api import attributes as attr
from neutron_lib.api.definitions import firewall as fwaas_def
from neutron_lib.api.definitions import firewallrouterinsertion
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v1 as f_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils
import six
import testtools
from webob import exc

from neutron_fwaas.db.firewall import firewall_db as fdb
import neutron_fwaas.extensions
from neutron_fwaas.extensions import firewall
from neutron_fwaas.services.firewall import fwaas_plugin
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.db.firewall import (
    test_firewall_db as test_db_firewall)

extensions_path = neutron_fwaas.extensions.__path__[0]

FW_PLUGIN_KLASS = (
    "neutron_fwaas.services.firewall.fwaas_plugin.FirewallPlugin"
)


class FirewallTestExtensionManager(test_l3_plugin.L3TestExtensionManager):

    def get_resources(self):
        res = super(FirewallTestExtensionManager, self).get_resources()
        fwaas_def.RESOURCE_ATTRIBUTE_MAP['firewalls'].update(
            firewallrouterinsertion.RESOURCE_ATTRIBUTE_MAP['firewalls'])
        return res + firewall.Firewall.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFirewallRouterInsertionBase(
        test_db_firewall.FirewallPluginDbTestCase):

    def setUp(self, core_plugin=None, fw_plugin=None, ext_mgr=None):
        self.agentapi_del_fw_p = mock.patch(test_db_firewall.DELETEFW_PATH,
            create=True, new=test_db_firewall.FakeAgentApi().delete_firewall)
        self.agentapi_del_fw_p.start()

        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatAgentSchedulingServicePlugin')

        cfg.CONF.set_override('api_extensions_path', extensions_path)
        self.saved_attr_map = {}
        for resource, attrs in six.iteritems(attr.RESOURCES):
            self.saved_attr_map[resource] = attrs.copy()
        if not fw_plugin:
            fw_plugin = FW_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin,
            'fw_plugin_name': fw_plugin}

        if not ext_mgr:
            ext_mgr = FirewallTestExtensionManager()
        super(test_db_firewall.FirewallPluginDbTestCase, self).setUp(
            plugin=plugin, service_plugins=service_plugins, ext_mgr=ext_mgr)

        self.addCleanup(self.restore_attribute_map)
        self.setup_notification_driver()

        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.plugin = directory.get_plugin('FIREWALL')
        self.callbacks = self.plugin.endpoints[0]

    def restore_attribute_map(self):
        # Remove the fwaasrouterinsertion extension
        fwaas_def.RESOURCE_ATTRIBUTE_MAP['firewalls'].pop('router_ids')
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attr.RESOURCES = self.saved_attr_map

    def _create_firewall(self, fmt, name, description, firewall_policy_id=None,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        router_ids = kwargs.get('router_ids')
        if firewall_policy_id is None:
            res = self._create_firewall_policy(fmt, 'fwp',
                                               description="firewall_policy",
                                               shared=True,
                                               firewall_rules=[],
                                               audited=True)
            firewall_policy = self.deserialize(fmt or self.fmt, res)
            firewall_policy_id = firewall_policy["firewall_policy"]["id"]
        data = {'firewall': {'name': name,
                             'description': description,
                             'firewall_policy_id': firewall_policy_id,
                             'admin_state_up': admin_state_up,
                             'tenant_id': tenant_id}}
        if router_ids is not None:
            data['firewall']['router_ids'] = router_ids
        firewall_req = self.new_create_request('firewalls', data, fmt)
        firewall_res = firewall_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, firewall_res.status_int)
        return firewall_res


class TestFirewallCallbacks(TestFirewallRouterInsertionBase):

    def test_set_firewall_status(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP
            ) as fw:
                fw_id = fw['firewall']['id']
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         nl_constants.ACTIVE)
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(nl_constants.ACTIVE, fw_db['status'])
                self.assertTrue(res)
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         nl_constants.ERROR)
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(nl_constants.ERROR, fw_db['status'])
                self.assertFalse(res)

    def test_set_firewall_status_pending_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP
            ) as fw:
                fw_id = fw['firewall']['id']
                fw_db = self.plugin._get_firewall(ctx, fw_id)
                fw_db['status'] = nl_constants.PENDING_DELETE
                ctx.session.flush()
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         nl_constants.ACTIVE)
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(nl_constants.PENDING_DELETE, fw_db['status'])
                self.assertFalse(res)

    def test_firewall_deleted(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False) as fw:
                fw_id = fw['firewall']['id']
                with ctx.session.begin(subtransactions=True):
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    fw_db['status'] = nl_constants.PENDING_DELETE
                    ctx.session.flush()
                    res = self.callbacks.firewall_deleted(ctx, fw_id)
                    self.assertTrue(res)
                    self.assertRaises(f_exc.FirewallNotFound,
                                      self.plugin.get_firewall,
                                      ctx, fw_id)

    def test_firewall_deleted_concurrently(self):
        ctx = context.get_admin_context()
        alt_ctx = context.get_admin_context()

        _get_firewall = self.plugin._get_firewall

        def getdelete(context, firewall_id):
            fw_db = _get_firewall(context, firewall_id)
            # NOTE(cby): Use a different session to simulate a concurrent del
            self.plugin.delete_db_firewall_object(alt_ctx, firewall_id)
            return fw_db

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                do_delete=False
            ) as fw:
                fw_id = fw['firewall']['id']
                with ctx.session.begin(subtransactions=True):
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    fw_db['status'] = nl_constants.PENDING_DELETE
                    ctx.session.flush()

                with mock.patch.object(
                    self.plugin, '_get_firewall', side_effect=getdelete
                ):
                    observed = self.callbacks.firewall_deleted(ctx, fw_id)
                    self.assertTrue(observed)

                self.assertRaises(f_exc.FirewallNotFound,
                                  self.plugin.get_firewall,
                                  ctx, fw_id)

    def test_firewall_deleted_not_found(self):
        ctx = context.get_admin_context()
        observed = self.callbacks.firewall_deleted(ctx, 'notfound')
        self.assertTrue(observed)

    def test_firewall_deleted_error(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
            ) as fw:
                fw_id = fw['firewall']['id']
                res = self.callbacks.firewall_deleted(ctx, fw_id)
                self.assertFalse(res)
                fw_db = self.plugin._get_firewall(ctx, fw_id)
                self.assertEqual(nl_constants.ERROR, fw_db['status'])

    def test_get_firewall_for_tenant(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with self.firewall_rule(name='fwr1', tenant_id=tenant_id) as fwr1, \
                self.firewall_rule(name='fwr2', tenant_id=tenant_id) as fwr2, \
                self.firewall_rule(name='fwr3', tenant_id=tenant_id) as fwr3:
            with self.firewall_policy(tenant_id=tenant_id) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fr = [fwr1, fwr2, fwr3]
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                res = req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                        firewall_policy_id=fwp_id,
                        tenant_id=tenant_id,
                        admin_state_up=test_db_firewall.ADMIN_STATE_UP) as fw:
                    fw_id = fw['firewall']['id']
                    res = self.callbacks.get_firewalls_for_tenant(ctx)
                    fw_rules = (
                        self.plugin._make_firewall_dict_with_rules(ctx,
                                                                   fw_id)
                    )
                    fw_rules['add-router-ids'] = []
                    fw_rules['del-router-ids'] = []
                    self.assertEqual(fw_rules, res[0])
                    self._compare_firewall_rule_lists(
                        fwp_id, fr, res[0]['firewall_rule_list'])


class TestFirewallAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallAgentApi, self).setUp()

        self.api = fwaas_plugin.FirewallAgentApi('topic', 'host')

    def test_init(self):
        self.assertEqual('topic', self.api.client.target.topic)
        self.assertEqual('host', self.api.host)

    def _call_test_helper(self, method_name, host):
        with mock.patch.object(self.api.client, 'cast') as rpc_mock, \
                mock.patch.object(self.api.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = self.api.client
            getattr(self.api, method_name)(mock.sentinel.context, 'test', host)

        prepare_args = {'server': host}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method_name,
                                         firewall='test', host='host')

    def test_create_firewall(self):
        self._call_test_helper('create_firewall', 'host')

    def test_update_firewall(self):
        self._call_test_helper('update_firewall', 'host')

    def test_delete_firewall(self):
        self._call_test_helper('delete_firewall', 'host')


class TestFirewallPluginBase(TestFirewallRouterInsertionBase,
                             test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        super(TestFirewallPluginBase, self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        fake_notifier.reset()

    def test_create_firewall_routers_not_specified(self):
        """neutron firewall-create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                with self.firewall() as fw1:
                    self.assertEqual(nl_constants.PENDING_CREATE,
                        fw1['firewall']['status'])

    def test_create_firewall_routers_specified(self):
        """neutron firewall-create test-policy --router-ids "r1 r2" """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id) as router2:
                router_ids = [router1['router']['id'], router2['router']['id']]
                with self.firewall(router_ids=router_ids) as fw1:
                    self.assertEqual(nl_constants.PENDING_CREATE,
                        fw1['firewall']['status'])

    def test_create_firewall_routers_present_empty_list_specified(self):
        """neutron firewall-create test-policy --router-ids "" """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                router_ids = []
                with self.firewall(router_ids=router_ids) as fw1:
                    self.assertEqual(nl_constants.INACTIVE,
                        fw1['firewall']['status'])

    def test_create_firewall_no_routers_empty_list_specified(self):
        """neutron firewall-create test-policy --router-ids "" """
        router_ids = []
        with self.firewall(router_ids=router_ids) as fw1:
            self.assertEqual(nl_constants.INACTIVE,
                fw1['firewall']['status'])

    def test_create_second_firewall_on_same_tenant(self):
        """fw1 created with default routers, fw2 no routers on same tenant."""
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                router_ids = []
                with self.firewall() as fw1:
                    with self.firewall(router_ids=router_ids) as fw2:
                        self.assertEqual(nl_constants.PENDING_CREATE,
                            fw1['firewall']['status'])
                        self.assertEqual(nl_constants.INACTIVE,
                            fw2['firewall']['status'])

    def test_create_firewall_admin_not_affected_by_other_tenant(self):
        # Create fw with admin after creating fw with other tenant
        with self.firewall(tenant_id='other-tenant') as fw1:
            with self.firewall() as fw2:
                self.assertEqual('other-tenant', fw1['firewall']['tenant_id'])
                self.assertEqual(self._tenant_id, fw2['firewall']['tenant_id'])

    def test_update_firewall_calls_get_dvr_hosts_for_router(self):
        ctx = context.get_admin_context()
        name = "user_fw"
        attrs = self._get_test_firewall_attrs(name)
        check_attr1 = getattr(self.l3_plugin,
                              "get_l3_agents_hosting_routers", False)
        check_attr2 = getattr(self.l3_plugin,
                              "_get_dvr_hosts_for_router", False)
        # For third-party L3-service plugins do not run this test
        if check_attr1 is False or check_attr2 is False:
            return
        with self.router(name='router1', admin_state_up=True,
                tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    self.callbacks.set_firewall_status(ctx, fw_id,
                                                       nl_constants.ACTIVE)
                    with mock.patch.object(
                            self.l3_plugin,
                            'get_l3_agents_hosting_routers') as s_hosts, \
                        mock.patch.object(
                            self.plugin,
                            '_check_dvr_extensions') as dvr_exts, \
                        mock.patch.object(
                            self.l3_plugin,
                            '_get_dvr_hosts_for_router') as u_hosts:
                        self.plugin.update_firewall(ctx, fw_id, firewall)
                        dvr_exts.return_value = True
                        self.assertTrue(u_hosts.called)
                        self.assertTrue(s_hosts.called)

    def test_update_firewall(self):
        ctx = context.get_admin_context()
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         nl_constants.ACTIVE)
                    data = {'firewall': {'name': name}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                    attrs = self._replace_firewall_status(attrs,
                                                          nl_constants.
                                                          PENDING_CREATE,
                                                          nl_constants.
                                                          PENDING_UPDATE)
                    for k, v in six.iteritems(attrs):
                        self.assertEqual(v, res['firewall'][k])

    def test_update_firewall_fails_when_firewall_pending(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    data = {'firewall': {'name': name}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_with_router_when_firewall_inactive(self):
        name = "firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    name=name,
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    data = {
                        'firewall': {'router_ids': [router1['router']['id']]}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                    attrs = self._replace_firewall_status(attrs,
                                                      nl_constants.
                                                      PENDING_CREATE,
                                                      nl_constants.
                                                      PENDING_UPDATE)
                    for k, v in six.iteritems(attrs):
                        self.assertEqual(v, res['firewall'][k])

    @testtools.skip('bug/1622694')
    def test_update_firewall_shared_fails_for_non_admin(self):
        ctx = context.get_admin_context()
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    tenant_id='noadmin',
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    self.callbacks.set_firewall_status(ctx, fw_id,
                                                   nl_constants.ACTIVE)
                    data = {'firewall': {'shared': True}}
                    req = self.new_update_request(
                        'firewalls', data, fw_id,
                        context=context.Context('', 'noadmin'))
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_update_firewall_policy_fails_when_firewall_pending(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP
                ):
                    data = {'firewall_policy': {'name': name}}
                    req = self.new_update_request('firewall_policies',
                                              data, fwp_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_rule_fails_when_firewall_pending(self):
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.firewall_rule(name='fwr1') as fr:
                with self.firewall_policy() as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    fr_id = fr['firewall_rule']['id']
                    fw_rule_ids = [fr_id]
                    data = {'firewall_policy':
                           {'firewall_rules': fw_rule_ids}}
                    req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                    req.get_response(self.ext_api)
                    with self.firewall(
                        firewall_policy_id=fwp_id,
                        admin_state_up=test_db_firewall.ADMIN_STATE_UP
                    ):
                        data = {'firewall_rule': {'protocol': 'udp'}}
                        req = self.new_update_request('firewall_rules',
                                                  data, fr_id)
                        res = req.get_response(self.ext_api)
                        self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_delete_firewall_with_no_routers(self):
        ctx = context.get_admin_context()
        # stop the AgentRPC patch for this one to test pending states
        self.agentapi_del_fw_p.stop()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                do_delete=False
            ) as fw:
                fw_id = fw['firewall']['id']
                req = self.new_delete_request('firewalls', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(exc.HTTPNoContent.code, res.status_int)
                self.assertRaises(f_exc.FirewallNotFound,
                                  self.plugin.get_firewall,
                                  ctx, fw_id)

    def test_delete_firewall_after_agent_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               do_delete=False) as fw:
                fw_id = fw['firewall']['id']
                req = self.new_delete_request('firewalls', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(exc.HTTPNoContent.code, res.status_int)
                self.assertRaises(f_exc.FirewallNotFound,
                                  self.plugin.get_firewall,
                                  ctx, fw_id)

    def test_make_firewall_dict_with_in_place_rules(self):
        ctx = context.get_admin_context()
        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            with self.firewall_policy() as fwp:
                fr = [fwr1, fwr2, fwr3]
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[]
                ) as fw:
                    fw_id = fw['firewall']['id']
                    fw_rules = (
                        self.plugin._make_firewall_dict_with_rules(ctx,
                                                                   fw_id)
                    )
                    self.assertEqual(fw_id, fw_rules['id'])
                    self._compare_firewall_rule_lists(
                        fwp_id, fr, fw_rules['firewall_rule_list'])

    def test_make_firewall_dict_with_in_place_rules_no_policy(self):
        ctx = context.get_admin_context()
        with self.firewall() as fw:
            fw_id = fw['firewall']['id']
            fw_rules = self.plugin._make_firewall_dict_with_rules(ctx, fw_id)
            self.assertEqual([], fw_rules['firewall_rule_list'])

    def test_list_firewalls(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(name='fw1', firewall_policy_id=fwp_id,
                               description='fw') as fwalls:
                self._test_list_resources('firewall', [fwalls],
                                          query_params='description=fw')

    def test_list_firewalls_with_filtering(self):
        with self.router(name='my_router', admin_state_up=True,
                         tenant_id=self._tenant_id) as router:
            router_id = router['router']['id']
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(name='fw1', firewall_policy_id=fwp_id,
                                   description='fw',
                                   router_ids=[router_id]) as fwalls:
                    filter_pattern = None
                    fw = fwalls['firewall']
                    for filter_pattern in fw:
                        query_params = 'fields=%s' % filter_pattern
                        expect = [{filter_pattern: fw[filter_pattern]}]
                        self._test_list_resources('firewall', expect,
                                                  query_params=query_params)

    def test_insert_rule(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id) as fw:
                    fw_id = fw['firewall']['id']
                    self.plugin.insert_rule(ctx, fwp_id, rule_info)
                    fw_rules = self.plugin._make_firewall_dict_with_rules(
                        ctx, fw_id)
                    self.assertEqual(1, len(fw_rules['firewall_rule_list']))
                    self.assertEqual(fr_id,
                                     fw_rules['firewall_rule_list'][0]['id'])

    def test_insert_rule_notif(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id):
                    self.plugin.insert_rule(ctx, fwp_id, rule_info)
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'firewall_policy.update.insert_rule'
            event_types = [event['event_type'] for event in notifications]
            self.assertIn(expected_event_type, event_types)

    def test_remove_rule(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy(firewall_rules=[fr_id]) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id) as fw:
                    fw_id = fw['firewall']['id']
                    self.plugin.remove_rule(ctx, fwp_id, rule_info)
                    fw_rules = self.plugin._make_firewall_dict_with_rules(
                        ctx, fw_id)
                    self.assertEqual([], fw_rules['firewall_rule_list'])

    def test_remove_rule_notif(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy(firewall_rules=[fr_id]) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id):
                    self.plugin.remove_rule(ctx, fwp_id, rule_info)
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'firewall_policy.update.remove_rule'
            event_types = [event['event_type'] for event in notifications]
            self.assertIn(expected_event_type, event_types)

    def test_firewall_quota_lower(self):
        """Test quota using overridden value."""
        cfg.CONF.set_override('quota_firewall', 3, group='QUOTAS')
        with self.firewall(name='quota1'), \
                self.firewall(name='quota2'), \
                self.firewall(name='quota3'):
            data = {'firewall': {'name': 'quota4',
                                 'firewall_policy_id': None,
                                 'tenant_id': self._tenant_id,
                                 'shared': False}}
            req = self.new_create_request('firewalls', data, 'json')
            res = req.get_response(self.ext_api)
            self.assertIn('Quota exceeded', res.body.decode('utf-8'))
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_firewall_quota_default(self):
        """Test quota using default value."""
        with self.firewall(name='quota1'), \
                self.firewall(name='quota2'), \
                self.firewall(name='quota3'), \
                self.firewall(name='quota4'), \
                self.firewall(name='quota5'), \
                self.firewall(name='quota6'), \
                self.firewall(name='quota7'), \
                self.firewall(name='quota8'), \
                self.firewall(name='quota9'), \
                self.firewall(name='quota10'):
            data = {'firewall': {'name': 'quota11',
                                 'firewall_policy_id': None,
                                 'tenant_id': self._tenant_id,
                                 'shared': False}}
            req = self.new_create_request('firewalls', data, 'json')
            res = req.get_response(self.ext_api)
            self.assertIn('Quota exceeded', res.body.decode('utf-8'))
            self.assertEqual(exc.HTTPConflict.code, res.status_int)


class TestFirewallRouterPluginBase(test_db_firewall.FirewallPluginDbTestCase,
                                   test_l3_plugin.L3NatTestCaseMixin,
                                   test_agent.AgentDBTestMixIn):

    def setUp(self, core_plugin=None, fw_plugin=None, ext_mgr=None):
        self.agentapi_del_fw_p = mock.patch(test_db_firewall.DELETEFW_PATH,
            create=True, new=test_db_firewall.FakeAgentApi().delete_firewall)
        self.agentapi_del_fw_p.start()

        self.client_mock = mock.MagicMock(name="mocked client")
        mock.patch('neutron.common.rpc.get_client'
                   ).start().return_value = self.client_mock

        # the L3 routing with L3 agent scheduling service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatAgentSchedulingServicePlugin')

        cfg.CONF.set_override('api_extensions_path', extensions_path)
        if not fw_plugin:
            fw_plugin = FW_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin,
                           'fw_plugin_name': fw_plugin}

        fdb.Firewall_db_mixin.\
            supported_extension_aliases = ["fwaas",
                                           "fwaasrouterinsertion"]
        fdb.Firewall_db_mixin.path_prefix = fwaas_def.API_PREFIX

        super(test_db_firewall.FirewallPluginDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            ext_mgr = FirewallTestExtensionManager()
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.plugin = directory.get_plugin('FIREWALL')

    def test_get_firewall_tenant_ids_on_host_with_associated_router(self):
        agent = helpers.register_l3_agent("host1")
        tenant_id = uuidutils.generate_uuid()
        ctxt = context.get_admin_context()

        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id) as router1:
            router_id = router1['router']['id']
            self.l3_plugin.add_router_to_l3_agent(ctxt, agent.id,
                                                  router_id)
            with self.firewall(tenant_id=tenant_id,
                               router_ids=[router_id]):
                tenant_ids = self.plugin.get_firewall_tenant_ids_on_host(
                    ctxt, 'host1')
                self.assertEqual([tenant_id], tenant_ids)

    def test_get_firewall_tenant_ids_on_host_without_associated_router(self):
        agent1 = helpers.register_l3_agent("host1")
        helpers.register_l3_agent("host2")
        tenant_id = uuidutils.generate_uuid()
        ctxt = context.get_admin_context()

        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id) as router1:
            router_id = router1['router']['id']
            self.l3_plugin.add_router_to_l3_agent(ctxt, agent1.id,
                                                  router_id)
            with self.firewall(tenant_id=tenant_id,
                               router_ids=[router_id]):
                tenant_ids = self.plugin.get_firewall_tenant_ids_on_host(
                    ctxt, 'host_2')
                self.assertEqual([], tenant_ids)

    def test_get_firewall_tenant_ids_on_host_with_routers(self):
        agent1 = helpers.register_l3_agent("host1")
        tenant_id1 = uuidutils.generate_uuid()
        tenant_id2 = uuidutils.generate_uuid()
        ctxt = context.get_admin_context()

        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id1) as router1:
            with self.router(name='router2', admin_state_up=True,
                             tenant_id=tenant_id2) as router2:
                router_id1 = router1['router']['id']
                router_id2 = router2['router']['id']
                self.l3_plugin.add_router_to_l3_agent(ctxt, agent1.id,
                                                      router_id1)
                self.l3_plugin.add_router_to_l3_agent(ctxt, agent1.id,
                                                      router_id2)
                with self.firewall(tenant_id=tenant_id1,
                                   router_ids=[router_id1]):
                    with self.firewall(tenant_id=tenant_id2,
                                       router_ids=[router_id2]):
                        tenant_ids = (self.plugin
                                      .get_firewall_tenant_ids_on_host(
                                          ctxt, 'host1'))
                        self.assertItemsEqual([tenant_id1, tenant_id2],
                                              tenant_ids)
