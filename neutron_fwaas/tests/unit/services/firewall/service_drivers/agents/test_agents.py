# Copyright 2016
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

from unittest import mock

from neutron.conf import common as common_conf
from neutron import extensions as neutron_extensions
from neutron.tests.unit.extensions import test_l3
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron_fwaas._i18n import _
from neutron_fwaas.db.firewall.v2.firewall_db_v2 import FirewallGroup
from neutron_fwaas.services.firewall.service_drivers.agents import agents
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.services.firewall import test_fwaas_plugin_v2


FIREWALL_AGENT_PLUGIN = ('neutron_fwaas.services.firewall.service_drivers.'
                         'agents.agents')
FIREWALL_AGENT_PLUGIN_KLASS = FIREWALL_AGENT_PLUGIN + '.FirewallAgentDriver'
DELETEFW_PATH = (FIREWALL_AGENT_PLUGIN + '.FirewallAgentApi.'
                 'delete_firewall_group')


class FakeAgentApi(agents.FirewallAgentCallbacks):
    """
    This class used to mock the AgentAPI delete method inherits from
    FirewallCallbacks because it needs access to the firewall_deleted method.
    The delete_firewall method belongs to the FirewallAgentApi, which has
    no access to the firewall_deleted method normally because it's not
    responsible for deleting the firewall from the DB. However, it needs
    to in the unit tests since there is no agent to call back.
    """
    def __init__(self):
        return

    def delete_firewall_group(self, context, firewall_group, **kwargs):
        self.plugin = directory.get_plugin('FIREWALL_V2')
        self.firewall_db = self.plugin.driver.firewall_db
        self.firewall_group_deleted(context, firewall_group['id'], **kwargs)


class TestFirewallAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallAgentApi, self).setUp()

        self.api = agents.FirewallAgentApi('topic', 'host')

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


class TestAgentDriver(test_fwaas_plugin_v2.FirewallPluginV2TestCase,
                      test_l3.L3NatTestCaseMixin):

    def setUp(self):
        self._mock_agentapi_del_fw_p = mock.patch(
            DELETEFW_PATH, create=True,
            new=FakeAgentApi().delete_firewall_group,
        )
        self.agentapi_del_fw_p = self._mock_agentapi_del_fw_p.start()
        self.addCleanup(self._mock_agentapi_del_fw_p.stop)
        self._mock_get_client = mock.patch.object(agents.n_rpc, 'get_client')
        self._mock_get_client.start()
        self.addCleanup(self._mock_get_client.stop)
        mock.patch.object(agents.n_rpc, 'Connection').start()

        l3_plugin_str = ('neutron.tests.unit.extensions.test_l3.'
                         'TestL3NatServicePlugin')
        l3_plugin = {'l3_plugin_name': l3_plugin_str}
        common_conf.register_core_common_config_opts(cfg=cfg.CONF)
        super(TestAgentDriver, self).setUp(
            service_provider=FIREWALL_AGENT_PLUGIN_KLASS,
            extra_service_plugins=l3_plugin,
            extra_extension_paths=neutron_extensions.__path__)

        self.db = self.plugin.driver.firewall_db
        self.callbacks = agents.FirewallAgentCallbacks(self.db)

        router_distributed_opts = [
            cfg.BoolOpt(
                'router_distributed',
                default=False,
                help=_("System-wide flag to determine the type of router "
                       "that tenants can create. Only admin can override.")),
        ]
        cfg.CONF.register_opts(router_distributed_opts)

    @property
    def _self_context(self):
        return context.Context('', self._tenant_id)

    def _get_test_firewall_group_attrs(self, name,
                                       status=nl_constants.INACTIVE):
        return super(TestAgentDriver, self)._get_test_firewall_group_attrs(
            name, status=status)

    def test_set_firewall_group_status(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(as_admin=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                ingress_firewall_policy_id=fwp_id,
                admin_state_up=self.ADMIN_STATE_UP
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
        with self.firewall_policy(as_admin=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                ingress_firewall_policy_id=fwp_id,
                admin_state_up=self.ADMIN_STATE_UP,
                do_delete=False
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                with ctx.session.begin(subtransactions=True):
                    fwg_db = self.db._get_firewall_group(ctx, fwg_id)
                    fwg_db['status'] = nl_constants.PENDING_DELETE

                observed = self.callbacks.firewall_group_deleted(ctx, fwg_id)
                self.assertTrue(observed)

            self.assertRaises(f_exc.FirewallGroupNotFound,
                              self.plugin.get_firewall_group,
                              ctx, fwg_id)

    def test_firewall_group_deleted_concurrently(self):
        ctx = context.get_admin_context()
        alt_ctx = context.get_admin_context()

        _get_firewall_group = self.db._get_firewall_group

        def getdelete(context, fwg_id):
            fwg_db = _get_firewall_group(context, fwg_id)
            # NOTE(cby): Use a different session to simulate a concurrent del
            with alt_ctx.session.begin(subtransactions=True):
                alt_ctx.session.query(FirewallGroup).filter_by(
                    id=fwg_id).delete()
            return fwg_db

        with self.firewall_policy(as_admin=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                firewall_policy_id=fwp_id,
                admin_state_up=self.ADMIN_STATE_UP,
                do_delete=False,
                as_admin=True,
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                with ctx.session.begin(subtransactions=True):
                    fwg_db = self.db._get_firewall_group(ctx, fwg_id)
                    fwg_db['status'] = nl_constants.PENDING_DELETE
                    ctx.session.flush()

                with mock.patch.object(
                    self.db, '_get_firewall_group', side_effect=getdelete
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
        with self.firewall_policy(as_admin=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                firewall_policy_id=fwp_id,
                admin_state_up=self.ADMIN_STATE_UP,
                as_admin=True,
            ) as fwg:
                fwg_id = fwg['firewall_group']['id']
                observed = self.callbacks.firewall_group_deleted(
                    ctx, fwg_id)
                self.assertFalse(observed)
                fwg_db = self.db._get_firewall_group(ctx, fwg_id)
                self.assertEqual(nl_constants.ERROR, fwg_db['status'])

    def test_create_firewall_group_ports_not_specified(self):
        """neutron firewall-create test-policy """
        with self.firewall_policy(as_admin=True) as fwp:
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
            with self.firewall_policy(as_admin=True) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall_group(
                    name='test',
                    ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id, ports=fwg_ports,
                    admin_state_up=True) as fwg1:
                    self.assertEqual(nl_constants.PENDING_CREATE,
                         fwg1['firewall_group']['status'])

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
                with self.firewall_policy(as_admin=True) as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    with self.firewall_group(
                        name='test',
                        ingress_firewall_policy_id=fwp_id,
                        egress_firewall_policy_id=fwp_id,
                        ports=fwg_ports,
                        admin_state_up=True) as fwg1:
                        self.assertEqual(nl_constants.PENDING_CREATE,
                            fwg1['firewall_group']['status'])

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

    def test_update_firewall_group_with_new_ports_no_policy(self):
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

            with self.firewall_policy(as_admin=True) as fwp:
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

            with self.firewall_policy(as_admin=True) as fwp:
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
            with self.firewall_rule(as_admin=True) as fwr:
                with self.firewall_policy(
                        firewall_rules=[fwr['firewall_rule']['id']],
                        as_admin=True) as fwp:
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
                        for k, v in attrs.items():
                            self.assertEqual(v, res['firewall_rule'][k])

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
            with self.firewall_rule(as_admin=True) as fwr:
                with self.firewall_policy(
                    firewall_rules=[fwr['firewall_rule']['id']],
                    as_admin=True) as fwp:
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

    def test_update_firewall_group_with_ports_and_policy(self):
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
            with self.firewall_rule(as_admin=True) as fwr:
                with self.firewall_policy(
                        firewall_rules=[fwr['firewall_rule']['id']],
                        as_admin=True) as fwp:
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

    def test_create_firewall_group_with_dvr(self):
        cfg.CONF.set_override('router_distributed', True)
        attrs = self._get_test_firewall_group_attrs("firewall1")
        self._test_create_firewall_group(attrs)

    def test_create_firewall_group(self):
        attrs = self._get_test_firewall_group_attrs("firewall1")
        self._test_create_firewall_group(attrs)

    def test_create_firewall_group_with_empty_ports(self):
        attrs = self._get_test_firewall_group_attrs("fwg1")
        attrs['ports'] = []
        self._test_create_firewall_group(attrs)
