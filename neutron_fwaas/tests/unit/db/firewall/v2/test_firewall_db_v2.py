# Copyright (c) 2016 OpenStack Foundation
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

import contextlib

import mock
from neutron.api import extensions as api_ext
from neutron.common import config
from neutron_lib.api.definitions import firewall_v2
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils
import six
import testtools
import webob.exc

from neutron_fwaas.common import fwaas_constants as constants
from neutron_fwaas.db.firewall.v2 import firewall_db_v2 as fdb
from neutron_fwaas import extensions
from neutron_fwaas.services.firewall import fwaas_plugin_v2
from neutron_fwaas.tests import base


DB_FW_PLUGIN_KLASS = (
    "neutron_fwaas.db.firewall.v2.firewall_db_v2.Firewall_db_mixin_v2"
)
FWAAS_PLUGIN = 'neutron_fwaas.services.firewall.fwaas_plugin_v2'
DELETEFW_PATH = FWAAS_PLUGIN + '.FirewallAgentApi.delete_firewall_group'
extensions_path = ':'.join(extensions.__path__)
DESCRIPTION = 'default description'
PROTOCOL = 'tcp'
IP_VERSION = 4
SOURCE_IP_ADDRESS_RAW = '1.1.1.1'
DESTINATION_IP_ADDRESS_RAW = '2.2.2.2'
SOURCE_PORT = '55000:56000'
DESTINATION_PORT = '56000:57000'
ACTION = 'allow'
AUDITED = True
ENABLED = True
ADMIN_STATE_UP = True
SHARED = True


class FakeAgentApi(fwaas_plugin_v2.FirewallCallbacks):
    """
    This class used to mock the AgentAPI delete method inherits from
    FirewallCallbacks because it needs access to the firewall_deleted method.
    The delete_firewall method belongs to the FirewallAgentApi, which has
    no access to the firewall_deleted method normally because it's not
    responsible for deleting the firewall from the DB. However, it needs
    to in the unit tests since there is no agent to call back.
    """
    def __init__(self):
        pass

    def delete_firewall_group(self, context, firewall_group, **kwargs):
        self.plugin = directory.get_plugin('FIREWALL_V2')
        self.firewall_group_deleted(context, firewall_group['id'], **kwargs)


class FirewallPluginV2DbTestCase(base.NeutronDbPluginV2TestCase):
    resource_prefix_map = dict(
        (k, firewall_v2.API_PREFIX)
        for k in firewall_v2.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, core_plugin=None, fw_plugin=None, ext_mgr=None):
        self.agentapi_delf_p = mock.patch(
            DELETEFW_PATH, create=True,
            new=FakeAgentApi().delete_firewall_group)
        self.agentapi_delf_p.start()
        if not fw_plugin:
            fw_plugin = DB_FW_PLUGIN_KLASS
        service_plugins = {'fw_plugin_name': fw_plugin}

        fdb.Firewall_db_mixin_v2.supported_extension_aliases = ["fwaas_v2"]
        fdb.Firewall_db_mixin_v2.path_prefix = firewall_v2.API_PREFIX
        super(FirewallPluginV2DbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            self.plugin = importutils.import_object(fw_plugin)
            ext_mgr = api_ext.PluginAwareExtensionManager(
                extensions_path,
                {'FIREWALL': self.plugin}
            )
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        router_distributed_opts = [
            cfg.BoolOpt(
                'router_distributed',
                default=False,
                help=("System-wide flag to determine the type of router "
                      "that tenants can create. Only admin can override.")),
        ]
        cfg.CONF.register_opts(router_distributed_opts)

    def _get_admin_context(self):
        # FIXME NOTE(ivasilevskaya) seems that test framework treats context
        # with user_id=None/tenant_id=None (return value of
        # context._get_admin_context() method) in a somewhat special way.
        # So as a workaround to have the framework behave properly right now
        # let's implement our own _get_admin_context method and look into the
        # matter some other time.
        return context.Context(user_id='admin',
                               tenant_id='admin-tenant',
                               is_admin=True)

    def _get_nonadmin_context(self, user_id=None, tenant_id=None):
        return context.Context(user_id=user_id or 'non-admin',
                               tenant_id=tenant_id or 'tenant1')

    def _test_list_resources(self, resource, items,
                             neutron_context=None,
                             query_params=None):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        res = self._list(resource_plural,
                         neutron_context=neutron_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(
            sorted([i[resource]['id'] for i in items]),
            sorted([i['id'] for i in res[resource_plural]]))

    def _list_req(self, resource_plural, ctx=None):
        if not ctx:
            ctx = self._get_admin_context()
        req = self.new_list_request(resource_plural)
        req.environ['neutron.context'] = ctx
        return self.deserialize(
            self.fmt, req.get_response(self.ext_api))[resource_plural]

    def _show_req(self, resource_plural, obj_id, ctx=None):
        req = self.new_show_request(resource_plural, obj_id, fmt=self.fmt)
        if not ctx:
            ctx = self._get_admin_context()
        req.environ['neutron.context'] = ctx
        res = self.deserialize(
            self.fmt, req.get_response(self.ext_api))
        return res

    def _build_default_fwg(self, ctx=None, is_one=True):
        res = self._list_req('firewall_groups', ctx=ctx)
        if is_one:
            self.assertEqual(1, len(res))
            return res[0]
        return res

    def _get_test_firewall_rule_attrs(self, name='firewall_rule1'):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'project_id': self._tenant_id,
                 'protocol': PROTOCOL,
                 'ip_version': IP_VERSION,
                 'source_ip_address': SOURCE_IP_ADDRESS_RAW,
                 'destination_ip_address': DESTINATION_IP_ADDRESS_RAW,
                 'source_port': SOURCE_PORT,
                 'destination_port': DESTINATION_PORT,
                 'action': ACTION,
                 'enabled': ENABLED,
                 'shared': SHARED}
        return attrs

    def _get_test_firewall_policy_attrs(self, name='firewall_policy1',
                                        audited=AUDITED):
        attrs = {'name': name,
                 'description': DESCRIPTION,
                 'tenant_id': self._tenant_id,
                 'project_id': self._tenant_id,
                 'firewall_rules': [],
                 'audited': audited,
                 'shared': SHARED}
        return attrs

    def _get_test_firewall_group_attrs(self, name='firewall_1',
                                 status='PENDING_CREATE'):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'project_id': self._tenant_id,
                 'admin_state_up': ADMIN_STATE_UP,
                 'status': status}

        return attrs

    def _create_firewall_policy(self, fmt, name, description, shared,
                                firewall_rules, audited,
                                expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'firewall_policy': {'name': name,
                                    'description': description,
                                    'tenant_id': tenant_id,
                                    'project_id': tenant_id,
                                    'firewall_rules': firewall_rules,
                                    'audited': audited,
                                    'shared': shared}}

        fw_policy_req = self.new_create_request('firewall_policies', data, fmt)
        fw_policy_res = fw_policy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, fw_policy_res.status_int)

        return fw_policy_res

    def _replace_firewall_status(self, attrs, old_status, new_status):
        if attrs['status'] is old_status:
            attrs['status'] = new_status
        return attrs

    @contextlib.contextmanager
    def firewall_policy(self, fmt=None, name='firewall_policy1',
                        description=DESCRIPTION, shared=SHARED,
                        firewall_rules=None, audited=True,
                        do_delete=True, **kwargs):
        if firewall_rules is None:
            firewall_rules = []
        if not fmt:
            fmt = self.fmt
        res = self._create_firewall_policy(fmt, name, description, shared,
                                           firewall_rules, audited, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        firewall_policy = self.deserialize(fmt or self.fmt, res)
        yield firewall_policy
        if do_delete:
            self._delete('firewall_policies',
                         firewall_policy['firewall_policy']['id'])

    def _create_firewall_rule(self, fmt, name, shared, protocol,
                              ip_version, source_ip_address,
                              destination_ip_address, source_port,
                              destination_port, action, enabled,
                              expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'firewall_rule': {'name': name,
                                  'tenant_id': tenant_id,
                                  'project_id': tenant_id,
                                  'protocol': protocol,
                                  'ip_version': ip_version,
                                  'source_ip_address': source_ip_address,
                                  'destination_ip_address':
                                  destination_ip_address,
                                  'source_port': source_port,
                                  'destination_port': destination_port,
                                  'action': action,
                                  'enabled': enabled,
                                  'shared': shared}}

        fw_rule_req = self.new_create_request('firewall_rules', data, fmt)
        fw_rule_res = fw_rule_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, fw_rule_res.status_int)

        return fw_rule_res

    @contextlib.contextmanager
    def firewall_rule(self, fmt=None, name='firewall_rule1',
                      shared=SHARED, protocol=PROTOCOL, ip_version=IP_VERSION,
                      source_ip_address=SOURCE_IP_ADDRESS_RAW,
                      destination_ip_address=DESTINATION_IP_ADDRESS_RAW,
                      source_port=SOURCE_PORT,
                      destination_port=DESTINATION_PORT,
                      action=ACTION, enabled=ENABLED,
                      do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_firewall_rule(fmt, name, shared, protocol,
                                         ip_version, source_ip_address,
                                         destination_ip_address,
                                         source_port, destination_port,
                                         action, enabled, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        firewall_rule = self.deserialize(fmt or self.fmt, res)
        yield firewall_rule
        if do_delete:
            self._delete('firewall_rules',
                         firewall_rule['firewall_rule']['id'])

    def _create_firewall_group(self, fmt, name, description,
                               ingress_firewall_policy_id,
                               egress_firewall_policy_id,
                               ports=None, admin_state_up=True,
                               expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        if ingress_firewall_policy_id is None:
            default_policy = kwargs.get('default_policy', True)
            if default_policy:
                res = self._create_firewall_policy(fmt, 'fwp',
                                                   description=DESCRIPTION,
                                                   shared=SHARED,
                                                   firewall_rules=[],
                                                   audited=AUDITED)
                firewall_policy = self.deserialize(fmt or self.fmt, res)
                fwp_id = firewall_policy["firewall_policy"]["id"]
                ingress_firewall_policy_id = fwp_id
        data = {'firewall_group': {'name': name,
                     'description': description,
                     'ingress_firewall_policy_id': ingress_firewall_policy_id,
                     'egress_firewall_policy_id': egress_firewall_policy_id,
                     'admin_state_up': admin_state_up}}
        ctx = kwargs.get('context', None)
        if ctx is None or ctx.is_admin:
            data['firewall_group'].update({'tenant_id': tenant_id})
            data['firewall_group'].update({'project_id': tenant_id})
        if ports is not None:
            data['firewall_group'].update({'ports': ports})

        firewall_req = self.new_create_request('firewall_groups', data, fmt,
                                               context=ctx)
        firewall_res = firewall_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, firewall_res.status_int)

        return firewall_res

    @contextlib.contextmanager
    def firewall_group(self, fmt=None, name='firewall_1',
                       description=DESCRIPTION,
                       ingress_firewall_policy_id=None,
                       egress_firewall_policy_id=None,
                       ports=None, admin_state_up=True,
                       do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_firewall_group(fmt, name, description,
                                          ingress_firewall_policy_id,
                                          egress_firewall_policy_id,
                                          ports=ports,
                                          admin_state_up=admin_state_up,
                                          **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        firewall_group = self.deserialize(fmt or self.fmt, res)
        yield firewall_group
        if do_delete:
            self._delete('firewall_groups',
                         firewall_group['firewall_group']['id'])

    def _rule_action(self, action, id, firewall_rule_id, insert_before=None,
                     insert_after=None, expected_code=webob.exc.HTTPOk.code,
                     expected_body=None, body_data=None):
        # We intentionally do this check for None since we want to distinguish
        # from empty dictionary
        if body_data is None:
            if action == 'insert':
                body_data = {'firewall_rule_id': firewall_rule_id,
                             'insert_before': insert_before,
                             'insert_after': insert_after}
            else:
                body_data = {'firewall_rule_id': firewall_rule_id}

        req = self.new_action_request('firewall_policies',
                                      body_data, id,
                                      "%s_rule" % action)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(expected_body, response)
        return response

    def _compare_firewall_rule_lists(self, firewall_policy_id,
                                     observed_list, expected_list):
        position = 0
        for r1, r2 in zip(observed_list, expected_list):
            rule = r1['firewall_rule']
            rule['firewall_policy_id'] = firewall_policy_id
            position += 1
            rule['position'] = position
            for k in rule:
                self.assertEqual(r2[k], rule[k])


class TestFirewallDBPluginV2(FirewallPluginV2DbTestCase):

    def test_get_policy_ordered_rules(self):
        with self.firewall_rule(name='alone'), \
                self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr3') as fwr3, \
                self.firewall_rule(name='fwr2') as fwr2:
            fwrs = fwr1, fwr2, fwr3
            expected_ids = [fwr['firewall_rule']['id'] for fwr in fwrs]
            with self.firewall_policy(firewall_rules=expected_ids) as fwp:
                ctx = self._get_admin_context()
                fwp_id = fwp['firewall_policy']['id']
                observeds = self.plugin._get_policy_ordered_rules(ctx, fwp_id)
                observed_ids = [r['id'] for r in observeds]
                self.assertEqual(expected_ids, observed_ids)

    def test_create_firewall_policy(self):
        name = "firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(name=name, shared=SHARED,
                                  firewall_rules=None, audited=AUDITED
                                  ) as firewall_policy:
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, firewall_policy['firewall_policy'][k])

    def test_create_firewall_policy_with_rules(self):
        name = "firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            fr = [fwr1, fwr2, fwr3]
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            attrs['firewall_rules'] = fw_rule_ids
            with self.firewall_policy(name=name, shared=SHARED,
                                      firewall_rules=fw_rule_ids,
                                      audited=AUDITED) as fwp:
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, fwp['firewall_policy'][k])

    def test_create_admin_firewall_policy_with_other_tenant_rules(self):
        with self.firewall_rule(shared=False) as fr:
            fw_rule_ids = [fr['firewall_rule']['id']]
            res = self._create_firewall_policy(None, 'firewall_policy1',
                                               description=DESCRIPTION,
                                               shared=SHARED,
                                               firewall_rules=fw_rule_ids,
                                               audited=AUDITED,
                                               tenant_id='admin-tenant')
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_firewall_policy_with_previously_associated_rule(self):
        with self.firewall_rule() as fwr:
            fw_rule_ids = [fwr['firewall_rule']['id']]
            with self.firewall_policy(firewall_rules=fw_rule_ids):
                with self.firewall_policy(shared=SHARED,
                                          firewall_rules=fw_rule_ids) as fwp2:
                    self.assertEqual(
                        fwr['firewall_rule']['id'],
                        fwp2['firewall_policy']['firewall_rules'][0])

    def test_create_shared_firewall_policy_with_nonshared_rule(self):
        with self.firewall_rule(shared=False) as fwr:
            fw_rule_ids = [fwr['firewall_rule']['id']]
            res = self._create_firewall_policy(None, 'firewall_policy1',
                                               description=DESCRIPTION,
                                               shared=SHARED,
                                               firewall_rules=fw_rule_ids,
                                               audited=AUDITED)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_show_firewall_policy(self):
        name = "firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(name=name, shared=SHARED,
                                  firewall_rules=None, audited=AUDITED) as fwp:
            res = self._show_req('firewall_policies',
                                 fwp['firewall_policy']['id'])
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_policy'][k])

    def test_list_firewall_policies(self):
        with self.firewall_policy(name='fwp1', description='fwp') as fwp1, \
                self.firewall_policy(name='fwp2', description='fwp') as fwp2, \
                self.firewall_policy(name='fwp3', description='fwp') as fwp3:
            fw_policies = [fwp1, fwp2, fwp3]
            self._test_list_resources('firewall_policy',
                                      fw_policies,
                                      query_params='description=fwp')

    def test_update_firewall_policy(self):
        name = "new_firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name, audited=False)

        with self.firewall_policy(shared=SHARED, firewall_rules=None,
                                  audited=AUDITED) as fwp:
            data = {'firewall_policy': {'name': name}}
            req = self.new_update_request('firewall_policies', data,
                                          fwp['firewall_policy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_policy'][k])

    def _test_update_firewall_policy(self, with_audited):
        with self.firewall_policy(name='firewall_policy1', description='fwp',
                                  audited=AUDITED) as fwp:
            attrs = self._get_test_firewall_policy_attrs(audited=with_audited)
            data = {'firewall_policy':
                    {'description': 'fw_p1'}}
            if with_audited:
                data['firewall_policy']['audited'] = 'True'

            req = self.new_update_request('firewall_policies', data,
                                          fwp['firewall_policy']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            attrs['description'] = 'fw_p1'
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_policy'][k])

    def test_update_firewall_policy_set_audited_false(self):
        self._test_update_firewall_policy(with_audited=False)

    def test_update_firewall_policy_with_audited_set_true(self):
        self._test_update_firewall_policy(with_audited=True)

    def test_update_firewall_policy_with_rules(self):
        attrs = self._get_test_firewall_policy_attrs()

        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            with self.firewall_policy() as fwp:
                fr = [fwr1, fwr2, fwr3]
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                attrs['firewall_rules'] = fw_rule_ids
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['audited'] = False
                attrs['firewall_rules'] = sorted(attrs['firewall_rules'])
                # TODO(sridar): set it so that the ordering is maintained
                res['firewall_policy']['firewall_rules'] = sorted(
                    res['firewall_policy']['firewall_rules'])
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_policy'][k])

    def test_update_firewall_policy_replace_rules(self):
        attrs = self._get_test_firewall_policy_attrs()

        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3, \
                self.firewall_rule(name='fwr4') as fwr4:
            frs = [fwr1, fwr2, fwr3, fwr4]
            fr1 = frs[0:2]
            fr2 = frs[2:4]
            with self.firewall_policy() as fwp:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)

                fw_rule_ids = [r['firewall_rule']['id'] for r in fr2]
                attrs['firewall_rules'] = fw_rule_ids
                new_data = {'firewall_policy':
                            {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', new_data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['audited'] = False
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_policy'][k])

    @testtools.skip('bug/1614673')
    def test_update_firewall_policy_reorder_rules(self):
        attrs = self._get_test_firewall_policy_attrs()

        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3, \
                self.firewall_rule(name='fwr4') as fwr4:
            fr = [fwr1, fwr2, fwr3, fwr4]
            with self.firewall_policy() as fwp:
                fw_rule_ids = [fr[2]['firewall_rule']['id'],
                               fr[3]['firewall_rule']['id']]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                # shuffle the rules, add more rules
                fw_rule_ids = [fr[1]['firewall_rule']['id'],
                               fr[3]['firewall_rule']['id'],
                               fr[2]['firewall_rule']['id'],
                               fr[0]['firewall_rule']['id']]
                attrs['firewall_rules'] = fw_rule_ids
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                rules = []
                for rule_id in fw_rule_ids:
                    res = self._show_req('firewall_rules', rule_id)
                    rules.append(res['firewall_rule'])
                self.assertEqual(1, rules[0]['position'])
                self.assertEqual(fr[1]['firewall_rule']['id'], rules[0]['id'])
                self.assertEqual(2, rules[1]['position'])
                self.assertEqual(fr[3]['firewall_rule']['id'], rules[1]['id'])
                self.assertEqual(3, rules[2]['position'])
                self.assertEqual(fr[2]['firewall_rule']['id'], rules[2]['id'])
                self.assertEqual(4, rules[3]['position'])
                self.assertEqual(fr[0]['firewall_rule']['id'], rules[3]['id'])

    def test_update_firewall_policy_with_non_existing_rule(self):
        attrs = self._get_test_firewall_policy_attrs()

        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2:
            fr = [fwr1, fwr2]
            with self.firewall_policy() as fwp:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                # appending non-existent rule
                fw_rule_ids.append(uuidutils.generate_uuid())
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                # check that the firewall_rule was not found
                self.assertEqual(404, res.status_int)
                # check if none of the rules got added to the policy
                res = self._show_req('firewall_policies',
                                     fwp['firewall_policy']['id'])
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_policy'][k])

    def test_update_shared_firewall_policy_with_nonshared_rule(self):
        with self.firewall_rule(name='fwr1', shared=False) as fr:
            with self.firewall_policy() as fwp:
                fw_rule_ids = [fr['firewall_rule']['id']]
                # update shared policy with nonshared rule
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_update_firewall_policy_with_shared_attr_nonshared_rule(self):
        with self.firewall_rule(name='fwr1', shared=False) as fr:
            with self.firewall_policy(shared=False) as fwp:
                fw_rule_ids = [fr['firewall_rule']['id']]
                # update shared policy with shared attr and nonshared rule
                data = {'firewall_policy': {'shared': SHARED,
                                            'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_update_firewall_policy_with_shared_attr_exist_unshare_rule(self):
        with self.firewall_rule(name='fwr1', shared=False) as fr:
            fw_rule_ids = [fr['firewall_rule']['id']]
            with self.firewall_policy(shared=False,
                                      firewall_rules=fw_rule_ids) as fwp:
                # update policy with shared attr
                data = {'firewall_policy': {'shared': SHARED}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_policy_assoc_with_other_tenant_firewall(self):
        with self.firewall_policy(shared=SHARED, tenant_id='tenant1') as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id):
                data = {'firewall_policy': {'shared': False}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_policy_from_shared_to_unshared(self):
        with self.firewall_policy(shared=True) as fwp:
            # update policy with public attr
            data = {'firewall_policy': {'shared': False}}
            req = self.new_update_request('firewall_policies', data,
                                          fwp['firewall_policy']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

    def test_update_from_shared_to_unshared_associated_as_ingress_fwp(self):
        with self.firewall_policy(shared=True, tenant_id='here') as fwp:
            # update policy with public attr
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(tenant_id='another',
                                     ingress_firewall_policy_id=fwp_id):
                data = {'firewall_policy': {'shared': False}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_from_shared_to_unshared_associated_as_egress_fwp(self):
        with self.firewall_policy(shared=True, tenant_id='here') as fwp:
            # update policy with public attr
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(tenant_id='another',
                                     egress_firewall_policy_id=fwp_id):
                data = {'firewall_policy': {'shared': False}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_from_shared_to_unshared_associated_as_ingress_egress(self):
        with self.firewall_policy(shared=True, tenant_id='here') as fwp:
            # update policy with public attr
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(tenant_id='another',
                                     egress_firewall_policy_id=fwp_id,
                                     ingress_firewall_policy_id=fwp_id):
                data = {'firewall_policy': {'shared': False}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_default_fwg_policy(self):
        """
        Make sure that neither admin nor non-admin can update policy
        associated with default firewall group
        """
        ctx_admin = self._get_admin_context()
        ctx_nonadmin = self._get_nonadmin_context()
        for ctx in [ctx_admin, ctx_nonadmin]:
            self._build_default_fwg(ctx=ctx)
            policies = self._list_req('firewall_policies')
            for p in policies:
                data = {'firewall_policy':
                        {'firewall_rules': []}}
                req = self.new_update_request('firewall_policies',
                                              data, p['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    def test_delete_firewall_policy(self):
        ctx = self._get_admin_context()
        with self.firewall_policy(do_delete=False) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            req = self.new_delete_request('firewall_policies', fwp_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(204, res.status_int)
            self.assertRaises(f_exc.FirewallPolicyNotFound,
                              self.plugin.get_firewall_policy,
                              ctx, fwp_id)

    @testtools.skip('bug/1614673')
    def test_delete_firewall_policy_with_rule(self):
        ctx = self._get_admin_context()
        attrs = self._get_test_firewall_policy_attrs()
        with self.firewall_policy(do_delete=False) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_rule(name='fwr1') as fr:
                fr_id = fr['firewall_rule']['id']
                fw_rule_ids = [fr_id]
                attrs['firewall_rules'] = fw_rule_ids
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                fw_rule = self.plugin.get_firewall_rule(ctx, fr_id)
                self.assertEqual(fwp_id, fw_rule['ingress_firewall_policy_id'])
                req = self.new_delete_request('firewall_policies', fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(204, res.status_int)
                self.assertRaises(f_exc.FirewallPolicyNotFound,
                                  self.plugin.get_firewall_policy,
                                  ctx, fwp_id)
                fw_rule = self.plugin.get_firewall_rule(ctx, fr_id)
                self.assertIsNone(fw_rule['ingress_firewall_policy_id'])

    def test_delete_firewall_policy_with_firewall_group_association(self):
        attrs = self._get_test_firewall_group_attrs()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall_group(
                    ingress_firewall_policy_id=fwp_id,
                    admin_state_up=ADMIN_STATE_UP):
                req = self.new_delete_request('firewall_policies', fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    def test_create_firewall_rule(self):
        attrs = self._get_test_firewall_rule_attrs()

        with self.firewall_rule() as firewall_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, firewall_rule['firewall_rule'][k])

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.firewall_rule(source_port=None,
                                destination_port=None) as firewall_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, firewall_rule['firewall_rule'][k])

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule(source_port=10000,
                                destination_port=80) as firewall_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, firewall_rule['firewall_rule'][k])

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule(source_port='10000',
                                destination_port='80') as firewall_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, firewall_rule['firewall_rule'][k])

    def test_create_firewall_src_port_illegal_range(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['source_port'] = '65535:1024'
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_firewall_dest_port_illegal_range(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['destination_port'] = '65535:1024'
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_firewall_rule_icmp_with_port(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['protocol'] = 'icmp'
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_firewall_rule_icmp_without_port(self):
        attrs = self._get_test_firewall_rule_attrs()

        attrs['protocol'] = 'icmp'
        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.firewall_rule(source_port=None,
                                destination_port=None,
                                protocol='icmp') as firewall_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, firewall_rule['firewall_rule'][k])

    def test_create_firewall_without_source(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['source_ip_address'] = None
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(201, res.status_int)

    def test_create_firewall_rule_without_destination(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['destination_ip_address'] = None
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(201, res.status_int)

    def test_create_firewall_rule_without_protocol_with_dport(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['protocol'] = None
        attrs['source_port'] = None
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_firewall_rule_without_protocol_with_sport(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['protocol'] = None
        attrs['destination_port'] = None
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_show_firewall_rule_with_fw_policy_not_associated(self):
        attrs = self._get_test_firewall_rule_attrs()
        with self.firewall_rule() as fw_rule:
            res = self._show_req('firewall_rules',
                                 fw_rule['firewall_rule']['id'])
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_rule'][k])

    @testtools.skip('bug/1614673')
    def test_show_firewall_rule_with_fw_policy_associated(self):
        attrs = self._get_test_firewall_rule_attrs()
        with self.firewall_rule() as fw_rule:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['ingress_firewall_policy_id'] = fwp_id
                data = {'firewall_policy':
                        {'firewall_rules':
                         [fw_rule['firewall_rule']['id']]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                res = self._show_req('firewall_rules',
                                     fw_rule['firewall_rule']['id'])
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_rule'][k])

    def test_create_firewall_rule_with_ipv6_addrs_and_wrong_ip_version(self):
        attrs = self._get_test_firewall_rule_attrs()
        attrs['source_ip_address'] = '::/0'
        attrs['destination_ip_address'] = '2001:db8:3::/64'
        attrs['ip_version'] = 4
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

        attrs = self._get_test_firewall_rule_attrs()
        attrs['source_ip_address'] = None
        attrs['destination_ip_address'] = '2001:db8:3::/64'
        attrs['ip_version'] = 4
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

        attrs = self._get_test_firewall_rule_attrs()
        attrs['source_ip_address'] = '::/0'
        attrs['destination_ip_address'] = None
        attrs['ip_version'] = 4
        res = self._create_firewall_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_list_firewall_rules(self):
        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            fr = [fwr1, fwr2, fwr3]
            query_params = 'protocol=tcp'
            self._test_list_resources('firewall_rule', fr,
                                      query_params=query_params)

    def test_update_firewall_rule(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)

        attrs['source_port'] = '10:20'
        attrs['destination_port'] = '30:40'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'protocol': PROTOCOL,
                                      'source_port': '10:20',
                                      'destination_port': '30:40'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_rule'][k])

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'protocol': PROTOCOL,
                                      'source_port': 10000,
                                      'destination_port': 80}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_rule'][k])

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'protocol': PROTOCOL,
                                      'source_port': '10000',
                                      'destination_port': '80'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_rule'][k])

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': None,
                                      'destination_port': None}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(v, res['firewall_rule'][k])

    def test_update_firewall_rule_with_port_and_no_proto(self):
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'protocol': None,
                                      'destination_port': 80}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_firewall_rule_without_ports_and_no_proto(self):
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'protocol': None,
                                      'destination_port': None,
                                      'source_port': None}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_firewall_rule_with_port(self):
        with self.firewall_rule(source_port=None,
                                destination_port=None,
                                protocol=None) as fwr:
            data = {'firewall_rule': {'destination_port': 80}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_firewall_rule_with_port_illegal_range(self):
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'destination_port': '65535:1024'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_firewall_rule_with_port_and_protocol(self):
        with self.firewall_rule(source_port=None,
                                destination_port=None,
                                protocol=None) as fwr:
            data = {'firewall_rule': {'destination_port': 80,
                                      'protocol': 'tcp'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_firewall_rule_icmp_with_port(self):
        with self.firewall_rule(source_port=None,
                                destination_port=None,
                                protocol=None) as fwr:
            data = {'firewall_rule': {'destination_port': 80,
                                      'protocol': 'icmp'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

        with self.firewall_rule(source_port=None,
                                destination_port=None,
                                protocol='icmp') as fwr:
            data = {'firewall_rule': {'destination_port': 80}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_firewall_rule_with_policy_associated(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)
        with self.firewall_rule() as fwr:
            with self.firewall_policy() as fwp:
                fwr_id = fwr['firewall_rule']['id']
                data = {'firewall_policy': {'firewall_rules': [fwr_id]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                data = {'firewall_rule': {'name': name}}
                req = self.new_update_request('firewall_rules', data,
                                              fwr['firewall_rule']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_rule'][k])
                res = self._show_req('firewall_policies',
                                     fwp['firewall_policy']['id'])
                self.assertEqual(
                    [fwr_id],
                    res['firewall_policy']['firewall_rules'])
                self.assertFalse(res['firewall_policy']['audited'])

    @testtools.skip('bug/1614680')
    def test_update_firewall_rule_associated_with_other_tenant_policy(self):
        with self.firewall_rule(shared=SHARED, tenant_id='tenant1') as fwr:
            fwr_id = [fwr['firewall_rule']['id']]
            with self.firewall_policy(shared=False, firewall_rules=fwr_id):
                data = {'firewall_rule': {'shared': False}}
                req = self.new_update_request('firewall_rules', data,
                                              fwr['firewall_rule']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_rule_with_ipv6_ipaddr(self):
        with self.firewall_rule(source_ip_address="1::10",
                                destination_ip_address=None,
                                ip_version=6) as fwr_v6:
            data = {'firewall_rule': {
                'destination_ip_address': "2::20"}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr_v6['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_delete_firewall_rule(self):
        ctx = self._get_admin_context()
        with self.firewall_rule(do_delete=False) as fwr:
            fwr_id = fwr['firewall_rule']['id']
            req = self.new_delete_request('firewall_rules', fwr_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(204, res.status_int)
            self.assertRaises(f_exc.FirewallRuleNotFound,
                              self.plugin.get_firewall_rule,
                              ctx, fwr_id)

    def test_delete_firewall_rule_with_policy_associated(self):
        with self.firewall_rule() as fwr:
            with self.firewall_policy() as fwp:
                fwr_id = fwr['firewall_rule']['id']
                data = {'firewall_policy': {'firewall_rules': [fwr_id]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                req = self.new_delete_request('firewall_rules', fwr_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    def _test_create_firewall_group(self, attrs):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['ingress_firewall_policy_id'] = fwp_id
            attrs['egress_firewall_policy_id'] = fwp_id
            with self.firewall_group(
                name=attrs['name'],
                ingress_firewall_policy_id=fwp_id,
                egress_firewall_policy_id=fwp_id,
                admin_state_up=ADMIN_STATE_UP,
                ports=attrs['ports'] if 'ports' in attrs else None,
            ) as firewall_group:
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, firewall_group['firewall_group'][k])

    def test_create_firewall_group(self):
        attrs = self._get_test_firewall_group_attrs("firewall1")
        self._test_create_firewall_group(attrs)

    def test_create_firewall_group_with_ports(self):
        with self.port(
            device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF) as dummy_port:
            attrs = self._get_test_firewall_group_attrs("fwg1")
            attrs['ports'] = [dummy_port['port']['id']]
            self._test_create_firewall_group(attrs)

    def test_create_firewall_group_with_empty_ports(self):
        attrs = self._get_test_firewall_group_attrs("fwg1")
        attrs['ports'] = []
        self._test_create_firewall_group(attrs)

    def test_create_default_firewall_group_multiple_times_diff_tenants(self):
        ctx_admin = self._get_admin_context()
        fwg_admin = self._build_default_fwg(ctx=ctx_admin)
        res = self._build_default_fwg(ctx=ctx_admin, is_one=False)
        # check that only 1 group has been created
        self.assertEqual(1, len(res))
        ctx = self._get_nonadmin_context()
        fwg_na = self._build_default_fwg(ctx=ctx)
        res = self._build_default_fwg(ctx=ctx, is_one=False)
        # check that only 1 group has been created
        self.assertEqual(1, len(res))
        # make sure that admin default_fwg and non_admin don't match
        self.assertNotEqual(fwg_na['id'], fwg_admin['id'])
        # make sure that admin can see default groups for admin and non-admin
        res = self._list_req('firewall_groups', ctx=ctx_admin)
        self.assertEqual(2, len(res))
        self.assertEqual(set([ctx_admin.tenant_id, ctx.tenant_id]),
                         set([r['tenant_id'] for r in res]))

    def test_create_default_firewall_group(self):
        self._build_default_fwg()
        result_map = {
            'firewall_groups': {"keys": ["description", "name"],
                                "data": [("Default firewall group",
                                          constants.DEFAULT_FWG)]
                                },
            'firewall_policies': {
                "keys": ["description", "name"],
                "data": [("Ingress firewall policy",
                          constants.DEFAULT_FWP_INGRESS),
                         ("Egress firewall policy",
                          constants.DEFAULT_FWP_EGRESS)]},
            'firewall_rules': {
                "keys": ["description", "action", "protocol", "enabled",
                         "ip_version", "name"],
                "data": [
                    ("default ingress rule for IPv4", "deny", None, True, 4,
                     "default ingress ipv4 (deny all)"),
                    ("default egress rule for IPv4", "allow", None, True, 4,
                     "default egress ipv4 (allow all)"),
                    ("default ingress rule for IPv6", "deny", None, True, 6,
                     "default ingress ipv6 (deny all)"),
                    ("default egress rule for IPv6", "allow", None, True, 6,
                     "default egress ipv6 (allow all)")]
            }
        }

        def _check_rules_match_policies(policy, direction):
            if direction in policy["description"].lower():
                for rule_id in policy['firewall_rules']:
                    rule = self._show_req(
                        'firewall_rules', rule_id)['firewall_rule']
                    self.assertTrue(direction in rule["description"])

        for obj in result_map:
            res = self._list_req(obj)
            check_keys = result_map[obj]["keys"]
            expected = result_map[obj]["data"]
            self.assertEqual(len(expected), len(res))

            # an attempt to check that rules match policies
            if obj == 'firewall_policies':
                for p in res:
                    _check_rules_match_policies(p, "ingress")
                    _check_rules_match_policies(p, "egress")

            # check that a rule with given params is present in actual
            # data by comparing expected/actual tuples
            actual = []
            for r in res:
                actual.append(tuple(r[key] for key in check_keys))
            self.assertEqual(set(expected), set(actual))

    def test_create_firewall_group_exists_default(self):
        self._build_default_fwg()['id']
        attrs = self._get_test_firewall_group_attrs("firewall1")
        self._test_create_firewall_group(attrs)

    def test_create_firewall_group_with_dvr(self):
        cfg.CONF.set_override('router_distributed', True)
        attrs = self._get_test_firewall_group_attrs("firewall1", "CREATED")
        self._test_create_firewall_group(attrs)

    def test_create_firewall_group_with_fwp_does_not_exist(self):
        fmt = self.fmt
        fwg_name = "firewall1"
        description = "my_firewall1"
        not_found_fwp_id = uuidutils.generate_uuid()
        self._create_firewall_group(fmt, fwg_name,
                              description, not_found_fwp_id,
                              not_found_fwp_id, ports=None,
                              admin_state_up=ADMIN_STATE_UP,
                              expected_res_status=404)

    def test_create_firewall_group_with_fwp_on_different_tenant(self):
        fmt = self.fmt
        fwg_name = "firewall1"
        description = "my_firewall1"
        with self.firewall_policy(shared=False, tenant_id='tenant2') as fwp:
            fwp_id = fwp['firewall_policy']['id']
            ctx = self._get_nonadmin_context()
            self._create_firewall_group(fmt, fwg_name,
                                        description,
                    ingress_firewall_policy_id=fwp_id,
                                        egress_firewall_policy_id=fwp_id,
                    context=ctx,
                                        expected_res_status=404)

    def test_create_firewall_group_with_admin_and_fwp_different_tenant(self):
        fmt = self.fmt
        fwg_name = "firewall1"
        description = "my_firewall1"
        with self.firewall_policy(shared=False, tenant_id='tenant2') as fwp:
            fwp_id = fwp['firewall_policy']['id']
            ctx = self._get_admin_context()
            self._create_firewall_group(fmt, fwg_name,
                                        description, fwp_id, fwp_id,
                                        tenant_id="admin-tenant",
                                        context=ctx,
                                        expected_res_status=404)

    def test_create_firewall_group_with_admin_and_fwp_is_shared(self):
        fwg_name = "fw_with_shared_fwp"
        with self.firewall_policy(tenant_id="tenantX") as fwp:
            fwp_id = fwp['firewall_policy']['id']
            ctx = self._get_admin_context()
            target_tenant = 'tenant1'
            with self.firewall_group(name=fwg_name,
                                     ingress_firewall_policy_id=fwp_id,
                                     tenant_id=target_tenant, context=ctx,
                                     admin_state_up=ADMIN_STATE_UP) as fwg:
                self.assertEqual(target_tenant,
                                 fwg['firewall_group']['tenant_id'])

    def _test_show_firewall_group(self, attrs):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['ingress_firewall_policy_id'] = fwp_id
            attrs['egress_firewall_policy_id'] = fwp_id
            attrs['status'] = 'PENDING_CREATE'
            with self.firewall_group(
                    name=attrs['name'],
                    ports=attrs['ports'] if 'ports' in attrs else None,
                    ingress_firewall_policy_id=fwp_id,
                    egress_firewall_policy_id=fwp_id,
                    admin_state_up=ADMIN_STATE_UP) as firewall_group:
                res = self._show_req('firewall_groups',
                                     firewall_group['firewall_group']['id'])
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_group'][k])

    def test_show_firewall_group(self):
        attrs = self._get_test_firewall_group_attrs('fwg1')
        self._test_show_firewall_group(attrs)

    def test_show_firewall_group_with_ports(self):
        attrs = self._get_test_firewall_group_attrs('fwg1')
        with self.port(
            device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF) as dummy_port:
            attrs['ports'] = [dummy_port['port']['id']]
            self._test_show_firewall_group(attrs)

    def test_show_firewall_group_with_empty_ports(self):
        attrs = self._get_test_firewall_group_attrs('fwg1')
        attrs['ports'] = []
        self._test_show_firewall_group(attrs)

    def test_list_firewall_groups(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(name='fwg1', tenant_id='tenant1',
                               ingress_firewall_policy_id=fwp_id,
                               description='fwg') as fwg1, \
                    self.firewall_group(name='fwg2', tenant_id='tenant2',
                                  ingress_firewall_policy_id=fwp_id,
                                  egress_firewall_policy_id=fwp_id,
                                  description='fwg') as fwg2, \
                    self.firewall_group(name='fwg3', tenant_id='tenant3',
                                  ingress_firewall_policy_id=fwp_id,
                                  egress_firewall_policy_id=fwp_id,
                                  description='fwg') as fwg3:
                fwgrps = [fwg1, fwg2, fwg3]
                self._test_list_resources('firewall_group', fwgrps,
                                          query_params='description=fwg')

    def test_update_firewall_group(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_group_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(
                    ingress_firewall_policy_id=fwp_id,
                    admin_state_up=ADMIN_STATE_UP) as firewall:
                data = {'firewall_group': {'name': name}}
                req = self.new_update_request('firewall_groups', data,
                                              firewall['firewall_group']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, res['firewall_group'][k])

    def test_existing_default_create_default_firewall_group(self):
        self._build_default_fwg()
        self._create_firewall_group(fmt=None,
                                    name=constants.DEFAULT_FWG,
                                    description="",
                                    ingress_firewall_policy_id=None,
                                    egress_firewall_policy_id=None,
                                    expected_res_status=409)

    def test_update_default_firewall_group_with_non_admin_success(self):
        ctx = self._get_nonadmin_context()
        def_fwg_id = self._build_default_fwg(ctx=ctx)['id']
        with self.port(
            device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF,
            ctx=ctx) as dummy_port:
            port_id = dummy_port['port']['id']
            success_cases = [
                    {'ports': [port_id]},
                    {'ports': []},
                    {'ports': None},
                    {},
            ]
            for attr in success_cases:
                data = {'firewall_group': attr}
                req = self.new_update_request(
                    'firewall_groups', data, def_fwg_id)
                req.environ['neutron.context'] = ctx
                res = req.get_response(self.ext_api)
                self.assertEqual(200, res.status_int)

    def test_update_default_firewall_group_with_non_admin_failure(self):
        ctx = self._get_nonadmin_context()
        def_fwg_id = self._build_default_fwg(ctx=ctx)['id']
        with self.port(
            device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF,
            ctx=ctx) as dummy_port:
            port_id = dummy_port['port']['id']
            conflict_cases = [
                    {'name': ''},
                    {'name': 'default'},
                    {'name': 'non-default'},
                    {'ingress_firewall_policy_id': None},
                    {'egress_firewall_policy_id': None},
                    {'description': 'try to modify'},
                    {'admin_state_up': True},
                    {'ports': [port_id], 'name': ''},
                    {'ports': [], 'name': 'default'},
                    {'ports': None, 'name': 'non-default'},
            ]
            for attr in conflict_cases:
                data = {'firewall_group': attr}
                req = self.new_update_request(
                    'firewall_groups', data, def_fwg_id)
                req.environ['neutron.context'] = ctx
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    def test_update_default_firewall_group_with_admin_success(self):
        ctx = self._get_admin_context()
        with self.port(
            device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF,
            ctx=ctx) as dummy_port:
            port_id = dummy_port['port']['id']
            def_fwg_id = self._build_default_fwg(ctx=ctx)['id']
            success_cases = [
                    {'ports': [port_id]},
                    {'ports': []},
                    {'ports': None},
                    {'ingress_firewall_policy_id': None},
                    {'egress_firewall_policy_id': None},
                    {'description': 'try to modify'},
                    {'admin_state_up': True},
                    {},
            ]
            for attr in success_cases:
                data = {'firewall_group': attr}
                req = self.new_update_request(
                    'firewall_groups', data, def_fwg_id)
                req.environ['neutron.context'] = ctx
                res = req.get_response(self.ext_api)
                self.assertEqual(200, res.status_int)

    def test_update_default_firewall_group_with_admin_failure(self):
        ctx = self._get_admin_context()
        with self.port(
            device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF,
            ctx=ctx) as dummy_port:
            port_id = dummy_port['port']['id']
            def_fwg_id = self._build_default_fwg(ctx=ctx)['id']
            conflict_cases = [
                    {'name': 'default'},
                    {'name': 'non-default'},
                    {'name': ''},
                    {'ports': [port_id], 'name': ''},
                    {'ports': [], 'name': 'default'},
                    {'ports': None, 'name': 'non-default'},
            ]
            for attr in conflict_cases:
                data = {'firewall_group': attr}
                req = self.new_update_request(
                    'firewall_groups', data, def_fwg_id)
                req.environ['neutron.context'] = ctx
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    def test_update_firewall_group_with_fwp(self):
        ctx = self._get_nonadmin_context()
        with self.firewall_policy(name='p1', tenant_id=ctx.tenant_id,
                                  shared=False) as fwp1, \
                self.firewall_policy(name='p2', tenant_id=ctx.tenant_id,
                                     shared=False) as fwp2, \
                self.firewall_group(
                    ingress_firewall_policy_id=fwp1['firewall_policy']['id'],
                    egress_firewall_policy_id=fwp2['firewall_policy']['id'],
                    context=ctx) as fw:
            fw_id = fw['firewall_group']['id']
            fwp2_id = fwp2['firewall_policy']['id']
            data = {'firewall_group': {'ingress_firewall_policy_id': fwp2_id}}
            req = self.new_update_request('firewall_groups', data, fw_id,
                                          context=ctx)
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_change_fwg_name_to_default(self):
        """
           Make sure that neither admin nor non-admin can change name of
           existing firewall group to default
        """
        admin_ctx = self._get_admin_context()
        nonadmin_ctx = self._get_nonadmin_context()
        with self.firewall_group(context=nonadmin_ctx) as fwg:
            data = {'firewall_group': {'name': constants.DEFAULT_FWG}}
            fwg_id = fwg['firewall_group']['id']
            for ctx in [admin_ctx, nonadmin_ctx]:
                req = self.new_update_request('firewall_groups', data, fwg_id,
                                              context=ctx)
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    @testtools.skip('bug/1614680')
    def test_update_firewall_group_with_shared_fwp(self):
        ctx = self._get_nonadmin_context()
        with self.firewall_policy(name='p1', tenant_id=ctx.tenant_id,
                                  shared=True) as fwp1, \
                self.firewall_policy(name='p2', tenant_id='tenant2',
                                     shared=True) as fwp2, \
                self.firewall_group(
                    ingress_firewall_policy_id=fwp1['firewall_policy']['id'],
                    egress_firewall_policy_id=fwp1['firewall_policy']['id'],
                    context=ctx) as fw:
            fw_id = fw['firewall_group']['id']
            fwp2_id = fwp2['firewall_policy']['id']
            data = {'firewall_group': {'ingress_firewall_policy_id': fwp2_id}}
            req = self.new_update_request('firewall_groups', data, fw_id,
                                          context=ctx)
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_firewall_group_with_admin_and_fwp_different_tenant(self):
        ctx = self._get_admin_context()
        with self.firewall_policy() as fwp1, \
                self.firewall_policy(tenant_id='tenant2',
                                     shared=False) as fwp2, \
                self.firewall_group(
                    ingress_firewall_policy_id=fwp1['firewall_policy']['id'],
                    egress_firewall_policy_id=fwp1['firewall_policy']['id'],
                    context=ctx) as fw:
            fw_id = fw['firewall_group']['id']
            fwp2_id = fwp2['firewall_policy']['id']
            data = {'firewall_group': {'egress_firewall_policy_id': fwp2_id}}
            req = self.new_update_request('firewall_groups', data, fw_id,
                                          context=ctx)
            res = req.get_response(self.ext_api)
            self.assertEqual(404, res.status_int)

    def test_update_firewall_group_fwp_not_found_on_different_tenant(self):
        with self.firewall_policy(name='fwp1', tenant_id='tenant1',
                                  do_delete=False) as fwp1, \
                self.firewall_policy(name='fwp2', shared=False,
                                     tenant_id='tenant2') as fwp2:

            fwps = [fwp1, fwp2]
            # create firewall using fwp1 exists the same tenant.
            fwp1_id = fwps[0]['firewall_policy']['id']
            fwp2_id = fwps[1]['firewall_policy']['id']
            ctx = self._get_nonadmin_context()
            with self.firewall_group(ingress_firewall_policy_id=fwp1_id,
                               context=ctx) as firewall:
                fw_id = firewall['firewall_group']['id']
                fw_db = self.plugin._get_firewall_group(ctx, fw_id)
                fw_db['status'] = nl_constants.ACTIVE
                # update firewall from fwp1 to fwp2(different tenant)
                data = {'firewall_group':
                        {'ingress_firewall_policy_id': fwp2_id}}
                req = self.new_update_request('firewall_groups', data, fw_id,
                                              context=ctx)
                res = req.get_response(self.ext_api)
                self.assertEqual(404, res.status_int)

    def test_delete_firewall_group(self):
        ctx = self._get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_group(ingress_firewall_policy_id=fwp_id,
                               do_delete=False) as fw:
                fw_id = fw['firewall_group']['id']
                req = self.new_delete_request('firewall_groups', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(204, res.status_int)
                self.assertRaises(f_exc.FirewallGroupNotFound,
                                  self.plugin.get_firewall_group,
                                  ctx, fw_id)

    def test_delete_firewall_group_already_deleted(self):
        ctx = self._get_admin_context()
        deleted_id = uuidutils.generate_uuid()
        with self.firewall_group(do_delete=False) as fwg:
            fwg_id = fwg['firewall_group']['id']
            self.assertIsNone(self.plugin.delete_firewall_group(ctx, fwg_id))
        self.assertIsNone(self.plugin.delete_firewall_group(ctx, deleted_id))

    def test_delete_default_firewall_group_with_admin(self):
        ctx_a = self._get_admin_context()
        ctx_na = self._get_nonadmin_context()
        def_fwg_id = None
        for ctx in [ctx_na, ctx_a]:
            def_fwg_id = self._build_default_fwg(ctx=ctx)['id']
            req = self.new_delete_request('firewall_groups', def_fwg_id)
            req.environ['neutron.context'] = ctx_a
            self.assertEqual(204, req.get_response(self.ext_api).status_int)
        # check that policy has been deleted by listing as admin and getting 1
        # default fwg with a differnt id
        res = self._list_req('firewall_groups', ctx=ctx_a)
        self.assertEqual(1, len(res))
        self.assertNotEqual(def_fwg_id, res[0]['id'])

    def test_delete_default_firewall_group_with_non_admin(self):
        ctx = self._get_nonadmin_context()
        def_fwg_id = self._build_default_fwg(ctx=ctx)['id']
        req = self.new_delete_request('firewall_groups', def_fwg_id)
        req.environ['neutron.context'] = ctx
        self.assertEqual(409, req.get_response(self.ext_api).status_int)

    def test_insert_rule_in_policy_with_prior_rules_added_via_update(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            frs = [fwr1, fwr2, fwr3]
            fr1 = frs[0:2]
            fwr3 = frs[2]
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                attrs['firewall_rules'] = fw_rule_ids[:]
                data = {'firewall_policy': {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                self._rule_action('insert', fwp_id, fw_rule_ids[0],
                                  insert_before=fw_rule_ids[0],
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPConflict.code,
                                  expected_body=None)
                fwr3_id = fwr3['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr3_id)
                self._rule_action('insert', fwp_id, fwr3_id,
                                  insert_before=fw_rule_ids[0],
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_insert_rule_in_policy_failures(self):
        with self.firewall_rule(name='fwr1') as fr1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fr1_id = fr1['firewall_rule']['id']
                fw_rule_ids = [fr1_id]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test inserting with empty request body
                self._rule_action('insert', fwp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None, body_data={})
                # test inserting when firewall_rule_id is missing in
                # request body
                insert_data = {'insert_before': '123',
                               'insert_after': '456'}
                self._rule_action('insert', fwp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None,
                                  body_data=insert_data)
                # test inserting when firewall_rule_id is None
                insert_data = {'firewall_rule_id': None,
                               'insert_before': '123',
                               'insert_after': '456'}
                self._rule_action('insert', fwp_id, None,
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None,
                                  body_data=insert_data)
                # test inserting when firewall_policy_id is incorrect
                self._rule_action('insert', '123', fr1_id,
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test inserting when firewall_policy_id is None
                self._rule_action('insert', None, fr1_id,
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_insert_rule_and_already_associated(self):
        with self.firewall_rule() as fwr:
            fwr_id = fwr['firewall_rule']['id']
            with self.firewall_policy(firewall_rules=[fwr_id]) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                self._rule_action(
                    'insert', fwp_id, fwr_id,
                    insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPConflict.code,
                    body_data={'firewall_rule_id': fwr_id})

    def test_insert_rule_for_previously_associated_rule(self):
        with self.firewall_rule() as fwr:
            fwr_id = fwr['firewall_rule']['id']
            fw_rule_ids = [fwr_id]
            with self.firewall_policy(firewall_rules=fw_rule_ids):
                with self.firewall_policy(name='firewall_policy2') as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    insert_data = {'firewall_rule_id': fwr_id}
                    self._rule_action(
                        'insert', fwp_id, fwr_id, insert_before=None,
                        insert_after=None,
                        expected_code=webob.exc.HTTPOk.code,
                        expected_body=None, body_data=insert_data)

    def test_insert_rule_for_previously_associated_rule_other_tenant(self):
        with self.firewall_rule(tenant_id='tenant-2') as fwr:
            fwr_id = fwr['firewall_rule']['id']
            fw_rule_ids = [fwr_id]
            with self.firewall_policy(tenant_id='tenant-2',
                                      firewall_rules=fw_rule_ids):
                with self.firewall_policy(name='firewall_policy2') as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    insert_data = {'firewall_rule_id': fwr_id}
                    self._rule_action(
                        'insert', fwp_id, fwr_id, insert_before=None,
                        insert_after=None,
                        expected_code=webob.exc.HTTPOk.code,
                        expected_body=None, body_data=insert_data)

    def test_insert_rule_for_prev_associated_ref_rule(self):
        with self.firewall_rule(name='fwr0') as fwr0, \
                self.firewall_rule(name='fwr1') as fwr1:
            fwr = [fwr0, fwr1]
            fwr0_id = fwr[0]['firewall_rule']['id']
            fwr1_id = fwr[1]['firewall_rule']['id']
            with self.firewall_policy(name='fwp0') as fwp0, \
                    self.firewall_policy(name='fwp1',
                                         firewall_rules=[fwr1_id]) as fwp1:
                fwp = [fwp0, fwp1]
                fwp0_id = fwp[0]['firewall_policy']['id']
                # test inserting before a rule which
                # is associated with different policy
                self._rule_action('insert', fwp0_id, fwr0_id,
                                  insert_before=fwr1_id,
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)
                # test inserting  after a rule which
                # is associated with different policy
                self._rule_action('insert', fwp0_id, fwr0_id,
                                  insert_after=fwr1_id,
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_insert_rule_for_policy_of_other_tenant(self):
        with self.firewall_rule(tenant_id='tenant-2', shared=False) as fwr:
            fwr_id = fwr['firewall_rule']['id']
            with self.firewall_policy(name='firewall_policy') as fwp:
                fwp_id = fwp['firewall_policy']['id']
                insert_data = {'firewall_rule_id': fwr_id}
                self._rule_action(
                    'insert', fwp_id, fwr_id, insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPConflict.code,
                    expected_body=None, body_data=insert_data)

    def test_insert_rule_missing_rule_id(self):
        with self.firewall_rule(tenant_id='tenant-2', shared=False):
            with self.firewall_policy(name='firewall_policy') as fwp:
                fwp_id = fwp['firewall_policy']['id']
                insert_data = {}
                self._rule_action(
                    'insert', fwp_id, None, insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPBadRequest.code,
                    expected_body=None, body_data=insert_data)

    def test_insert_rule_empty_rule_id(self):
        with self.firewall_rule(tenant_id='tenant-2', shared=False):
            with self.firewall_policy(name='firewall_policy') as fwp:
                fwp_id = fwp['firewall_policy']['id']
                insert_data = {'firewall_rule_id': None}
                self._rule_action(
                    'insert', fwp_id, None, insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPNotFound.code,
                    expected_body=None, body_data=insert_data)

    def test_insert_rule_invalid_rule_id(self):
        with self.firewall_rule(tenant_id='tenant-2', shared=False):
            with self.firewall_policy(name='firewall_policy') as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fwr_id_fake = 'foo'
                insert_data = {'firewall_rule_id': fwr_id_fake}
                self._rule_action(
                    'insert', fwp_id, fwr_id_fake, insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPNotFound.code,
                    expected_body=None, body_data=insert_data)

    def test_insert_rule_nonexistent_rule_id(self):
        with self.firewall_rule(tenant_id='tenant-2', shared=False):
            with self.firewall_policy(name='firewall_policy') as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fwr_id_fake = uuidutils.generate_uuid()
                insert_data = {'firewall_rule_id': fwr_id_fake}
                self._rule_action(
                    'insert', fwp_id, fwr_id_fake, insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPNotFound.code,
                    expected_body=None, body_data=insert_data)

    def test_insert_rule_in_policy(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        with self.firewall_rule(name='fwr0') as fwr0, \
                self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3, \
                self.firewall_rule(name='fwr4') as fwr4, \
                self.firewall_rule(name='fwr5') as fwr5, \
                self.firewall_rule(name='fwr6') as fwr6:
            fwr = [fwr0, fwr1, fwr2, fwr3, fwr4, fwr5, fwr6]
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                # test insert when rule list is empty
                fwr0_id = fwr[0]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr0_id)
                self._rule_action('insert', fwp_id, fwr0_id,
                                  insert_before=None,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at top of rule list, insert_before and
                # insert_after not provided
                fwr1_id = fwr[1]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr1_id)
                insert_data = {'firewall_rule_id': fwr1_id}
                self._rule_action('insert', fwp_id, fwr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs, body_data=insert_data)
                # test insert at top of list above existing rule
                fwr2_id = fwr[2]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr2_id)
                self._rule_action('insert', fwp_id, fwr2_id,
                                  insert_before=fwr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at bottom of list
                fwr3_id = fwr[3]['firewall_rule']['id']
                attrs['firewall_rules'].append(fwr3_id)
                self._rule_action('insert', fwp_id, fwr3_id,
                                  insert_before=None,
                                  insert_after=fwr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_before
                fwr4_id = fwr[4]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr4_id)
                self._rule_action('insert', fwp_id, fwr4_id,
                                  insert_before=fwr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_after
                fwr5_id = fwr[5]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr5_id)
                self._rule_action('insert', fwp_id, fwr5_id,
                                  insert_before=None,
                                  insert_after=fwr2_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert when both insert_before and
                # insert_after are set
                fwr6_id = fwr[6]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr6_id)
                self._rule_action('insert', fwp_id, fwr6_id,
                                  insert_before=fwr5_id,
                                  insert_after=fwr5_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_remove_rule_and_not_associated(self):
        with self.firewall_rule(name='fwr0') as fwr:
            with self.firewall_policy(name='firewall_policy2') as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fwr_id = fwr['firewall_rule']['id']
                msg = "Firewall rule {0} is not associated with " \
                      "firewall policy {1}.".format(fwr_id, fwp_id)
                result = self._rule_action(
                    'remove', fwp_id, fwr_id,
                    insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPBadRequest.code,
                    body_data={'firewall_rule_id': fwr_id})
                self.assertEqual(msg, result['NeutronError']['message'])

    def test_remove_rule_from_policy(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            fr1 = [fwr1, fwr2, fwr3]
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                attrs['firewall_rules'] = fw_rule_ids[:]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test removing a rule from a policy that does not exist
                self._rule_action('remove', '123', fw_rule_ids[1],
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing a rule in the middle of the list
                attrs['firewall_rules'].remove(fw_rule_ids[1])
                self._rule_action('remove', fwp_id, fw_rule_ids[1],
                                  expected_body=attrs)
                # test removing a rule at the top of the list
                attrs['firewall_rules'].remove(fw_rule_ids[0])
                self._rule_action('remove', fwp_id, fw_rule_ids[0],
                                  expected_body=attrs)
                # test removing remaining rule in the list
                attrs['firewall_rules'].remove(fw_rule_ids[2])
                self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                  expected_body=attrs)
                # test removing rule that is not associated with the policy
                self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_remove_rule_from_policy_failures(self):
        with self.firewall_rule(name='fwr1') as fr1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [fr1['firewall_rule']['id']]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test removing rule that does not exist
                self._rule_action('remove', fwp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing rule with bad request
                self._rule_action('remove', fwp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None, body_data={})
                # test removing rule with firewall_rule_id set to None
                self._rule_action('remove', fwp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None,
                                  body_data={'firewall_rule_id': None})

    def test_show_firewall_rule_by_name(self):
        with self.firewall_rule(name='firewall_Rule1') as fw_rule:
            res = self._show('firewall_rules',
                             fw_rule['firewall_rule']['id'])
            self.assertEqual('firewall_Rule1', res['firewall_rule']['name'])

    def test_show_firewall_policy_by_name(self):
        with self.firewall_policy(name='firewall_Policy1') as fw_policy:
            res = self._show('firewall_policies',
                             fw_policy['firewall_policy']['id'])
            self.assertEqual(
                'firewall_Policy1', res['firewall_policy']['name'])

    def test_show_firewall_group_by_name(self):
        with self.firewall_group(name='fireWall1') as fw:
            res = self._show('firewall_groups', fw['firewall_group']['id'])
            self.assertEqual('fireWall1', res['firewall_group']['name'])

    def test_set_port_in_use_for_firewall_group(self):
        fwg_db = {'id': 'fake_id'}
        new_ports = {'ports': ['fake_port1', 'fake_port2']}
        m_context = context.get_admin_context()
        with mock.patch.object(m_context.session, 'add',
                               side_effect=[None, f_exc.FirewallGroupPortInUse(
                                    port_ids=['fake_port2'])]):
            self.assertRaises(f_exc.FirewallGroupPortInUse,
                              self.plugin._set_ports_for_firewall_group,
                              m_context,
                              fwg_db,
                              new_ports)

    def test_set_port_for_default_firewall_group(self):
        ctx = self._get_nonadmin_context()
        self._build_default_fwg(ctx=ctx)
        with self.port(project_id=ctx.tenant_id) as port1, \
            self.port(project_id=ctx.tenant_id) as port2:
            port1_id = port1['port']['id']
            port2_id = port2['port']['id']
            port_ids = [port1_id, port2_id]
            project_id = ctx.tenant_id

            self.plugin.set_port_for_default_firewall_group(
                ctx, port1_id, project_id)
            self.plugin.set_port_for_default_firewall_group(
                ctx, port2_id, project_id)
            def_fwg_db = self.plugin._get_default_fwg(ctx, project_id)
            self.assertEqual('PENDING_UPDATE', def_fwg_db['status'])
            self.assertEqual(sorted(port_ids), sorted(def_fwg_db['ports']))

    def test_set_port_for_default_firewall_group_raised_port_in_use(self):
        ctx = self._get_nonadmin_context()
        self._build_default_fwg(ctx=ctx)
        self.plugin.update_firewall_group_status = mock.Mock()
        with self.port(project_id=ctx.tenant_id) as port1:
            port1_id = port1['port']['id']
            port_ids = [port1_id]
            self.plugin._set_ports_for_firewall_group = mock.Mock(
                side_effect=f_exc.FirewallGroupPortInUse(port_ids=port_ids))
            project_id = ctx.tenant_id

            self.plugin.set_port_for_default_firewall_group(
                ctx, port1_id, project_id)
            self.plugin.update_firewall_group_status.assert_not_called()
