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

import contextlib

import mock
import six
import webob.exc

from neutron.api import extensions as api_ext
from neutron.db import servicetype_db as sdb
from neutron_lib.api.definitions import firewall_v2
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.exceptions import firewall_v2 as f_exc
from neutron_lib.plugins import directory
from oslo_utils import importutils

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas import extensions
from neutron_fwaas.services.firewall import fwaas_plugin_v2
from neutron_fwaas.tests import base


def http_client_error(req, res):
    explanation = "Request '%s %s %s' failed: %s" % (req.method, req.url,
                                                     req.body, res.body)
    return webob.exc.HTTPClientError(code=res.status_int,
                                     explanation=explanation)


class FirewallPluginV2TestCase(base.NeutronDbPluginV2TestCase):
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

    resource_prefix_map = dict(
        (k, firewall_v2.API_PREFIX)
        for k in firewall_v2.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, service_provider=None, core_plugin=None,
              extra_service_plugins=None, extra_extension_paths=None):
        provider = fwaas_constants.FIREWALL_V2
        if not service_provider:
            provider += (':dummy:neutron_fwaas.services.firewall.'
                         'service_drivers.driver_api.FirewallDriverDB:default')
        else:
            provider += ':test:' + service_provider + ':default'

        bits = provider.split(':')
        provider = {
            'service_type': bits[0],
            'name': bits[1],
            'driver': bits[2],
            'default': True,
        }
        # override the default service provider
        self.service_providers = (
            mock.patch.object(sdb.ServiceTypeManager,
                              'get_service_providers').start())
        self.service_providers.return_value = [provider]

        plugin_str = ('neutron_fwaas.services.firewall.fwaas_plugin_v2.'
                      'FirewallPluginV2')
        service_plugins = {'fw_plugin_name': plugin_str}
        service_plugins.update(extra_service_plugins or {})

        # we need to provide a plugin instance, although the extension manager
        # will create a new instance of the plugin
        plugins = {
            fwaas_constants.FIREWALL_V2: fwaas_plugin_v2.FirewallPluginV2(),
        }
        for plugin_name, plugin_str in (extra_service_plugins or {}).items():
            plugins[plugin_name] = importutils.import_object(plugin_str)
        ext_mgr = api_ext.PluginAwareExtensionManager(
            ':'.join(extensions.__path__ + (extra_extension_paths or [])),
            plugins,
        )

        super(FirewallPluginV2TestCase, self).setUp(
            plugin=core_plugin,
            service_plugins=service_plugins,
            ext_mgr=ext_mgr,
        )

        # find the Firewall plugin that was instantiated by the extension
        # manager
        self.plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)

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

    def _get_nonadmin_context(self, user_id='non-admin', tenant_id='tenant1'):
        return context.Context(user_id=user_id, tenant_id=tenant_id)

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
                 'protocol': self.PROTOCOL,
                 'ip_version': self.IP_VERSION,
                 'source_ip_address': self.SOURCE_IP_ADDRESS_RAW,
                 'destination_ip_address': self.DESTINATION_IP_ADDRESS_RAW,
                 'source_port': self.SOURCE_PORT,
                 'destination_port': self.DESTINATION_PORT,
                 'action': self.ACTION,
                 'enabled': self.ENABLED,
                 'shared': self.SHARED}
        return attrs

    def _get_test_firewall_policy_attrs(self, name='firewall_policy1',
                                        audited=AUDITED):
        attrs = {'name': name,
                 'description': self.DESCRIPTION,
                 'tenant_id': self._tenant_id,
                 'project_id': self._tenant_id,
                 'firewall_rules': [],
                 'audited': audited,
                 'shared': self.SHARED}
        return attrs

    def _get_test_firewall_group_attrs(self, name='firewall_1',
                                       status=nl_constants.CREATED):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'project_id': self._tenant_id,
                 'admin_state_up': self.ADMIN_STATE_UP,
                 'status': status}

        return attrs

    def _create_firewall_policy(self, fmt, name, description, shared,
                                firewall_rules, audited,
                                expected_res_status=None, **kwargs):
        data = {'firewall_policy': {'name': name,
                                    'description': description,
                                    'firewall_rules': firewall_rules,
                                    'audited': audited,
                                    'shared': shared}}
        ctx = kwargs.get('context', None)
        if ctx is None or ctx.is_admin:
            tenant_id = kwargs.get('tenant_id', self._tenant_id)
            data['firewall_policy'].update({'tenant_id': tenant_id})
            data['firewall_policy'].update({'project_id': tenant_id})

        req = self.new_create_request('firewall_policies', data, fmt,
                                      context=ctx)
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif res.status_int >= 400:
            raise http_client_error(req, res)

        return res

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
        ctx = kwargs.get('context', None)
        if ctx is None or ctx.is_admin:
            tenant_id = kwargs.get('tenant_id', self._tenant_id)
            data['firewall_rule'].update({'tenant_id': tenant_id})
            data['firewall_rule'].update({'project_id': tenant_id})

        req = self.new_create_request('firewall_rules', data, fmt, context=ctx)
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif res.status_int >= 400:
            raise http_client_error(req, res)

        return res

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
                               ingress_firewall_policy_id=None,
                               egress_firewall_policy_id=None,
                               ports=None, admin_state_up=True,
                               expected_res_status=None, **kwargs):
        if ingress_firewall_policy_id is None:
            default_policy = kwargs.get('default_policy', True)
            if default_policy:
                res = self._create_firewall_policy(
                    fmt,
                    'fwp',
                    description=self.DESCRIPTION,
                    shared=self.SHARED,
                    firewall_rules=[],
                    audited=self.AUDITED,
                )
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
            tenant_id = kwargs.get('tenant_id', self._tenant_id)
            data['firewall_group'].update({'tenant_id': tenant_id})
            data['firewall_group'].update({'project_id': tenant_id})
        if ports is not None:
            data['firewall_group'].update({'ports': ports})

        req = self.new_create_request('firewall_groups', data, fmt,
                                      context=ctx)
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif res.status_int >= 400:
            raise http_client_error(req, res)
        return res

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

    def _test_create_firewall_group(self, attrs):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['ingress_firewall_policy_id'] = fwp_id
            attrs['egress_firewall_policy_id'] = fwp_id
            with self.firewall_group(
                name=attrs['name'],
                ingress_firewall_policy_id=fwp_id,
                egress_firewall_policy_id=fwp_id,
                admin_state_up=self.ADMIN_STATE_UP,
                ports=attrs['ports'] if 'ports' in attrs else None,
            ) as firewall_group:
                for k, v in six.iteritems(attrs):
                    self.assertEqual(v, firewall_group['firewall_group'][k])


class TestFirewallPluginBasev2(FirewallPluginV2TestCase):
    def test_create_firewall_group_with_port_on_different_project(self):
        with self.port(tenant_id='fake_project_id_1') as port:
            admin_ctx = context.get_admin_context()
            self._create_firewall_group(
                self.fmt,
                "firewall_group1",
                self.DESCRIPTION,
                context=admin_ctx,
                ports=[port['port']['id']],
                expected_res_status=webob.exc.HTTPConflict.code,
            )

    def test_update_firewall_group_with_port_on_different_project(self):
        ctx = context.Context('not_admin', 'fake_project_id_1')
        with self.firewall_group(ctx=ctx) as firewall_group:
            with self.port(tenant_id='fake_project_id_2') as port:
                data = {
                    'firewall_group': {
                        'ports': [port['port']['id']],
                    },
                }
                req = self.new_update_request(
                    'firewall_groups',
                    data,
                    firewall_group['firewall_group']['id'],
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_firewall_group_with_with_wrong_type_port(self):
        with self.port(device_owner="wrong port type") as port:
            self._create_firewall_group(
                self.fmt,
                "firewall_group1",
                self.DESCRIPTION,
                ports=[port['port']['id']],
                expected_res_status=webob.exc.HTTPConflict.code,
            )

    def test_update_firewall_group_with_with_wrong_type_port(self):
        with self.firewall_group() as firewall_group:
            with self.port(device_owner="wrong port type") as port:
                data = {
                    'firewall_group': {
                        'ports': [port['port']['id']],
                    },
                }
                req = self.new_update_request(
                    'firewall_groups',
                    data,
                    firewall_group['firewall_group']['id'],
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_firewall_group_with_port_already_in_use(self):
        with self.port(
                device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF) as port:
            with self.firewall_group(ports=[port['port']['id']]):
                self._create_firewall_group(
                    self.fmt,
                    "firewall_group2",
                    self.DESCRIPTION,
                    ports=[port['port']['id']],
                    expected_res_status=webob.exc.HTTPConflict.code,
                )

    def test_update_firewall_group_with_port_already_in_use(self):
        with self.port(
                device_owner=nl_constants.DEVICE_OWNER_ROUTER_INTF) as port:
            with self.firewall_group(ports=[port['port']['id']]):
                with self.firewall_group() as firewall_group:
                    data = {
                        'firewall_group': {
                            'ports': [port['port']['id']],
                        },
                    }
                    req = self.new_update_request(
                        'firewall_groups',
                        data,
                        firewall_group['firewall_group']['id'],
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(webob.exc.HTTPConflict.code,
                                     res.status_int)

    def test_firewall_group_policy_rule_can_be_updated(self):
        pending_status = [nl_constants.PENDING_CREATE,
                          nl_constants.PENDING_UPDATE,
                          nl_constants.PENDING_DELETE]

        for status in pending_status:
            with self.firewall_rule() as fwr:
                fwr_id = fwr['firewall_rule']['id']
                with self.firewall_policy(firewall_rules=[fwr_id]) as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    with self.firewall_group(
                            ingress_firewall_policy_id=fwp_id) as fwg:
                        self.plugin.driver.firewall_db.\
                            update_firewall_group_status(
                                context.get_admin_context(),
                                fwg['firewall_group']['id'],
                                status
                            )
                        data = {
                            'firewall_rule': {
                                'name': 'new_name',
                            },
                        }
                        req = self.new_update_request(
                            'firewall_rules',
                            data,
                            fwr_id,
                        )
                        res = req.get_response(self.ext_api)
                        self.assertEqual(webob.exc.HTTPConflict.code,
                                         res.status_int)

    def test_create_firewall_policy_with_other_project_not_shared_rule(self):
        project1_context = self._get_nonadmin_context(tenant_id='project1')
        project2_context = self._get_nonadmin_context(tenant_id='project2')
        with self.firewall_rule(context=project1_context, shared=False) as fwr:
            fwr_id = fwr['firewall_rule']['id']
            self.firewall_policy(
                context=project2_context,
                firewall_rules=[fwr_id],
                expected_res_status=webob.exc.HTTPNotFound.code,
            )

    def test_update_firewall_policy_with_other_project_not_shared_rule(self):
        project1_context = self._get_nonadmin_context(tenant_id='project1')
        project2_context = self._get_nonadmin_context(tenant_id='project2')
        with self.firewall_rule(context=project1_context, shared=False) as fwr:
            with self.firewall_policy(context=project2_context,
                                      shared=False) as fwp:
                fwr_id = fwr['firewall_rule']['id']
                fwp_id = fwp['firewall_policy']['id']
                data = {
                    'firewall_policy': {
                        'firewall_rules': [fwr_id],
                    },
                }
                req = self.new_update_request('firewall_policy', data, fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_firewall_policy_with_other_project_shared_rule(self):
        admin_context = self._get_admin_context()
        project1_context = self._get_nonadmin_context(tenant_id='project1')
        with self.firewall_rule(context=admin_context, shared=True) as fwr:
            fwr_id = fwr['firewall_rule']['id']
            self.firewall_policy(
                context=project1_context,
                firewall_rules=[fwr_id],
                expected_res_status=webob.exc.HTTPOk.code,
            )


class TestAutomaticAssociation(TestFirewallPluginBasev2):
    def setUp(self):
        # TODO(yushiro): Replace constant value for this test class
        # Set auto association fwg
        super(TestAutomaticAssociation, self).setUp()

    def test_vm_port(self):
        port = {
            "id": "fake_port",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vif_details": {"ovs_hybrid_plug": False},
            "project_id": "fake_project",
            "port_security_enabled": True,
        }
        self.plugin._core_plugin.get_port = mock.Mock(return_value=port)
        fake_default_fwg = {
            'id': 'fake_id',
            'name': 'default',
            'ports': ['fake_port_id1'],
        }
        self.plugin.get_firewall_groups = \
            mock.Mock(return_value=[fake_default_fwg])
        self.plugin.update_firewall_group = mock.Mock()
        kwargs = {
            "context": mock.ANY,
            "port": port,
            "original_port": {"binding:vif_type": "unbound"}
        }
        self.plugin.handle_update_port(
            "PORT", "after_update", "test_plugin", **kwargs)
        self.plugin.get_firewall_groups.assert_called_once_with(
            mock.ANY,
            filters={
                'tenant_id': [kwargs['port']['project_id']],
                'name': [fake_default_fwg['name']],
            },
            fields=['id', 'ports'],
        )
        port_ids = fake_default_fwg['ports'] + [kwargs['port']['id']]
        self.plugin.update_firewall_group.assert_called_once_with(
            mock.ANY,
            fake_default_fwg['id'],
            {'firewall_group': {'ports': port_ids}},
        )

    def test_vm_port_not_newly_created(self):
        self.plugin.get_firewall_group = mock.Mock()
        self.plugin.update_firewall_group = mock.Mock()
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
        self.plugin.get_firewall_group.assert_not_called()
        self.plugin.update_firewall_group.assert_not_called()

    def test_not_vm_port(self):
        self.plugin.get_firewall_group = mock.Mock()
        self.plugin.update_firewall_group = mock.Mock()
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
            self.plugin.get_firewall_group.assert_not_called()
            self.plugin.update_firewall_group.assert_not_called()

    def test_set_port_for_default_firewall_group_raised_port_in_use(self):
        port_id = 'fake_port_id_already_associated_to_default_fw'
        port = {
            "id": port_id,
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vif_details": {"ovs_hybrid_plug": False},
            "project_id": "fake_project",
            "port_security_enabled": True,
        }
        self.plugin._core_plugin.get_port = mock.Mock(return_value=port)
        self.plugin.get_firewall_groups = mock.Mock(return_value=[])
        self.plugin.update_firewall_group = mock.Mock(
            side_effect=f_exc.FirewallGroupPortInUse(port_ids=[port_id]))
        kwargs = {
            "context": mock.ANY,
            "port": port,
            "original_port": {"binding:vif_type": "unbound"}
        }
        try:
            self.plugin.handle_update_port("PORT", "after_update",
                                           "test_plugin", **kwargs)
        except f_exc.FirewallGroupPortInUse:
            self.fail("Associating port to default firewall group raises "
                      "'FirewallGroupPortInUse' while it should ignore it")
