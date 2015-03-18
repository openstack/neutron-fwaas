# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import mock
import sys

from neutron import context as n_context
from neutron.plugins.common import constants
from neutron.tests import base

# Mocking imports of 3rd party cisco library in unit tests and all modules
# that depends on this libary.
with mock.patch.dict(sys.modules, {
    'networking_cisco': mock.Mock(),
    'networking_cisco.plugins': mock.Mock().plugins,
    'networking_cisco.plugins.cisco': mock.Mock().cisco,
    'networking_cisco.plugins.cisco.cfg_agent': mock.Mock().cfg_agent,
    'networking_cisco.plugins.cisco.cfg_agent.device_drivers':
        mock.Mock().device_drivers,
    'networking_cisco.plugins.cisco.cfg_agent.service_helpers':
        mock.Mock().service_helpers,
}):
    from neutron_fwaas.services.firewall.drivers.cisco import (
        csr_firewall_svc_helper)

HOST = 'myhost'
FAKE_FW = {'id': '1234'}
FAKE_FW_STATUS = {
    'fw_id': '1234',
    'acl_id': 'acl123',
    'if_list': []
}


class TestCsrFirewallServiceHelper(base.BaseTestCase):

    def setUp(self):
        super(TestCsrFirewallServiceHelper, self).setUp()

        self.firewall_plugin_api_cls_p = mock.patch(
            'neutron_fwaas.services.firewall.drivers.cisco.'
            'csr_firewall_svc_helper.CsrFirewalllPluginApi')
        self.firewall_plugin_api_cls = self.firewall_plugin_api_cls_p.start()
        self.firewall_plugin_api = mock.Mock()
        self.firewall_plugin_api_cls.return_value = self.firewall_plugin_api
        self.firewall_plugin_api.get_firewalls_for_device = mock.MagicMock()
        self.firewall_plugin_api.get_firewalls_for_tenant = mock.MagicMock()
        self.firewall_plugin_api.get_tenants_with_firewalls = mock.MagicMock()
        self.firewall_plugin_api.firewall_deleted = mock.MagicMock()
        self.firewall_plugin_api.set_firewall_status = mock.MagicMock()
        mock.patch('neutron.common.rpc.create_connection').start()

        self.fw_svc_helper = csr_firewall_svc_helper.CsrFirewallServiceHelper(
            HOST, mock.Mock(), mock.Mock())
        self.fw_svc_helper.acl_driver = mock.Mock()
        self.fw_svc_helper.event_q = mock.Mock()
        self.fw_svc_helper.event_q.enqueue = mock.Mock()

        self.ctx = mock.Mock()

    def _test_firewall_even_enqueue(self, event_name):
        firewall_event = {'event': event_name,
                          'context': self.ctx,
                          'firewall': FAKE_FW,
                          'host': HOST}
        self.fw_svc_helper.event_q.enqueue.assert_called_with(
            'csr_fw_event_q', firewall_event)

    def test_create_firewall(self):
        self.fw_svc_helper.create_firewall(self.ctx, FAKE_FW, HOST)
        self._test_firewall_even_enqueue('FW_EVENT_CREATE')

    def test_update_firewall(self):
        self.fw_svc_helper.update_firewall(self.ctx, FAKE_FW, HOST)
        self._test_firewall_even_enqueue('FW_EVENT_UPDATE')

    def test_delete_firewall(self):
        self.fw_svc_helper.delete_firewall(self.ctx, FAKE_FW, HOST)
        self._test_firewall_even_enqueue('FW_EVENT_DELETE')

    def _test_fullsync(self, firewall_status, function_name):
        self.fw_svc_helper._invoke_firewall_driver = mock.Mock()
        self.fw_svc_helper.fullsync = True
        self.firewall_plugin_api.get_tenants_with_firewalls.return_value = [
            '1']
        firewall = FAKE_FW
        firewall['status'] = firewall_status
        self.firewall_plugin_api.get_firewalls_for_tenant.return_value = [
            firewall]
        ctx_p = mock.patch.object(n_context, 'Context').start()
        ctx_p.return_value = self.ctx
        self.fw_svc_helper.process_service()
        self.fw_svc_helper._invoke_firewall_driver.assert_called_with(
            self.ctx, firewall, function_name)
        self.assertFalse(self.fw_svc_helper.fullsync)

    def test_proc_service_fullsync_firewall_pending_create(self):
        self._test_fullsync('PENDING_CREATE', 'create_firewall')

    def test_proc_service_fullsync_firewall_pending_update(self):
        self._test_fullsync('PENDING_UPDATE', 'update_firewall')

    def test_proc_service_fullsync_frewall_pending_delete(self):
        self._test_fullsync('PENDING_DELETE', 'delete_firewall')

    def _test_proc_service_device_ids(self, firewall_status, function_name):
        self.fw_svc_helper._invoke_firewall_driver = mock.Mock()
        self.fw_svc_helper.fullsync = False
        ctx_p = mock.patch.object(n_context, 'Context').start()
        ctx_p.return_value = self.ctx
        firewall = FAKE_FW
        firewall['status'] = firewall_status
        self.firewall_plugin_api.get_firewalls_for_device.return_value = [
            firewall]
        self.fw_svc_helper.process_service(device_ids=['123'])
        self.fw_svc_helper._invoke_firewall_driver.assert_called_with(
            self.ctx, firewall, function_name)

    def test_proc_service_device_ids_firewall_pending_create(self):
        self._test_proc_service_device_ids(
            'PENDING_CREATE', 'create_firewall')

    def test_proc_service_device_ids_firewall_pending_update(self):
        self._test_proc_service_device_ids(
            'PENDING_UPDATE', 'update_firewall')

    def test_proc_service_device_ids_firewall_pending_delete(self):
        self._test_proc_service_device_ids(
            'PENDING_DELETE', 'delete_firewall')

    def _test_firewall_event(self, event, function_name):
        self.fw_svc_helper._invoke_firewall_driver = mock.Mock()
        self.fw_svc_helper.fullsync = False
        event_data = {'event': event, 'context': self.ctx,
                      'firewall': FAKE_FW, 'host': HOST}
        event_q_returns = [event_data, None]

        def _ev_dequeue_side_effect(*args):
            return event_q_returns.pop(0)

        self.fw_svc_helper.event_q.dequeue = mock.Mock(
            side_effect=_ev_dequeue_side_effect)

        self.fw_svc_helper.process_service()
        self.fw_svc_helper._invoke_firewall_driver.assert_called_once_with(
            self.ctx, FAKE_FW, function_name)

    def test_proc_service_firewall_event_create(self):
        self._test_firewall_event('FW_EVENT_CREATE', 'create_firewall')

    def test_proc_service_firewall_event_update(self):
        self._test_firewall_event('FW_EVENT_UPDATE', 'update_firewall')

    def test_proc_service_firewall_event_delete(self):
        self._test_firewall_event('FW_EVENT_DELETE', 'delete_firewall')

    def test_invoke_firewall_driver_for_delete(self):
        self.fw_svc_helper.acl_driver.delete_firewall = mock.Mock()

        self.fw_svc_helper.acl_driver.delete_firewall.return_value = True
        self.fw_svc_helper._invoke_firewall_driver(
            self.ctx, FAKE_FW, 'delete_firewall')
        self.fw_svc_helper.acl_driver.delete_firewall.assert_called_with(
            None, None, FAKE_FW)
        self.firewall_plugin_api.firewall_deleted.assert_called_with(
            self.ctx, FAKE_FW['id'])

        self.fw_svc_helper.acl_driver.delete_firewall.return_value = False
        self.fw_svc_helper._invoke_firewall_driver(
            self.ctx, FAKE_FW, 'delete_firewall')
        self.firewall_plugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)

    def test_invoke_firewall_driver_for_create(self):
        self.fw_svc_helper.acl_driver.create_firewall = mock.Mock()

        self.fw_svc_helper.acl_driver.create_firewall.return_value = (
            True, FAKE_FW_STATUS)
        self.fw_svc_helper._invoke_firewall_driver(
            self.ctx, FAKE_FW, 'create_firewall')
        self.fw_svc_helper.acl_driver.create_firewall.assert_called_with(
            None, None, FAKE_FW)
        self.firewall_plugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ACTIVE, FAKE_FW_STATUS)

        self.fw_svc_helper.acl_driver.create_firewall.return_value = (
            False, {})
        self.fw_svc_helper._invoke_firewall_driver(
            self.ctx, FAKE_FW, 'create_firewall')
        self.firewall_plugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)

    def test_invoke_firewall_driver_for_update(self):
        self.fw_svc_helper.acl_driver.update_firewall = mock.Mock()

        self.fw_svc_helper.acl_driver.update_firewall.return_value = (
            True, FAKE_FW_STATUS)
        self.fw_svc_helper._invoke_firewall_driver(
            self.ctx, FAKE_FW, 'update_firewall')
        self.fw_svc_helper.acl_driver.update_firewall.assert_called_with(
            None, None, FAKE_FW)
        self.firewall_plugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ACTIVE, FAKE_FW_STATUS)

        self.fw_svc_helper.acl_driver.update_firewall.return_value = (
            False, {})
        self.fw_svc_helper._invoke_firewall_driver(
            self.ctx, FAKE_FW, 'update_firewall')
        self.firewall_plugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)
