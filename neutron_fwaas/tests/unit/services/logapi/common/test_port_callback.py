# Copyright (c) 2018 Fujitsu Limited
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

from neutron.objects import ports as port_objects
from neutron.services.logapi.drivers import base as log_driver_base
from neutron.services.logapi.drivers import manager as driver_mgr
from neutron.tests import base
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as nl_const
from oslo_utils import uuidutils

from neutron_fwaas.services.logapi.common import log_db_api
from neutron_fwaas.services.logapi.common import port_callback

FAKE_DRIVER = None


class FakeDriver(log_driver_base.DriverBase):

    @staticmethod
    def create():
        return FakeDriver(
            name='fake_driver',
            vif_types=[],
            vnic_types=[],
            supported_logging_types=['firewall_group'],
            requires_rpc=True
        )


def fake_register():
    global FAKE_DRIVER
    if not FAKE_DRIVER:
        FAKE_DRIVER = FakeDriver.create()
    driver_mgr.register(resources.PORT, port_callback.NeutronPortCallBack)


class TestFirewallGroupRuleCallback(base.BaseTestCase):

    def setUp(self):
        super(TestFirewallGroupRuleCallback, self).setUp()
        self.driver_manager = driver_mgr.LoggingServiceDriverManager()
        self.port_callback = port_callback.NeutronPortCallBack(mock.Mock(),
                                                               mock.Mock())
        self.m_context = mock.Mock()

    def _create_port_object(self, name=None, device_owner=None,
                            status=nl_const.PORT_STATUS_ACTIVE):
        port_data = {
            'id': uuidutils.generate_uuid(),
            'project_id': 'fake_tenant_id',
            'status': status
        }
        if name:
            port_data['name'] = name
        if device_owner:
            port_data['device_owner'] = device_owner
        return port_objects.Port(**port_data)

    @mock.patch.object(port_callback.NeutronPortCallBack, 'handle_event')
    def test_handle_event(self, m_port_cb_handler):
        fake_register()
        self.driver_manager.register_driver(FAKE_DRIVER)
        payload = events.DBEventPayload(None)
        registry.publish(resources.PORT, events.AFTER_CREATE, mock.ANY,
                         payload)
        m_port_cb_handler.assert_called_once_with(
            resources.PORT, events.AFTER_CREATE, mock.ANY, payload=payload)

        m_port_cb_handler.reset_mock()
        registry.publish(
            resources.PORT, events.AFTER_UPDATE, mock.ANY, payload)
        m_port_cb_handler.assert_called_once_with(
            resources.PORT, events.AFTER_UPDATE, mock.ANY, payload=payload)

        m_port_cb_handler.reset_mock()
        registry.publish(
            'non_registered_resource', events.AFTER_CREATE, mock.ANY)
        m_port_cb_handler.assert_not_called()

        m_port_cb_handler.reset_mock()
        registry.publish(
            'non_registered_resource', events.AFTER_UPDATE, mock.ANY)
        m_port_cb_handler.assert_not_called()

    def test_trigger_logging(self):
        fake_log_obj = mock.Mock()
        self.port_callback.resource_push_api = mock.Mock()
        port = self._create_port_object(device_owner='fake_device_owner')

        # Test with log resource could be found from DB
        with mock.patch.object(log_db_api, 'get_logs_for_port',
                               return_value=[fake_log_obj]):
            self.port_callback.trigger_logging(self.m_context, port)
            self.port_callback.resource_push_api.assert_called()

        # Test with log resource could not be found from DB
        self.port_callback.resource_push_api.reset_mock()
        with mock.patch.object(log_db_api, 'get_logs_for_port',
                               return_value=[]):
            self.port_callback.trigger_logging(self.m_context, port)
            self.port_callback.resource_push_api.assert_not_called()

    def test_handle_event_with_router_port(self):
        with mock.patch.object(self.port_callback, 'trigger_logging'):
            # Test for router port enabling
            payload = self._fake_port_config(
                nl_const.DEVICE_OWNER_ROUTER_INTF, action='enable')
            self.port_callback.handle_event(mock.ANY,
                                            events.AFTER_UPDATE,
                                            mock.ANY,
                                            payload=payload)
            self.port_callback.trigger_logging.assert_called()

            # Test for router port disabling
            self.port_callback.trigger_logging.reset_mock()
            payload = self._fake_port_config(
                nl_const.DEVICE_OWNER_ROUTER_INTF, action='disable')
            self.port_callback.handle_event(mock.ANY,
                                            events.AFTER_UPDATE,
                                            mock.ANY,
                                            payload=payload)
            self.port_callback.trigger_logging.assert_called()

            # Test for router port status does not change
            self.port_callback.trigger_logging.reset_mock()
            payload = \
                self._fake_port_config(nl_const.DEVICE_OWNER_ROUTER_INTF)
            self.port_callback.handle_event(mock.ANY,
                                            events.AFTER_UPDATE,
                                            mock.ANY,
                                            payload=payload)
            self.port_callback.trigger_logging.assert_not_called()

    def test_handle_event_with_non_router_port(self):
        with mock.patch.object(self.port_callback, 'trigger_logging'):
            # Test for port enabling
            payload = self._fake_port_config('fake_port_type',
                                             action='enable')
            self.port_callback.handle_event(mock.ANY,
                                            events.AFTER_UPDATE,
                                            mock.ANY,
                                            payload=payload)
            self.port_callback.trigger_logging.assert_not_called()

            # Test for port disabling
            self.port_callback.trigger_logging.reset_mock()
            payload = self._fake_port_config('fake_port_type',
                                             action='disable')
            self.port_callback.handle_event(mock.ANY,
                                            events.AFTER_UPDATE,
                                            mock.ANY,
                                            payload=payload)
            self.port_callback.trigger_logging.assert_not_called()

    def _fake_port_config(self, device_owner, action=None):
        if action == 'enable':
            # Create original port with DOWN status
            original_port = self._create_port_object(
                device_owner=device_owner, status=nl_const.PORT_STATUS_DOWN)

            # Create port with ACTIVE status
            port = self._create_port_object(
                device_owner=device_owner, status=nl_const.PORT_STATUS_ACTIVE)
        elif action == 'disable':
            # Create original port with ACTIVE status
            original_port = self._create_port_object(
                device_owner=device_owner, status=nl_const.PORT_STATUS_ACTIVE)

            # Create port with DOWN status
            port = self._create_port_object(
                device_owner=device_owner, status=nl_const.PORT_STATUS_DOWN)
        else:
            # Create original port with ACTIVE status
            original_port = self._create_port_object(
                device_owner=device_owner, status=nl_const.PORT_STATUS_ACTIVE)

            # Create port with ACTIVE status
            port = self._create_port_object(
                device_owner=device_owner, status=nl_const.PORT_STATUS_ACTIVE)
        payload = events.DBEventPayload(self.m_context,
                                        states=[original_port, port])
        return payload
