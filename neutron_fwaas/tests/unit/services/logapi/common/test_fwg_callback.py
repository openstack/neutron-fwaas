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
from neutron_lib import constants as nl_const

from neutron_fwaas.common import fwaas_constants as fw_const
from neutron_fwaas.services.logapi.common import fwg_callback
from neutron_fwaas.services.logapi.common import log_db_api

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
    driver_mgr.register(fw_const.FIREWALL_GROUP,
                        fwg_callback.FirewallGroupCallBack)


class TestFirewallGroupRuleCallback(base.BaseTestCase):

    def setUp(self):
        super(TestFirewallGroupRuleCallback, self).setUp()
        self.driver_manager = driver_mgr.LoggingServiceDriverManager()
        self.fwg_callback = fwg_callback.FirewallGroupCallBack(mock.Mock(),
                                                               mock.Mock())
        self.m_context = mock.Mock()

    @mock.patch.object(fwg_callback.FirewallGroupCallBack, 'handle_event')
    def test_handle_event(self, mock_fwg_cb):
        fake_register()
        self.driver_manager.register_driver(FAKE_DRIVER)

        registry.publish(
            fw_const.FIREWALL_GROUP, events.AFTER_CREATE, mock.ANY)
        mock_fwg_cb.assert_called_once_with(
            fw_const.FIREWALL_GROUP, events.AFTER_CREATE, mock.ANY,
            payload=None)

        mock_fwg_cb.reset_mock()
        registry.publish(
            fw_const.FIREWALL_GROUP, events.AFTER_UPDATE, mock.ANY)
        mock_fwg_cb.assert_called_once_with(
            fw_const.FIREWALL_GROUP, events.AFTER_UPDATE, mock.ANY,
            payload=None)

        mock_fwg_cb.reset_mock()
        registry.publish(
            'non_registered_resource', events.AFTER_CREATE, mock.ANY)
        mock_fwg_cb.assert_not_called()

        mock_fwg_cb.reset_mock()
        registry.publish(
            'non_registered_resource', events.AFTER_UPDATE, mock.ANY)
        mock_fwg_cb.assert_not_called()

    def test_need_to_notify(self):
        port_objects.Port.get_object = \
            mock.Mock(side_effect=self._get_object_side_effect)

        # Test with router devices
        for device in nl_const.ROUTER_INTERFACE_OWNERS:
            result = self.fwg_callback.need_to_notify(self.m_context, [device])
            self.assertEqual(True, result)
        # Test with non-router device
        result = self.fwg_callback.need_to_notify(self.m_context,
                                                  ['fake_port'])
        self.assertEqual(False, result)

        # Test with ports_delta is empty
        result = self.fwg_callback.need_to_notify(self.m_context, [])
        self.assertEqual(False, result)

    def test_trigger_logging(self):
        m_payload = mock.Mock()
        self.fwg_callback.resource_push_api = mock.Mock()
        m_payload.resource_id = 'fake_resource_id'
        ports_delta = ['fake_port_id']

        # Test with log resource could be found from DB
        with mock.patch.object(log_db_api, 'get_logs_for_fwg',
                               return_value={'fake': 'fake'}):
            self.fwg_callback.trigger_logging(self.m_context,
                                              m_payload.resource_id,
                                              ports_delta)
            self.fwg_callback.resource_push_api.assert_called()

        # Test with log resource could not be found from DB
        self.fwg_callback.resource_push_api.reset_mock()
        with mock.patch.object(log_db_api, 'get_logs_for_fwg',
                               return_value={}):
            self.fwg_callback.trigger_logging(self.m_context,
                                              m_payload.resource_id,
                                              ports_delta)
            self.fwg_callback.resource_push_api.assert_not_called()

    def _get_object_side_effect(self, context, id):
        fake_port = {
            'id': 'fake_id',
            'device_owner': id,
        }
        return fake_port

    def test_handle_event_with_router_port(self):
        with mock.patch.object(self.fwg_callback, 'need_to_notify',
                               return_value=True):
            with mock.patch.object(self.fwg_callback, 'trigger_logging'):
                # Test for firewall group creation with router port
                m_payload = self._mock_payload(events.AFTER_CREATE,
                                               'fake_port_id')
                self.fwg_callback.handle_event(mock.ANY,
                                               events.AFTER_CREATE,
                                               mock.ANY,
                                               **{'payload': m_payload})
                self.fwg_callback.trigger_logging.assert_called()

                # Test for firewall group update with router port
                self.fwg_callback.trigger_logging.reset_mock()
                m_payload = self._mock_payload(events.AFTER_UPDATE,
                                               'fake_port_id')
                self.fwg_callback.handle_event(mock.ANY,
                                               events.AFTER_UPDATE,
                                               mock.ANY,
                                               **{'payload': m_payload})
                self.fwg_callback.trigger_logging.assert_called()

    def test_handle_event_with_non_router_port(self):
        with mock.patch.object(self.fwg_callback, 'need_to_notify',
                               return_value=False):
            with mock.patch.object(self.fwg_callback, 'trigger_logging'):

                # Test for firewall group creation with non router ports
                m_payload = self._mock_payload(events.AFTER_CREATE,
                                               'fake_port_id')
                self.fwg_callback.handle_event(mock.ANY,
                                               events.AFTER_CREATE,
                                               mock.ANY,
                                               **{'payload': m_payload})
                self.fwg_callback.trigger_logging.assert_not_called()

                # Test for firewall group creation without ports
                self.fwg_callback.trigger_logging.reset_mock()
                m_payload = self._mock_payload(events.AFTER_CREATE)
                self.fwg_callback.handle_event(mock.ANY,
                                               events.AFTER_CREATE,
                                               mock.ANY,
                                               **{'payload': m_payload})
                self.fwg_callback.trigger_logging.assert_not_called()

                # Test for firewall group update with non router ports
                self.fwg_callback.trigger_logging.reset_mock()
                m_payload = self._mock_payload(events.AFTER_UPDATE,
                                               'fake_port_id')
                self.fwg_callback.handle_event(mock.ANY,
                                               events.AFTER_UPDATE,
                                               mock.ANY,
                                               **{'payload': m_payload})
                self.fwg_callback.trigger_logging.assert_not_called()

                # Test for firewall group update without ports
                self.fwg_callback.trigger_logging.reset_mock()
                m_payload = self._mock_payload(events.AFTER_UPDATE)
                self.fwg_callback.handle_event(mock.ANY,
                                               events.AFTER_UPDATE,
                                               mock.ANY,
                                               **{'payload': m_payload})
                self.fwg_callback.trigger_logging.assert_not_called()

    def _mock_payload(self, event, ports_delta=None):
        m_payload = mock.Mock()
        m_payload.context = self.m_context
        if event == events.AFTER_CREATE:
            if ports_delta:
                m_payload.latest_state = {
                    'ports': [ports_delta]
                }
            else:
                m_payload.latest_state = {
                    'ports': []
                }
        if event == events.AFTER_UPDATE:
            if ports_delta:
                m_payload.states = [
                    {'ports': [ports_delta]},
                    {'ports': []}
                ]
            else:
                m_payload.states = [
                    {'ports': []},
                    {'ports': []}
                ]
        return m_payload
