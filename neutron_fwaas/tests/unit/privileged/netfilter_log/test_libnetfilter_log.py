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

import socket

import cffi
import mock
from neutron.tests import base
from oslo_utils import importutils
import testtools

# mock for dlopen
cffi.FFI = mock.Mock()
cffi.FFI.dlopen = mock.Mock(return_value=mock.Mock())
lib_log = importutils.import_module(
    'neutron_fwaas.privileged.netfilter_log.libnetfilter_log'
)


class NFLogAppTestCase(base.BaseTestCase):

    def setUp(self):

        self.nflog_app = lib_log.NFLogApp()
        self.spawn = mock.patch('eventlet.spawn').start()
        super(NFLogAppTestCase, self).setUp()

    def test_register_packet_handler(self):
        def fake_method():
            pass
        self.nflog_app.register_packet_handler(fake_method)
        self.assertEqual(fake_method, self.nflog_app.callback)

    def test_unregister_packet_handler(self):
        def fake_method():
            pass
        self.nflog_app.register_packet_handler(fake_method)
        self.assertEqual(fake_method, self.nflog_app.callback)
        self.nflog_app.unregister_packet_handler()
        self.assertIsNone(self.nflog_app.callback)


class NFLogWrapper(base.BaseTestCase):

    def setUp(self):
        super(NFLogWrapper, self).setUp()
        lib_log.libnflog = mock.Mock()
        lib_log.ffi = mock.Mock()

    def test_open_failed(self):
        lib_log.libnflog.nflog_open.return_value = None
        handle = lib_log.NFLogWrapper.get_instance()
        with testtools.ExpectedException(Exception):
            handle.open()
            lib_log.libnflog.nflog_open.assert_called_once_with()
            lib_log.libnflog.nflog_unbind_pf.assert_not_called()
            lib_log.libnflog.nflog_bind_pf.assert_not_called()
            handle.close()

    def test_bind_pf(self):
        nflog_handle = mock.Mock()
        lib_log.libnflog.nflog_open.return_value = nflog_handle
        handle = lib_log.NFLogWrapper.get_instance()
        handle.open()
        lib_log.libnflog.nflog_open.assert_called_once_with()
        calls = [mock.call(nflog_handle, socket.AF_INET),
                 mock.call(nflog_handle, socket.AF_INET6)]
        lib_log.libnflog.nflog_unbind_pf.assert_has_calls(
            calls, any_order=True)
        lib_log.libnflog.nflog_bind_pf.assert_has_calls(
            calls, any_order=True)

    def test_bind_group_set_mode_failed(self):
        nflog_handle = mock.Mock()
        g_handle = mock.Mock()
        lib_log.libnflog.nflog_open.return_value = nflog_handle
        lib_log.libnflog.nflog_bind_group.return_value = g_handle
        lib_log.libnflog.nflog_set_mode.return_value = -1
        handle = lib_log.NFLogWrapper.get_instance()
        with testtools.ExpectedException(Exception):
            handle.open()
            handle.bind_group(0)
            lib_log.libnflog.nflog_open.assert_called_once_with()
            lib_log.libnflog.nflog_bind_group.assert_called_once_with(
                nflog_handle, 0)
            lib_log.libnflog.nflog_set_mode.assert_called_once_with(
                g_handle, 0x2, 0xffff)
            lib_log.libnflog.nflog_callback_register.assert_not_called()

    def test_bind_group_set_callback_failed(self):
        nflog_handle = mock.Mock()
        g_handle = mock.Mock()
        lib_log.libnflog.nflog_open.return_value = nflog_handle
        lib_log.libnflog.nflog_bind_group.return_value = g_handle
        lib_log.libnflog.nflog_set_mode.return_value = 0
        lib_log.libnflog.nflog_callback_register.return_value = -1
        handle = lib_log.NFLogWrapper.get_instance()
        with testtools.ExpectedException(Exception):
            handle.open()
            handle.bind_group(0)
            lib_log.libnflog.nflog_open.assert_called_once_with()
            lib_log.libnflog.nflog_bind_group.assert_called_once_with(
                nflog_handle, 0)
            lib_log.libnflog.nflog_set_mode.assert_called_once_with(
                g_handle, 0x2, 0xffff)
            lib_log.libnflog.nflog_callback_register.assert_called_once_with(
                g_handle, handle.cb, lib_log.ffi.NULL)

    def test_bind_group_pass(self):
        nflog_handle = mock.Mock()
        g_handle = mock.Mock()
        lib_log.libnflog.nflog_open.return_value = nflog_handle
        lib_log.libnflog.nflog_bind_group.return_value = g_handle
        lib_log.libnflog.nflog_set_mode.return_value = 0
        lib_log.libnflog.nflog_callback_register.return_value = 0
        handle = lib_log.NFLogWrapper.get_instance()
        handle.open()
        handle.bind_group(0)
        lib_log.libnflog.nflog_open.assert_called_once_with()
        lib_log.libnflog.nflog_bind_group.assert_called_once_with(
            nflog_handle, 0)
        lib_log.libnflog.nflog_set_mode.assert_called_once_with(
            g_handle, 0x2, 0xffff)
        lib_log.libnflog.nflog_callback_register.assert_called_once_with(
            g_handle, handle.cb, lib_log.ffi.NULL)
