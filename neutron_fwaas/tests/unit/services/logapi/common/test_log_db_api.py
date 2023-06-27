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

from neutron.objects.logapi import logging_resource as log_object
from neutron.objects import ports as port_objects
from neutron.services.logapi.rpc import server as server_rpc
from neutron.tests import base
from neutron_lib import constants as nl_const
from oslo_utils import uuidutils

from neutron_fwaas.services.logapi.common import log_db_api
from neutron_fwaas.services.logapi.rpc import log_server as fwg_rpc

FWG = 'firewall_group'


def _create_log_object(tenant_id, resource_id=None,
                       target_id=None, event='ALL'):

    log_data = {
        'id': uuidutils.generate_uuid(),
        'name': 'fake_log_name',
        'resource_type': FWG,
        'project_id': tenant_id,
        'event': event,
        'enabled': True}
    if resource_id:
        log_data['resource_id'] = resource_id
    if target_id:
        log_data['target_id'] = target_id
    return log_object.Log(**log_data)


def _fake_log_info(id, project_id, ports_id, event='ALL'):
    expected = {
        'id': id,
        'project_id': project_id,
        'ports_log': ports_id,
        'event': event
    }
    return expected


def _fake_port_object(port_id, device_owner, status,
                      project_id=uuidutils.generate_uuid()):
    port_data = {
        'id': port_id,
        'device_owner': device_owner,
        'project_id': project_id
    }
    if status:
        port_data['status'] = status
    return port_data


class LoggingRpcCallbackTestCase(base.BaseTestCase):

    def setUp(self):
        super(LoggingRpcCallbackTestCase, self).setUp()
        self.context = mock.Mock()
        self.rpc_callback = server_rpc.LoggingApiSkeleton()

        log_db_api.fw_plugin_db = mock.Mock()

        self.vm_port = uuidutils.generate_uuid()
        self.router_port = uuidutils.generate_uuid()
        self.fake_vm_port = \
            _fake_port_object(self.vm_port,
                              nl_const.DEVICE_OWNER_COMPUTE_PREFIX,
                              nl_const.PORT_STATUS_ACTIVE)

        self.fake_router_port = \
            _fake_port_object(self.router_port,
                              nl_const.DEVICE_OWNER_ROUTER_INTF,
                              nl_const.PORT_STATUS_ACTIVE)
        self.fake_router_ports = \
            [_fake_port_object(self.router_port, device,
                               nl_const.PORT_STATUS_ACTIVE)
             for device in nl_const.ROUTER_INTERFACE_OWNERS]

    def test_get_fwg_log_info_for_log_resources(self):
        fwg_id = uuidutils.generate_uuid()
        tenant_id = uuidutils.generate_uuid()
        log_obj = _create_log_object(tenant_id, resource_id=fwg_id)

        rpc_call = fwg_rpc.get_fwg_log_info_for_log_resources
        with mock.patch.object(server_rpc, 'get_rpc_method',
                               return_value=rpc_call):
            fake_ports = ['fake_port_1', 'fake_port_2']
            with mock.patch.object(log_db_api, '_get_ports_being_logged',
                                   return_value=fake_ports):
                expected_log_info = [
                    _fake_log_info(log_obj['id'], tenant_id, fake_ports)
                ]

                logs_info = self.rpc_callback.\
                    get_sg_log_info_for_log_resources(self.context,
                                                      resource_type=FWG,
                                                      log_resources=[log_obj])
                self.assertEqual(expected_log_info, logs_info)

    def test_get_fwg_log_info_for_port(self):
        fwg_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        tenant_id = uuidutils.generate_uuid()

        log_obj = _create_log_object(tenant_id, resource_id=fwg_id,
                                     target_id=port_id)

        rpc_call = fwg_rpc.get_fwg_log_info_for_port
        with mock.patch.object(server_rpc, 'get_rpc_method',
                               return_value=rpc_call):
            with mock.patch.object(log_db_api, 'get_logs_for_port',
                                   return_value=[log_obj]):
                fake_ports = [port_id, 'fake_port2']
                with mock.patch.object(log_db_api, '_get_ports_being_logged',
                                       return_value=fake_ports):
                    expected_log_info = [_fake_log_info(log_obj['id'],
                                                        tenant_id,
                                                        fake_ports)]
                    logs_info = self.rpc_callback.\
                        get_sg_log_info_for_port(self.context,
                                                 resource_type=FWG,
                                                 port_id=port_id)
                    self.assertEqual(expected_log_info, logs_info)

    def test_get_ports_being_logged_with_target_id(self):
        tenant_id = uuidutils.generate_uuid()
        fwg_id = uuidutils.generate_uuid()

        # Test with VM port
        log_obj = _create_log_object(tenant_id, resource_id=fwg_id,
                                     target_id=self.vm_port)
        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_vm_port):
            logged_port_ids =  \
                log_db_api._get_ports_being_logged(self.context, log_obj)
            self.assertEqual([], logged_port_ids)

        # Test with router ports
        log_obj = _create_log_object(tenant_id, resource_id=fwg_id,
                                     target_id=self.router_port)

        log_db_api.fw_plugin_db. \
            get_fwg_attached_to_port = mock.Mock(return_value='fwg_id')
        with mock.patch.object(port_objects.Port, 'get_object',
                               side_effect=self.fake_router_ports):

            for port in self.fake_router_ports:
                logged_port_ids = \
                    log_db_api._get_ports_being_logged(self.context, log_obj)
                self.assertEqual([self.router_port], logged_port_ids)

        # Test with inactive router port
        self.fake_router_port['status'] = nl_const.PORT_STATUS_DOWN
        log_obj = _create_log_object(tenant_id, resource_id=fwg_id,
                                     target_id=self.router_port)

        log_db_api.fw_plugin_db. \
            get_fwg_attached_to_port = mock.Mock(return_value='fwg_id')
        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_router_port):
            logged_port_ids = \
                log_db_api._get_ports_being_logged(self.context, log_obj)
            self.assertEqual([], logged_port_ids)

    def test_get_ports_being_logged_with_resource_id(self):
        tenant_id = uuidutils.generate_uuid()
        fwg_id = uuidutils.generate_uuid()
        log_obj = _create_log_object(tenant_id, resource_id=fwg_id)

        log_db_api.fw_plugin_db.get_ports_in_firewall_group = \
            mock.Mock(return_value=[self.vm_port])
        # Test with VM port
        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_vm_port):
            logged_port_ids =  \
                log_db_api._get_ports_being_logged(self.context, log_obj)
            self.assertEqual([], logged_port_ids)

        # Test with router ports
        router_ports = [self.router_port, self.router_port, self.router_port]
        log_db_api.fw_plugin_db. \
            get_ports_in_firewall_group = mock.Mock(return_value=router_ports)
        log_db_api.fw_plugin_db. \
            get_fwg_attached_to_port = mock.Mock(return_value='fwg_id')

        with mock.patch.object(port_objects.Port, 'get_object',
                               side_effect=self.fake_router_ports):
            logged_port_ids = \
                log_db_api._get_ports_being_logged(self.context, log_obj)
            self.assertEqual(router_ports, logged_port_ids)

        # Test with both vm port and router ports
        log_db_api.fw_plugin_db.get_ports_in_firewall_group = \
            mock.Mock(return_value=[self.vm_port, self.router_port])
        log_db_api.fw_plugin_db. \
            get_fwg_attached_to_port = mock.Mock(return_value='fwg_id')

        with mock.patch.object(port_objects.Port, 'get_object',
                               side_effect=[self.fake_vm_port,
                                            self.fake_router_port]):
            logged_port_ids = \
                log_db_api._get_ports_being_logged(self.context, log_obj)
            self.assertEqual([self.router_port], logged_port_ids)

        # Test with inactive router port
        log_db_api.fw_plugin_db.get_ports_in_firewall_group = \
            mock.Mock(return_value=[self.router_port])
        log_db_api.fw_plugin_db. \
            get_fwg_attached_to_port = mock.Mock(return_value='fwg_id')

        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_router_port):
            logged_port_ids = \
                log_db_api._get_ports_being_logged(self.context, log_obj)
            self.assertEqual([self.router_port], logged_port_ids)

    def test_get_ports_being_logged_with_ports_in_tenant(self):
        tenant_id = uuidutils.generate_uuid()
        log_obj = _create_log_object(tenant_id)

        log_db_api.fw_plugin_db.get_fwg_ports_in_tenant = \
            mock.Mock(return_value=[self.router_port])
        log_db_api.fw_plugin_db. \
            get_fwg_attached_to_port = mock.Mock(return_value='fwg_id')

        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_router_port):
            log_db_api._get_ports_being_logged(self.context, log_obj)
            log_db_api.fw_plugin_db.get_fwg_ports_in_tenant.\
                assert_called_with(self.context, tenant_id)

    def test_logs_for_port_with_vm_port(self):
        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_vm_port):
            logs = log_db_api.get_logs_for_port(self.context, self.vm_port)
            self.assertEqual([], logs)

    def test_logs_for_port_with_router_port(self):
        tenant_id = uuidutils.generate_uuid()
        resource_id = uuidutils.generate_uuid()
        target_id = uuidutils.generate_uuid()
        log_db_api.fw_plugin_db.get_fwg_attached_to_port = \
            mock.Mock(side_effect=[[], resource_id, resource_id])
        with mock.patch.object(port_objects.Port, 'get_object',
                               return_value=self.fake_router_port):

            # Test with router port that did not attach to fwg
            logs = log_db_api.get_logs_for_port(self.context, self.router_port)
            self.assertEqual([], logs)

            # Test with router port that attached to fwg
            # Fake log objects that bounds a given port
            log = _create_log_object(tenant_id)
            resource_log = _create_log_object(tenant_id, resource_id)
            target_log = _create_log_object(tenant_id, resource_id, target_id)
            log_objs = [log, target_log, resource_log]

            with mock.patch.object(log_object.Log, 'get_objects',
                                   return_value=log_objs):
                self.fake_router_port = mock.Mock(return_value=target_id)
                logs = log_db_api.get_logs_for_port(self.context,
                                                    self.router_port)
                self.assertEqual(log_objs, logs)

            # Fake log objects that does not bound a given port
            unbound_resource = uuidutils.generate_uuid()
            resource_log = _create_log_object(tenant_id, unbound_resource)
            target_log = _create_log_object(tenant_id, unbound_resource,
                                           target_id)
            log_objs = [log, target_log, resource_log]

            with mock.patch.object(log_object.Log, 'get_objects',
                                   return_value=log_objs):
                self.fake_router_port = mock.Mock(return_value=target_id)
                logs = log_db_api.get_logs_for_port(self.context,
                                                    self.router_port)
                self.assertEqual([log], logs)

    def test_logs_for_fwg(self):
        tenant_id = uuidutils.generate_uuid()
        resource_id = uuidutils.generate_uuid()
        target_id = uuidutils.generate_uuid()

        # Fake log objects that bounds a given fwg
        log = _create_log_object(tenant_id)
        resource_log = _create_log_object(tenant_id, resource_id)
        target_log = _create_log_object(tenant_id, target_id=target_id)
        ports_delta = [target_id]

        # Test with port that in ports_delta
        log_db_api.fw_plugin_db.get_fwg_attached_to_port = \
            mock.Mock(return_value=None)
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[target_log]):
            logs = log_db_api.get_logs_for_fwg(self.context,
                                               resource_id,
                                               ports_delta)
            self.assertEqual([target_log], logs)

        # Test with log that bound to a give fwg
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[resource_log]):
            logs = log_db_api.get_logs_for_fwg(self.context,
                                               resource_id,
                                               ports_delta)
            self.assertEqual([resource_log], logs)

        # Test with log that does not bound to any fwg or port
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[log]):
            logs = log_db_api.get_logs_for_fwg(self.context,
                                               resource_id,
                                               ports_delta)
            self.assertEqual([log], logs)
