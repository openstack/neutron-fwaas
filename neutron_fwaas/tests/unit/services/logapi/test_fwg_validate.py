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

import mock
from neutron.objects import ports
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators
from neutron.tests import base
from neutron_lib import constants as nl_const
from sqlalchemy.orm import exc as orm_exc

from neutron_fwaas.services.logapi import exceptions as fwg_log_exc
from neutron_fwaas.services.logapi import fwg_validate


class TestFWGLogRequestValidations(base.BaseTestCase):
    """Test validator for a log creation request"""

    def setUp(self):
        super(TestFWGLogRequestValidations, self).setUp()
        fwg_validate.fwg_plugin = mock.Mock()
        fwg_validate.fwg_plugin.driver = mock.Mock()
        fwg_validate.fwg_plugin.driver.firewall_db = mock.Mock()

    def test_validate_fwg_request(self):
        m_context = mock.Mock()
        fake_data = {
            'resource_type': 'firewall_group',
            'resource_id': 'fake_fwg_id'
        }
        with mock.patch.object(fwg_validate, '_check_fwg'):
            fwg_validate.validate_firewall_group_request(m_context, fake_data)
            fwg_validate._check_fwg.\
                assert_called_with(m_context, fake_data['resource_id'])
        fake_data = {
            'resource_type': 'firewall_group',
            'resource_id': 'fake_fwg_id',
            'target_id': 'fake_port_id'
        }
        with mock.patch.object(fwg_validate,
                               '_check_target_resource_bound_fwg'):
            with mock.patch.object(fwg_validate, '_check_fwg'):
                with mock.patch.object(fwg_validate, '_check_fwg_port'):
                    fwg_validate.validate_firewall_group_request(m_context,
                                                                 fake_data)
                    fwg_validate._check_target_resource_bound_fwg.\
                        assert_called_with(m_context,
                                           fake_data['resource_id'],
                                           fake_data['target_id'])
                    fwg_validate._check_fwg. \
                        assert_called_with(m_context,
                                           fake_data['resource_id'])
                    fwg_validate._check_fwg_port. \
                        assert_called_with(m_context,
                                           fake_data['target_id'])

    def test_validate_request_fwg_id_not_exists(self):

        with mock.patch.object(fwg_validate.fwg_plugin, 'get_firewall_group',
                               side_effect=orm_exc.NoResultFound):
            self.assertRaises(
                log_exc.ResourceNotFound,
                fwg_validate._check_fwg,
                mock.ANY,
                'fake_fwg_id')

    def test_validate_request_fwg_not_active(self):
        fake_fwg = {'id': '1234', 'status': 'PENDING'}
        with mock.patch.object(fwg_validate.fwg_plugin, 'get_firewall_group',
                               return_value=fake_fwg):
            self.assertRaises(
                fwg_log_exc.FWGIsNotReadyForLogging,
                fwg_validate._check_fwg,
                mock.ANY,
                'fake_fwg_id')

    def test_validate_request_router_or_port_id_not_exists(self):
        with mock.patch.object(ports.Port, 'get_object', return_value=None):
            self.assertRaises(
                log_exc.TargetResourceNotFound,
                fwg_validate._check_fwg_port,
                mock.ANY,
                'fake_port_id')

    def test_validate_request_unsupported_fwg_log_on_vm_port(self):

        fake_port = {'device_owner': "compute:"}
        with mock.patch.object(ports.Port, 'get_object',
                               return_value=fake_port):
            with mock.patch.object(validators, 'validate_log_type_for_port',
                                   return_value=False):
                self.assertRaises(
                    log_exc.LoggingTypeNotSupported,
                    fwg_validate._check_fwg_port,
                    mock.ANY,
                    'fake_port_id')

    def test_validate_request_router_port_is_not_active(self):

        non_active_status = [nl_const.PORT_STATUS_DOWN,
                             nl_const.PORT_STATUS_ERROR,
                             nl_const.PORT_STATUS_NOTAPPLICABLE,
                             nl_const.PORT_STATUS_BUILD]
        fake_port = [{'device_owner': nl_const.DEVICE_OWNER_ROUTER_INTF,
                     'status': status}
                     for status in non_active_status]
        with mock.patch.object(ports.Port, 'get_object',
                               side_effect=fake_port):
            for status in non_active_status:
                self.assertRaises(
                    fwg_log_exc.PortIsNotReadyForLogging,
                    fwg_validate._check_fwg_port,
                    mock.ANY,
                    'fake_port_id')

    def test_validate_request_router_port_was_not_associated_fwg(self):

        fake_port = {'device_owner': nl_const.DEVICE_OWNER_ROUTER_INTF,
                     'status': nl_const.PORT_STATUS_ACTIVE}

        with mock.patch.object(ports.Port, 'get_object',
                               return_value=fake_port):
            with mock.patch.object(fwg_validate.fwg_plugin.driver.firewall_db,
                                   'get_fwg_attached_to_port',
                                   return_value=None):
                self.assertRaises(
                    fwg_log_exc.TargetResourceNotAssociated,
                    fwg_validate._check_fwg_port,
                    mock.ANY,
                    'fake_port_id')

    def test_validate_request_target_resource_not_bound_fwg(self):

        fake_ports_in_fwg = ['fake_port_id1, fake_port_id2']
        with mock.patch.object(
                fwg_validate.fwg_plugin.driver.firewall_db,
                'get_ports_in_firewall_group',
                return_value=fake_ports_in_fwg):

            self.assertRaises(
                log_exc.InvalidResourceConstraint,
                fwg_validate._check_target_resource_bound_fwg,
                mock.ANY,
                mock.ANY,
                'fake_target_id')
