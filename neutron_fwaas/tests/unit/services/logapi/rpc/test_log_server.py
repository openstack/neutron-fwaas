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

from neutron.services.logapi.rpc import server as server_rpc
from neutron.tests import base

from neutron_fwaas.services.logapi.rpc import log_server as fw_server_rpc


class FWGLoggingApiSkeletonTestCase(base.BaseTestCase):
    @mock.patch("neutron_fwaas.services.logapi.common.log_db_api."
                "get_fwg_log_info_for_port")
    def test_get_fwg_log_info_for_port(self, mock_callback):
        with mock.patch.object(
                server_rpc,
                'get_rpc_method',
                return_value=fw_server_rpc.get_fwg_log_info_for_port
        ):
            test_obj = server_rpc.LoggingApiSkeleton()
            m_context = mock.Mock()
            port_id = '123'
            test_obj.get_sg_log_info_for_port(m_context,
                                              resource_type='firewall_v2',
                                              port_id=port_id)
            mock_callback.assert_called_with(m_context, port_id)

    @mock.patch("neutron_fwaas.services.logapi.common.log_db_api."
                "get_fwg_log_info_for_log_resources")
    def test_get_fwg_log_info_for_log_resources(self, mock_callback):
        with mock.patch.object(
                server_rpc,
                'get_rpc_method',
                return_value=fw_server_rpc.get_fwg_log_info_for_log_resources
        ):
            test_obj = server_rpc.LoggingApiSkeleton()
            m_context = mock.Mock()
            log_resources = [mock.Mock()]
            test_obj.get_sg_log_info_for_log_resources(
                m_context,
                resource_type='firewall_v2',
                log_resources=log_resources)
            mock_callback.assert_called_with(m_context, log_resources)
