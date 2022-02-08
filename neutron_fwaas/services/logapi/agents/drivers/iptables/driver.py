# Copyright (c) 2018 Fujitsu Limited.
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

from neutron.services.logapi.drivers import base
from neutron.services.logapi.drivers import manager
from neutron_lib.callbacks import resources
from neutron_lib.services.logapi import constants as log_const
from oslo_log import log as logging
from oslo_utils import importutils

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.logapi.common import fwg_callback
from neutron_fwaas.services.logapi.common import port_callback
from neutron_fwaas.services.logapi import constants as fw_const
from neutron_fwaas.services.logapi.rpc import log_server as rpc_server

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_LOGGING_TYPES = [fw_const.FIREWALL_GROUP]


class IptablesLoggingDriver(base.DriverBase):

    @staticmethod
    def create():
        return IptablesLoggingDriver(
            name='iptables',
            vif_types=[],
            vnic_types=[],
            supported_logging_types=SUPPORTED_LOGGING_TYPES,
            requires_rpc=True)


def register():
    """Register iptables-based logging driver for FWaaS."""

    global DRIVER
    if not DRIVER:
        DRIVER = IptablesLoggingDriver.create()
        # Register RPC methods
        if DRIVER.requires_rpc:
            rpc_methods = [
                {resources.PORT: rpc_server.get_fwg_log_info_for_port},
                {log_const.LOG_RESOURCE: rpc_server.
                    get_fwg_log_info_for_log_resources}
            ]
            DRIVER.register_rpc_methods(fw_const.FIREWALL_GROUP, rpc_methods)

    # Trigger fwg validator
    importutils.import_module('neutron_fwaas.services.logapi.fwg_validate')
    # Register resource callback handler
    manager.register(
        fwaas_constants.FIREWALL_GROUP, fwg_callback.FirewallGroupCallBack)
    # Register resource callback handler for Neutron ports
    manager.register(resources.PORT, port_callback.NeutronPortCallBack)

    LOG.debug('FWaaS L3 Logging driver based iptables registered')
