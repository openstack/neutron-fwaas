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

from neutron.objects import ports
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators
from neutron_lib import constants as nl_const
from neutron_lib.plugins import directory
from sqlalchemy.orm import exc as orm_exc

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.logapi import constants as log_const
from neutron_fwaas.services.logapi import exceptions as fwg_log_exc

fwg_plugin = None


def _check_fwg(context, fwg_id):
    try:
        fwg = fwg_plugin.get_firewall_group(context, id=fwg_id)
    except orm_exc.NoResultFound:
        raise log_exc.ResourceNotFound(resource_id=fwg_id)

    if fwg['status'] != nl_const.ACTIVE:
        raise fwg_log_exc.FWGIsNotReadyForLogging(
            fwg_id=fwg_id, fwg_status=fwg['status'])


def _check_fwg_port(context, port_id):

    # Checking port exists
    port = ports.Port.get_object(context, id=port_id)
    if not port:
        raise log_exc.TargetResourceNotFound(target_id=port_id)

    device_owner = port.get('device_owner', '')
    # Checking supported firewall group logging for vm port
    if device_owner.startswith(nl_const.DEVICE_OWNER_COMPUTE_PREFIX):
        if not validators.validate_log_type_for_port(
                log_const.FIREWALL_GROUP, port):
            raise log_exc.LoggingTypeNotSupported(
                log_type=log_const.FIREWALL_GROUP,
                port_id=port_id)
    # Checking supported firewall group for router interface, DVR interface,
    # and HA replicated interface
    elif device_owner not in nl_const.ROUTER_INTERFACE_OWNERS:
        raise log_exc.LoggingTypeNotSupported(
            log_type=log_const.FIREWALL_GROUP, port_id=port_id)

    # Checking port status
    port_status = port.get('status')
    if port_status != nl_const.PORT_STATUS_ACTIVE:
        raise fwg_log_exc.PortIsNotReadyForLogging(target_id=port_id,
                                                   port_status=port_status)

    # Checking whether router port or vm port binding with any firewall group
    fwg_id = fwg_plugin.driver.firewall_db.get_fwg_attached_to_port(
        context, port_id=port_id)

    if not fwg_id:
        raise fwg_log_exc.TargetResourceNotAssociated(target_id=port_id)

    fwg = fwg_plugin.get_firewall_group(context, id=fwg_id)

    if fwg['status'] != nl_const.ACTIVE:
        raise fwg_log_exc.FWGIsNotReadyForLogging(fwg_id=fwg_id,
                                                  fwg_status=fwg['status'])


def _check_target_resource_bound_fwg(context, fwg_id, target_id):
    ports = fwg_plugin.driver.firewall_db.get_ports_in_firewall_group(
        context=context, firewall_group_id=fwg_id)
    if target_id not in ports:
        raise log_exc.InvalidResourceConstraint(
            resource=log_const.FIREWALL_GROUP,
            resource_id=fwg_id,
            target_resource=log_const.TARGET_RESOURCE,
            target_id=target_id)


@validators.ResourceValidateRequest.register(log_const.FIREWALL_GROUP)
def validate_firewall_group_request(context, log_data):
    """Validate a log request

    This method validates log request is satisfied or not.

    A ResourceNotFound will be raised if resource_id in log_data not exists or
    a TargetResourceNotFound will be raised if target_id in log_data not
    exists. Beside, FWGIsNotReadyForLogging will be raised in the case of
    queried firewall group is not in ACTIVE state. PortIsNotReadyForLogging
    exception will be raised if port is not in ACTIVE status. Besides,
    TargetResourceNotAssociated exception will be raised if a given port does
    not have any firewall group attach to. This method will also raise a
    LoggingTypeNotSupported, if there is no log_driver supporting for
    resource_type in log_data.

    In addition, if log_data specify both resource_id and target_id. A
    InvalidResourceConstraint will be raised if there is no constraint between
    resource_id and target_id.

    """

    global fwg_plugin
    if not fwg_plugin:
        fwg_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)
    resource_id = log_data.get('resource_id')
    target_id = log_data.get('target_id')
    if resource_id and target_id:
        _check_target_resource_bound_fwg(context, resource_id, target_id)
    if resource_id:
        _check_fwg(context, resource_id)
    if target_id:
        _check_fwg_port(context, target_id)
