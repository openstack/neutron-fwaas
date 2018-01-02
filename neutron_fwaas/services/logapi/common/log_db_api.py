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

from neutron.objects.logapi import logging_resource as log_object
from neutron.objects import ports as port_objects
from neutron_lib import constants as nl_const
from neutron_lib.plugins import directory

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.logapi import constants

fw_plugin_db = None


# TODO(longkb): We will support L2 port. Currently, this method returns only
# router ports.
def _get_ports_being_logged(context, log_obj):
    """Return a list of ports being logged with a given log_obj"""

    target_id = log_obj['target_id']
    resource_id = log_obj['resource_id']

    # If 'target_id' (port_id) is specified in a log_obj
    if target_id:
        fwg_id = fw_plugin_db.get_fwg_attached_to_port(context, target_id)
        if fwg_id:
            port_ids = [target_id]
        else:
            port_ids = []
    # If 'resource_id' (fwg_id) is specified in a log_obj
    elif resource_id:
        port_ids = \
            fw_plugin_db.get_ports_in_firewall_group(context, resource_id)
    # Both 'resource_id' and 'target_id' aren't specified in a log_resource
    else:
        tenant_id = log_obj['project_id']
        port_ids = fw_plugin_db.get_fwg_ports_in_tenant(context, tenant_id)

    filtered_port_ids = []
    for port_id in port_ids:
        port = port_objects.Port.get_object(context, id=port_id)
        device_owner = port.get('device_owner', '')
        # TODO(longkb): L2 ports will be supported in the future
        # Check whether a port is router port or not.
        if device_owner in nl_const.ROUTER_INTERFACE_OWNERS:
            # Check whether a port is attached to firewall group or not
            fwg = fw_plugin_db.get_fwg_attached_to_port(context, port_id)
            if fwg:
                filtered_port_ids.append(port_id)
    return filtered_port_ids


def _make_log_info_dict(log_obj, port_ids):
    log_info = {
        'id': log_obj['id'],
        'ports_log': port_ids,
        'event': log_obj['event'],
        'project_id': log_obj['project_id']
    }
    return log_info


def get_logs_for_port(context, port_id):
    """Return a list of log_resources bound to a given port_id"""

    logs_bounded = []
    port = port_objects.Port.get_object(context, id=port_id)

    if not port:
        return logs_bounded
    # Ignore if a given port_id is not belong to router port
    device_owner = port.get('device_owner', '')
    if device_owner not in nl_const.ROUTER_INTERFACE_OWNERS:
        return logs_bounded

    # Ignore if a given port does not attach to any fwg
    fwg_id = fw_plugin_db.get_fwg_attached_to_port(context, port_id)
    if not fwg_id:
        return logs_bounded

    project_id = port['project_id']
    log_objs = log_object.Log.get_objects(
        context, project_id=project_id,
        resource_type=constants.FIREWALL_GROUP, enabled=True)

    for log_obj in log_objs:
        if log_obj.resource_id == fwg_id:
            logs_bounded.append(log_obj)
        elif log_obj.target_id == port['id']:
            logs_bounded.append(log_obj)
        elif not log_obj.target_id and not log_obj.resource_id:
            logs_bounded.append(log_obj)
    return logs_bounded


def get_logs_for_fwg(context, fwg_id, ports_delta):
    """Return a list of log_resources bound to a firewall group"""

    global fw_plugin_db
    if not fw_plugin_db:
        fw_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)

        # NOTE(longkb): check whether fw plugin was loaded or not.
        if not fw_plugin:
            return []
        fw_plugin_db = fw_plugin.driver.firewall_db

    project_id = context.tenant_id
    log_objs = log_object.Log.get_objects(
        context, project_id=project_id,
        resource_type=constants.FIREWALL_GROUP, enabled=True)

    log_resources = []
    for log_obj in log_objs:
        if log_obj.resource_id == fwg_id:
            log_resources.append(log_obj)
        elif log_obj.target_id in ports_delta:
            log_resources.append(log_obj)
        elif not log_obj.resource_id and not log_obj.target_id:
            log_resources.append(log_obj)
    return log_resources


def get_fwg_log_info_for_port(context, port_ids):
    """Return a list of firewall group log info for a given port
    The list has format as below:

        [
            {
                'event': u'ALL',
                'id': '733e0499-e69e-4106-a84a-635fbc5fbbc0',
                'project_id': u'46f70361-ba71-4bd0-9769-3573fd227c4b',
                'ports_log':
                    [
                        port1_id,
                        port2_id,
                    ]
            },
        ]
    :param context: current running context information
    :param port_ids: list of ports which needed to get firewall group log info

    """

    global fw_plugin_db
    if not fw_plugin_db:
        fw_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)

        # NOTE(longkb): check whether fw plugin was loaded or not.
        if not fw_plugin:
            return []
        fw_plugin_db = fw_plugin.driver.firewall_db

    logs_info = []
    log_bounds = set()
    for port_id in port_ids:
        log_objs = get_logs_for_port(context, port_id)
        if log_objs:
            log_bounds |= set(log_objs)
    if log_bounds:
        for log_resource in log_bounds:
            port_ids = _get_ports_being_logged(context, log_resource)
            log_info = _make_log_info_dict(log_resource, port_ids)
            logs_info.append(log_info)
    return logs_info


def get_fwg_log_info_for_log_resources(context, log_resources):
    """Return a list of firewall group log info for list of log_resources
    The list has format as below:

        [
            {
                'event': u'ALL',
                'id': '733e0499-e69e-4106-a84a-635fbc5fbbc0',
                'project_id': u'46f70361-ba71-4bd0-9769-3573fd227c4b',
                'ports_log':
                    [
                        port1_id,
                        port2_id,
                    ]
            },
        ]
    :param context: current running context information
    :param log_resources: list of log_resources, which needed to get firewall
                          groups log info

    """

    global fw_plugin_db
    if not fw_plugin_db:
        fw_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)

        # NOTE(longkb): check whether fw plugin was loaded or not.
        if not fw_plugin:
            return []
        fw_plugin_db = fw_plugin.driver.firewall_db

    logs_info = []
    for log_resource in log_resources:
        ports_id = _get_ports_being_logged(context, log_resource)
        log_info = _make_log_info_dict(log_resource, ports_id)
        logs_info.append(log_info)

    return logs_info
