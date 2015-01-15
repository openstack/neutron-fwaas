# Copyright 2015 OpenStack Foundation.
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
#

import urllib

from neutron.common import constants as l3_constants
from neutron.openstack.common import log as logging
from vyatta.vrouter import client as vyatta_client

TRUST_ZONE = 'Internal_Trust'
UNTRUST_ZONE = 'External_Untrust'

ZONE_INTERFACE_CMD = 'zone-policy/zone/{0}/interface/{1}'
ZONE_FIREWALL_CMD = 'zone-policy/zone/{0}/from/{1}/firewall/name/{2}'

LOG = logging.getLogger(__name__)


def get_firewall_name(ri, fw):
    """Make firewall name for Vyatta vRouter

    Vyatta vRouter REST API allows firewall name length
    up to 28 characters.
    """
    return fw['id'].replace('-', '')[:28]


def get_trusted_zone_name(ri):
    return TRUST_ZONE


def get_untrusted_zone_name(ri):
    return UNTRUST_ZONE


def get_zone_cmds(rest_api, ri, fw_name):
    """Return zone update commands for Vyatta vRouter.

    Commands chain drops all zone-policy zones and create new zones
    based on internal interfaces and external gateway.
    """
    cmd_list = []

    # Delete the zone policies
    cmd_list.append(vyatta_client.DeleteCmd("zone-policy"))

    # Configure trusted zone
    trusted_zone_name = None
    # Add internal ports to trusted zone
    if l3_constants.INTERFACE_KEY in ri.router:
        trusted_zone_name = urllib.quote_plus(get_trusted_zone_name(ri))
        for port in ri.router[l3_constants.INTERFACE_KEY]:
            eth_if_id = rest_api.get_ethernet_if_id(port['mac_address'])
            cmd_list.append(vyatta_client.SetCmd(
                ZONE_INTERFACE_CMD.format(trusted_zone_name, eth_if_id)))
    # Configure untrusted zone
    untrusted_zone_name = get_untrusted_zone_name(ri)
    if untrusted_zone_name is not None:
        # Add external ports to untrusted zone
        if 'gw_port' in ri.router:
            gw_port = ri.router['gw_port']
            eth_if_id = rest_api.get_ethernet_if_id(gw_port['mac_address'])
            cmd_list.append(vyatta_client.SetCmd(
                ZONE_INTERFACE_CMD.format(untrusted_zone_name, eth_if_id)))

            if trusted_zone_name is not None:
                # Associate firewall to zone
                cmd_list.append(vyatta_client.SetCmd(
                    ZONE_FIREWALL_CMD.format(
                        trusted_zone_name, untrusted_zone_name,
                        urllib.quote_plus(fw_name))))

                cmd_list.append(vyatta_client.SetCmd(
                    ZONE_FIREWALL_CMD.format(
                        untrusted_zone_name, trusted_zone_name,
                        urllib.quote_plus(fw_name))))

    return cmd_list
