# Copyright 2015 Cisco Systems Inc.
# All rights reserved.
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

from neutron_lib.api import extensions
from neutron_lib import constants
from neutron_lib import exceptions as nexception

from neutron_fwaas._i18n import _


class FirewallRouterInUse(nexception.InUse):
    message = _("Router(s) %(router_ids)s provided already associated with "
                "other Firewall(s). ")


EXTENDED_ATTRIBUTES_2_0 = {
    'firewalls': {
        'router_ids': {'allow_post': True, 'allow_put': True,
            'validate': {'type:uuid_list': None},
            'is_visible': True, 'default': constants.ATTR_NOT_SPECIFIED},
    }
}


class Firewallrouterinsertion(extensions.ExtensionDescriptor):
    """Extension class supporting Firewall and Router(s) association.

    The extension enables providing an option to specify router-ids of
    routers where the firewall is to be installed. This is supported in
    a manner so that the older version of the API continues to be supported.
    On a CREATE, if the router_ids option is not specified then the firewall
    is installed on all routers on the tenant. If the router-ids option is
    provided with a list of routers then the firewall is installed on the
    specified routers. If the router-ids option is provided with an empty
    list then the firewall is created but put in an INACTIVE state to reflect
    that no routers are associated. This firewall can be updated with a list
    of routers which will then drive the state to ACTIVE after the agent
    installs and acks back. UPDATE also supports the option in a similar
    manner. If the router_ids option is not provided, then there is no change
    to the existing association with the routers. When the router_is option is
    provided with a list of routers or an empty list - this drives the new
    set of routers that the firewall is associated with.
    """
    @classmethod
    def get_name(cls):
        return "Firewall Router insertion"

    @classmethod
    def get_alias(cls):
        return "fwaasrouterinsertion"

    @classmethod
    def get_description(cls):
        return "Firewall Router insertion on specified set of routers"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/ext/neutron/fwaasrouterinsertion"
            "/api/v1.0")

    @classmethod
    def get_updated(cls):
        return "2015-01-27T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
