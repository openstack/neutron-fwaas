# Copyright (c) 2017 Thales Services SAS
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

import pyroute2

from neutron_fwaas import privileged
from neutron_fwaas.privileged import utils


def _get_ifname(link):
    attr_dict = dict(link['attrs'])
    return attr_dict['IFLA_IFNAME']


def list_interface_names():
    iproute = pyroute2.IPRoute()
    result = iproute.get_links()
    return [_get_ifname(link) for link in result]


@privileged.default.entrypoint
def get_in_namespace_interfaces(namespace):
    before = list_interface_names()
    with utils.in_namespace(namespace):
        inside = list_interface_names()
    after = list_interface_names()
    return before, inside, after
