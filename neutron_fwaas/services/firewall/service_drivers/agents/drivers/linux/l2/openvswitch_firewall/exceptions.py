# Copyright 2016, Red Hat, Inc.
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

from neutron_lib import exceptions

from neutron_fwaas._i18n import _


class OVSFWaaSPortNotFound(exceptions.NeutronException):
    message = _("Port %(port_id)s is not managed by this agent.")


class OVSFWaaSTagNotFound(exceptions.NeutronException):
    message = _("Cannot get vlan tag for port %(port_id)s.")