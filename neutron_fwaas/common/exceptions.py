# Copyright 2018 Fujitsu Limited.
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

from neutron_lib import exceptions as n_exc

from neutron_fwaas._i18n import _


# TODO(annp): migrate to neutron-lib after Queen release
class FirewallGroupPortNotSupported(n_exc.Conflict):
    message = _("Port %(port_id)s is not supported by firewall L2 driver. "
                "This may happen due to incompatible driver combination.")
