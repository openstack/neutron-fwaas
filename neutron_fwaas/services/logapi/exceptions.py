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

from neutron._i18n import _
from neutron_lib import exceptions as n_exc

# TODO(annp or longkb): move to neutron-lib


class FWGIsNotReadyForLogging(n_exc.InvalidInput):
    message = _("Firewall group %(fwg_id)s is not ready for logging "
                "because of %(fwg_status)s status.")


class TargetResourceNotAssociated(n_exc.InvalidInput):
    message = _("Target resource %(target_id)s is not associated with "
                "any firewall group.")


class PortIsNotReadyForLogging(n_exc.InvalidInput):
    message = _("Target resource %(target_id)s is not ready for logging "
                "because of %(port_status)s status.")
