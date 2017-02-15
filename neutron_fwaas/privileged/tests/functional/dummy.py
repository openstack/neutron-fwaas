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

from oslo_utils import uuidutils
from pyroute2 import netns as pynetns

from neutron_fwaas import privileged


# TODO(cby): move this method in neutron.tests.functional.privileged associated
# to a new privsep context.
@privileged.default.entrypoint
def dummy():
    """This method aim is to validate that we can use privsep in functests."""
    namespace = 'dummy-%s' % uuidutils.generate_uuid()
    pynetns.create(namespace)
    pynetns.remove(namespace)
