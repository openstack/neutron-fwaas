# Copyright (c) 2015 Midokura SARL
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

from tempest_lib.common import ssh
from tempest_lib import exceptions as lib_exc

from tempest import config
from tempest.scenario import manager

from neutron_fwaas.tests.tempest_plugin.tests import fwaas_client

CONF = config.CONF


class FWaaSScenarioTest(fwaas_client.FWaaSClientMixin,
                        manager.NetworkScenarioTest):
    _delete_wrapper = manager.NetworkScenarioTest.delete_wrapper

    def check_connectivity(self, ip_address, username=None, private_key=None,
                           should_connect=True,
                           check_icmp=True, check_ssh=True):
        if should_connect:
            msg = "Timed out waiting for %s to become reachable" % ip_address
        else:
            msg = "ip address %s is reachable" % ip_address
        if check_icmp:
            ok = self.ping_ip_address(ip_address,
                                      should_succeed=should_connect)
            self.assertTrue(ok, msg=msg)
        if check_ssh:
            connect_timeout = CONF.validation.connect_timeout
            kwargs = {}
            if not should_connect:
                # Use a shorter timeout for negative case
                kwargs['timeout'] = 1
            try:
                client = ssh.Client(ip_address, username, pkey=private_key,
                                    channel_timeout=connect_timeout,
                                    **kwargs)
                client.test_connection_auth()
            except lib_exc.SSHTimeout:
                if should_connect:
                    raise
