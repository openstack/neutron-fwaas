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

from tempest import config
from tempest.lib.common import ssh
from tempest.lib import exceptions as lib_exc

from neutron_fwaas.tests.tempest_plugin.tests import fwaas_client
from neutron_fwaas.tests.tempest_plugin.tests import fwaas_v2_client
from neutron_fwaas.tests.tempest_plugin.tests.scenario import manager

CONF = config.CONF


class FWaaSScenarioTestBase(object):
    def check_connectivity(self, ip_address, username=None, private_key=None,
                           should_connect=True,
                           check_icmp=True, check_ssh=True,
                           check_reverse_icmp_ip=None,
                           should_reverse_connect=True):
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
                self.assertTrue(should_connect, "Unexpectedly reachable")
                if check_reverse_icmp_ip:
                    cmd = 'ping -c1 -w1 %s' % check_reverse_icmp_ip
                    try:
                        client.exec_command(cmd)
                        self.assertTrue(should_reverse_connect,
                                        "Unexpectedly reachable (reverse)")
                    except lib_exc.SSHExecCommandFailed:
                        if should_reverse_connect:
                            raise
            except lib_exc.SSHTimeout:
                if should_connect:
                    raise


class FWaaSScenarioTest(fwaas_client.FWaaSClientMixin,
                        FWaaSScenarioTestBase,
                        manager.NetworkScenarioTest):
    pass


class FWaaSScenarioTest_V2(fwaas_v2_client.FWaaSClientMixin,
                        FWaaSScenarioTestBase,
                        manager.NetworkScenarioTest):
    pass
