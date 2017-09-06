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

import time

from neutron_lib import constants as nl_constants
from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from neutron_fwaas.tests.tempest_plugin.services import v2_client


CONF = config.CONF


class FWaaSClientMixin(object):

    @classmethod
    def resource_setup(cls):
        super(FWaaSClientMixin, cls).resource_setup()
        manager = cls.os_primary
        cls.firewall_groups_client = v2_client.FirewallGroupsClient(
            manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **manager.default_params)
        cls.firewall_policies_client = v2_client.FirewallPoliciesClient(
            manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **manager.default_params)
        cls.firewall_rules_client = v2_client.FirewallRulesClient(
            manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **manager.default_params)

    def create_firewall_rule(self, **kwargs):
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            **kwargs)
        fw_rule = body['firewall_rule']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.firewall_rules_client.delete_firewall_rule,
                        fw_rule['id'])
        return fw_rule

    def create_firewall_policy(self, **kwargs):
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"),
            **kwargs)
        fw_policy = body['firewall_policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.firewall_policies_client.delete_firewall_policy,
                        fw_policy['id'])
        return fw_policy

    def create_firewall_group(self, **kwargs):
        body = self.firewall_groups_client.create_firewall_group(
            name=data_utils.rand_name("fwg"),
            **kwargs)
        fwg = body['firewall_group']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_firewall_group_and_wait,
                        fwg['id'])
        return fwg

    def delete_firewall_group_and_wait(self, firewall_group_id):
        self.firewall_groups_client.delete_firewall_group(firewall_group_id)
        self._wait_firewall_group_while(firewall_group_id,
                                        [nl_constants.PENDING_DELETE],
                                        not_found_ok=True)

    def insert_firewall_rule_in_policy_and_wait(self,
                                                firewall_group_id,
                                                firewall_policy_id,
                                                firewall_rule_id, **kwargs):
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id,
            **kwargs)
        self.addCleanup(
            self._call_and_ignore_exceptions,
            (lib_exc.NotFound, lib_exc.BadRequest),
            self.remove_firewall_rule_from_policy_and_wait,
            firewall_group_id=firewall_group_id,
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        self._wait_firewall_group_ready(firewall_group_id)

    def remove_firewall_rule_from_policy_and_wait(self,
                                                  firewall_group_id,
                                                  firewall_policy_id,
                                                  firewall_rule_id):
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        self._wait_firewall_group_ready(firewall_group_id)

    @staticmethod
    def _call_and_ignore_exceptions(exc_list, func, *args, **kwargs):
        """Call the given function and pass if a given exception is raised."""

        try:
            return func(*args, **kwargs)
        except exc_list:
            pass

    def _wait_firewall_group_ready(self, firewall_group_id):
        self._wait_firewall_group_while(firewall_group_id,
                                        [nl_constants.PENDING_CREATE,
                                        nl_constants.PENDING_UPDATE])

    def _wait_firewall_group_while(self, firewall_group_id, statuses,
        not_found_ok=False):
        start = int(time.time())
        if not_found_ok:
            expected_exceptions = (lib_exc.NotFound)
        else:
            expected_exceptions = ()
        while True:
            try:
                fwg = self.firewall_groups_client.show_firewall_group(
                    firewall_group_id)
            except expected_exceptions:
                break
            status = fwg['firewall_group']['status']
            if status not in statuses:
                break
            if (int(time.time()) - start >=
                self.firewall_groups_client.build_timeout):
                msg = ("Firewall Group %(firewall_group)s failed to reach "
                       "non PENDING status (current %(status)s)") % {
                    "firewall_group": firewall_group_id,
                    "status": status,
                }
                raise exceptions.TimeoutException(msg)
            time.sleep(1)
