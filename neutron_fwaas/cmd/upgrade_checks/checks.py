# Copyright 2019 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.utils import upgrade_checks as base_checks
from oslo_config import cfg
from oslo_upgradecheck import upgradecheck

from neutron_fwaas._i18n import _


class Checks(base_checks.BaseChecks):

    def get_checks(self):
        return [
            (_("Check FWaaS v1"), self.fwaas_v1_check)
        ]

    @staticmethod
    def fwaas_v1_check(checker):
        fwaas_v1_names = [
            'firewall',
            'neutron_fwaas.services.firewall.fwaas_plugin:FirewallPlugin']
        for name in fwaas_v1_names:
            if name in cfg.CONF.service_plugins:
                return upgradecheck.Result(
                    upgradecheck.Code.FAILURE,
                    _("FWaaS v1 is removed. "
                      "FWaaS v2 should be used instead."))
        return upgradecheck.Result(upgradecheck.Code.SUCCESS)
