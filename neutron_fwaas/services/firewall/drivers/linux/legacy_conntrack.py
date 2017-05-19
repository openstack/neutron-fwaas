# Copyright (c) 2017 Fujitsu Limited
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

from oslo_log import log as logging

from neutron.agent.linux import utils as linux_utils

from neutron_fwaas._i18n import _
from neutron_fwaas.services.firewall.drivers import conntrack_base


LOG = logging.getLogger(__name__)


class ConntrackLegacy(conntrack_base.ConntrackDriverBase):
    def initialize(self, execute=None):
        LOG.debug('Initialize Conntrack Legacy')
        self.execute = execute or linux_utils.execute

    def flush_entries(self, namespace):
        prefixcmd = ['ip', 'netns', 'exec', namespace] if namespace else []
        cmd = prefixcmd + ['conntrack', '-D']
        self._execute_command(cmd)

    def delete_entries(self, rules, namespace):
        for rule in rules:
            cmd = self._get_conntrack_cmd_from_rule(rule, namespace)
            self._execute_command(cmd)

    def _execute_command(self, cmd):
        try:
            self.execute(cmd,
                         run_as_root=True,
                         check_exit_code=True,
                         extra_ok_codes=[1])
        except RuntimeError:
            msg = _("Failed execute conntrack command %s") % cmd
            raise RuntimeError(msg)

    def _get_conntrack_cmd_from_rule(self, rule, namespace):
        prefixcmd = (['ip', 'netns', 'exec', namespace]
                     if namespace else [])
        cmd = ['conntrack', '-D']
        if rule:
            conntrack_filter = self._get_conntrack_filter_from_rule(rule)
            exec_cmd = prefixcmd + cmd + conntrack_filter
        else:
            exec_cmd = prefixcmd + cmd
        return exec_cmd

    def _get_conntrack_filter_from_rule(self, rule):
        """Get conntrack filter from rule

        The key for get conntrack filter is protocol, destination_port
        and source_port. If we want to take more keys, add to the list.
        """
        conntrack_filter = []
        keys = [['-p', 'protocol'], ['-f', 'ip_version'],
                ['--dport', 'destination_port'], ['--sport', 'source_port']]
        for arg_key, rule_key in keys:
            val = rule.get(rule_key)
            if val:
                if rule_key == 'ip_version':
                    conntrack_filter.append(arg_key)
                    conntrack_filter.append('ipv' + str(val))
                else:
                    conntrack_filter.append(arg_key)
                    conntrack_filter.append(val)
        return conntrack_filter
