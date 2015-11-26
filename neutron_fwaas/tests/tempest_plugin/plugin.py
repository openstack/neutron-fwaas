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

import os

from tempest.test_discover import plugins


class NeutronFWaaSPlugin(plugins.TempestPlugin):
    def get_opt_lists(self):
        return []

    def load_tests(self):
        this_dir = os.path.dirname(os.path.abspath(__file__))
        # top_level_dir = $(this_dir)/../../..
        d = os.path.split(this_dir)[0]
        d = os.path.split(d)[0]
        top_level_dir = os.path.split(d)[0]
        test_dir = os.path.join(top_level_dir,
            'neutron_fwaas/tests/tempest_plugin/tests')
        return (test_dir, top_level_dir)

    def register_opts(self, conf):
        return
