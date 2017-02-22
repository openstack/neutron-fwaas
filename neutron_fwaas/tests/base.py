# Copyright 2014 OpenStack Foundation.
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
#

import os

from neutron.common import test_lib
from neutron.tests import base as n_base
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin


class BaseTestCase(n_base.BaseTestCase):
    pass


class NeutronDbPluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):

    def setup_config(self):
        # Copied from neutron's test_db_base_plugin_v2 because they
        # don't allow to specify args

        # Create the default configurations
        args = ['--config-file', n_base.etcdir('neutron.conf')]
        # If test_config specifies some config-file, use it, as well
        for config_file in test_lib.test_config.get('config_files', []):
            args.extend(['--config-file', config_file])

        # our own stuff
        dirpath = os.path.join(os.path.dirname(__file__),
                               'etc/neutron/policy.d')
        args.extend(['--config-dir', dirpath])
        self.config_parse(args=args)
