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

import abc


from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

LOG = logging.getLogger(__name__)


def load_and_init_conntrack_driver(*args, **kwargs):
    driver = cfg.CONF.fwaas.conntrack_driver
    try:
        conntrack_driver_cls = runtime.load_class_by_alias_or_classname(
            'neutron.agent.l3.firewall_drivers', driver)
    except ImportError:
        with excutils.save_and_reraise_exception():
            LOG.exception("Driver '%s' not found.", driver)
    conntrack_driver = conntrack_driver_cls()
    conntrack_driver.initialize(*args, **kwargs)
    return conntrack_driver


class ConntrackDriverBase(object, metaclass=abc.ABCMeta):
    """Base Driver for Conntrack"""

    @abc.abstractmethod
    def initialize(self, *args, **kwargs):
        """Initialize the driver"""

    @abc.abstractmethod
    def delete_entries(self, rules, namespace):
        """Delete conntrack entries specified by list of rules"""

    @abc.abstractmethod
    def flush_entries(self, namespace):
        """Delete all conntrack entries within namespace"""
