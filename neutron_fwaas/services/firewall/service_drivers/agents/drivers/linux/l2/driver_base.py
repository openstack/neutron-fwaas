# Copyright (C) 2017 Fujitsu Limited
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

import abc
import contextlib

import six


@six.add_metaclass(abc.ABCMeta)
class FirewallL2DriverBase(object):
    """Abstract firewall L2 driver base"""

    def __init__(self, integration_bridge, sg_enabled=False):
        pass

    def filter_defer_apply_on(self):
        """Defer application of filtering rule."""
        pass

    def filter_defer_apply_off(self):
        """Turn off deferral of rules and apply the rules now."""
        pass

    @property
    def ports(self):
        """Returns filtered ports."""
        pass

    @contextlib.contextmanager
    def defer_apply(self):
        """Defer apply context."""
        self.filter_defer_apply_on()
        try:
            yield
        finally:
            self.filter_defer_apply_off()

    def create_firewall_group(self, ports, firewall_group):
        """Called when a firewall group is created.
        """
        raise NotImplementedError()

    def update_firewall_group(self, ports, firewall_group):
        """Called when a firewall group is updated.
        """
        raise NotImplementedError()

    def delete_firewall_group(self, ports, firewall_group):
        """Called when a firewall group is deleted.
        """
        raise NotImplementedError()
