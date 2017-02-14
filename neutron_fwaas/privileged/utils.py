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

import contextlib
import ctypes
import os

from oslo_log import log as logging
from pyroute2 import netns as pynetns
import six

from neutron_fwaas._i18n import _


PROCESS_NETNS = '/proc/self/ns/net'

LOG = logging.getLogger(__name__)


class BackInNamespaceExit(SystemExit):
    """Raised if we fail to moved back process in its original namespace."""


def setns(netns):
    """Mimic future pyroute2 setns."""
    if isinstance(netns, six.string_types):
        return pynetns.setns(netns)

    # NOTE(cby): netns is a netns fd
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    error = libc.syscall(pynetns.__NR_setns, netns, pynetns.CLONE_NEWNET)
    if error:
        raise OSError(ctypes.get_errno(), 'failed to open netns', netns)
    return netns


@contextlib.contextmanager
def in_namespace(namespace):
    """Move current process in a specific namespace.

    This contextmanager moves current process in a specific namespace and
    ensures to move it back in original namespace or kills it if we fail to
    move back in original namespace.
    """
    if not namespace:
        yield
        return

    org_netns_fd = os.open(PROCESS_NETNS, os.O_RDONLY)
    try:
        new_netns_fd = setns(namespace)
        try:
            try:
                yield
            finally:
                try:
                    # NOTE(cby): this code is not executed only if we fail to
                    # move in target namespace
                    setns(org_netns_fd)
                except Exception as e:
                    msg = _('Failed to move back in original netns: %s') % e
                    LOG.critical(msg)
                    raise BackInNamespaceExit(msg)
        finally:
            os.close(new_netns_fd)
    finally:
        os.close(org_netns_fd)
