#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#
# Some parts are based on python-conntrack:
# Copyright (c) 2009-2011,2015 Andrew Grigorev <andrew@ei-grad.ru>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

"""
Conntrack - A simple python interface to libnetfilter_conntrack using ctypes.
"""

import ctypes as c
from ctypes.util import find_library
import os
from socket import AF_INET
from socket import AF_INET6

from pyroute2 import netns as pynetns

from oslo_log import log as logging

from neutron_fwaas._i18n import _LE
from neutron_fwaas.common import netlink_constants as nl_constants

from neutron_fwaas import privileged

LOG = logging.getLogger(__name__)

nfct = c.CDLL(find_library('netfilter_conntrack'))
libc = c.CDLL(find_library('libc.so.6'))

proto_num = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1,
}

family_socket = {
    4: AF_INET,
    6: AF_INET6,
}

NFCT_CALLBACK = c.CFUNCTYPE(c.c_int, c.c_int, c.c_void_p, c.c_void_p)


def _list(family=4):
    """
    Get list of active conntrack entries.

    :param: family: ipversion of conntrack entries to be listed.
    :return: entries: list of conntrack entries.
    """
    entries = []
    buf = c.create_string_buffer(1024)

    @NFCT_CALLBACK
    def cb(type, ct, data):
        nfct.nfct_snprintf(buf, 1024, ct, type, 0, nl_constants.NFCT_OF_TIME)
        entries.append(buf.value)
        return nl_constants.NFCT_CB_CONTINUE

    h = nfct.nfct_open(nl_constants.CONNTRACK, 0)

    if not h:
        LOG.exception(_LE("nfct_open failed!"))
        return entries

    nfct.nfct_callback_register(h, nl_constants.NFCT_T_ALL, cb, 0)
    ret = nfct.nfct_query(h, nl_constants.NFCT_Q_DUMP,
                          c.byref(c.c_int(family_socket[family])))
    if ret == -1:
        nfct.nfct_close(h)
        LOG.exception(_LE("nfct_query failed!"))
        return entries
    nfct.nfct_close(h)
    return entries


def _kill(**kwargs):
    """
    Delete specified conntrack entries.

    :param: kwargs: entry information
    :return: None
    """
    family = kwargs.get('family', 4)
    protocol = kwargs.get('protocol', 'tcp')
    source_address = kwargs.get('src', '0.0.0.0')
    destination_address = kwargs.get('dst', '0.0.0.0')

    ct = nfct.nfct_new()
    if not ct:
        LOG.exception(_LE("nfct_new failed!"))
        return

    nfct.nfct_set_attr_u8(ct, nl_constants.ATTR_L3PROTO, family_socket[family])

    if family == 4:
        nfct.nfct_set_attr_u32(ct, nl_constants.ATTR_IPV4_SRC,
                               libc.inet_addr(source_address))
        nfct.nfct_set_attr_u32(ct, nl_constants.ATTR_IPV4_DST,
                               libc.inet_addr(destination_address))
    elif family == 6:
        nfct.nfct_set_attr_u64(ct, nl_constants.ATTR_IPV6_SRC,
                               libc.inet_addr(source_address))
        nfct.nfct_set_attr_u64(ct, nl_constants.ATTR_IPV6_DST,
                               libc.inet_addr(destination_address))
    else:
        LOG.exception(_LE("Unsupported protocol family!"))

    nfct.nfct_set_attr_u8(ct, nl_constants.ATTR_L4PROTO, proto_num[protocol])

    if protocol == 'icmp':
        nfct.nfct_set_attr_u8(ct, nl_constants.ATTR_ICMP_TYPE,
                              kwargs.get('icmp_type', 8))
        nfct.nfct_set_attr_u8(ct, nl_constants.ATTR_ICMP_CODE,
                              kwargs.get('icmp_code', 0))
        nfct.nfct_set_attr_u16(ct, nl_constants.ATTR_ICMP_ID,
                               libc.htons(kwargs.get('icmp_id'), 0))
    else:
        nfct.nfct_set_attr_u16(ct, nl_constants.ATTR_PORT_SRC,
                               libc.htons(kwargs.get('sport')))
        nfct.nfct_set_attr_u16(ct, nl_constants.ATTR_PORT_DST,
                               libc.htons(kwargs.get('dport')))
    h = nfct.nfct_open(nl_constants.CONNTRACK, 0)
    if not h:
        LOG.exception(_LE("nfct_open failed!"))
    else:
        ret = nfct.nfct_query(h, nl_constants.NFCT_Q_DESTROY, ct)
        if ret == -1:
            LOG.exception(_LE("Deleting conntrack failed"))
    nfct.nfct_close(h)
    nfct.nfct_destroy(ct)


def _flush():
    ct = nfct.nfct_new()
    if not ct:
        libc.perror("nfct_new")
        raise LOG.exception(_LE("nfct_new failed!"))
        return
    h = nfct.nfct_open(nl_constants.CONNTRACK, 0)
    if not h:
        libc.perror("nfct_open")
        raise LOG.exception(_LE("nfct_open failed!"))
    else:
        ret = nfct.nfct_query(h, nl_constants.NFCT_Q_FLUSH, ct)
        if ret == -1:
            libc.perror("nfct_query")
            raise LOG.exception(_LE("nfct_query failed!"))
        nfct.nfct_close(h)
    nfct.nfct_destroy(ct)


def _parse_entry(entry, ipversion):
    """
    Parse entry to a tuple

    :param entry: Array from entry string split
    :param ipversion: ipversion used to get this entry
    :return: a tuple of parsed entry
    example: (4, 'tcp', '1111', '2222', '1.1.1.1', '2.2.2.2')
    """
    protocol = entry[1]
    if protocol == 'tcp':
        src_address = entry[5].split('=')[1]
        dst_address = entry[6].split('=')[1]
        sport = entry[7].split('=')[1]
        dport = entry[8].split('=')[1]
    elif protocol == 'udp':
        src_address = entry[4].split('=')[1]
        dst_address = entry[5].split('=')[1]
        sport = entry[6].split('=')[1]
        dport = entry[7].split('=')[1]
    elif protocol == 'icmp':
        src_address = entry[4].split('=')[1]
        dst_address = entry[5].split('=')[1]
        icmp_type = entry[6].split('=')[1]
        icmp_code = entry[7].split('=')[1]
        icmp_id = entry[8].split('=')[1]
        parsed_entry = (ipversion, protocol, icmp_type, icmp_code,
                        src_address, dst_address, icmp_id,)
        return parsed_entry
    parsed_entry = (ipversion, protocol, sport,
                    dport, src_address, dst_address,)
    return parsed_entry


@privileged.default.entrypoint
def list_entries(namespace):
    """
    List, parse and sort all entries

    :param namespace:
    :return: sorted list of entry tuples.
    example: [(4, 'icmp', '8', '0', '1.1.1.1', '2.2.2.2'),
              (4, 'tcp', '1111', '2222', '1.1.1.1', '2.2.2.2')]
    """
    entries = []
    if namespace:
        fd = pynetns.setns(namespace)
        ipversions = [4, 6]
        for ipversion in ipversions:
            xentries = _list(ipversion)
            for entry in xentries:
                sentry = entry.split()
                xentry = _parse_entry(sentry, ipversion)
                entries.append(xentry)
        os.close(fd)
    return sorted(entries)


def _kill_entry(entry):
    """
    Kill the entry

    :param entry: (ipversion, protocol, sport, dport, saddress, daddress)
    """

    if entry[1] == 'icmp':
        _kill(family=entry[0], protocol=entry[1],
              src=entry[4], dst=entry[5],
              icmp_type=int(entry[2]), icmp_code=int(entry[3]),
              icmp_id=int(entry[6]))
    else:
        _kill(family=entry[0], protocol=entry[1],
              src=entry[4], dst=entry[5],
              sport=int(entry[2]), dport=int(entry[3]))


@privileged.default.entrypoint
def kill_entries(namespace, entries):
    if namespace:
        fd = pynetns.setns(namespace)
        for entry in entries:
            _kill_entry(entry)
        os.close(fd)


@privileged.default.entrypoint
def flush_entries(namespace):
    if namespace:
        fd = pynetns.setns(namespace)
        _flush()
        os.close(fd)
