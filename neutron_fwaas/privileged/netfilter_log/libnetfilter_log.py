# Copyright (c) 2018 Fujitsu Limited
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

import multiprocessing
import socket
import struct
import time

import cffi
import eventlet
from eventlet.green import zmq
from neutron_lib.utils import runtime
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils
from ryu.lib import addrconv
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6

from neutron_fwaas._i18n import _
from neutron_fwaas import privileged
from neutron_fwaas.privileged import utils as fwaas_utils

LOG = logging.getLogger(__name__)

# TODO(annp): consider to make a pub-sub pattern which allows other logging
# driver like snat log can consume libnetfilter_log

NETFILTER_LOG = 'netfilter_log'
ADDR_IPC = "ipc:///var/run/nflog"
CDEF = '''
typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;

struct nfulnl_msg_packet_hdr {
    u_int16_t       hw_protocol;    // hw protocol (network order)
    u_int8_t        hook;           // netfilter hook
    u_int8_t        _pad;
};

int nflog_fd(struct nflog_handle *h);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);

struct nflog_handle *nflog_open(void);
int nflog_close(struct nflog_handle *h);
int nflog_bind_pf(struct nflog_handle *h, u_int16_t pf);
int nflog_unbind_pf(struct nflog_handle *h, u_int16_t pf);
struct nflog_g_handle *nflog_bind_group(struct nflog_handle *h, u_int16_t num);
int nflog_unbind_group(struct nflog_g_handle *gh);

static const u_int8_t NFULNL_COPY_PACKET;

int nflog_set_mode(struct nflog_g_handle *gh, u_int8_t mode, unsigned int len);
int nflog_set_timeout(struct nflog_g_handle *gh, u_int32_t timeout);
int nflog_set_flags(struct nflog_g_handle *gh, u_int16_t flags);
int nflog_set_qthresh(struct nflog_g_handle *gh, u_int32_t qthresh);
int nflog_set_nlbufsiz(struct nflog_g_handle *gh, u_int32_t nlbufsiz);

typedef int nflog_callback(struct nflog_g_handle *gh,
struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data);
int nflog_callback_register(
struct nflog_g_handle *gh, nflog_callback *cb, void *data);
int nflog_handle_packet(struct nflog_handle *h, char *buf, int len);

struct nfulnl_msg_packet_hdr *nflog_get_msg_packet_hdr(
struct nflog_data *nfad);

u_int16_t nflog_get_hwtype(struct nflog_data *nfad);
u_int16_t nflog_get_msg_packet_hwhdrlen(struct nflog_data *nfad);
char *nflog_get_msg_packet_hwhdr(struct nflog_data *nfad);
u_int32_t nflog_get_nfmark(struct nflog_data *nfad);
int nflog_get_timestamp(struct nflog_data *nfad, struct timeval *tv);
u_int32_t nflog_get_indev(struct nflog_data *nfad);
u_int32_t nflog_get_physindev(struct nflog_data *nfad);
u_int32_t nflog_get_outdev(struct nflog_data *nfad);
u_int32_t nflog_get_physoutdev(struct nflog_data *nfad);
struct nfulnl_msg_packet_hw *nflog_get_packet_hw(struct nflog_data *nfad);

int nflog_get_payload(struct nflog_data *nfad, char **data);

char *nflog_get_prefix(struct nflog_data *nfad);
'''

ffi = None
libnflog = None


def init_library():
    """Load libnetfilter_log library"""

    global ffi
    global libnflog
    if not ffi:
        ffi = cffi.FFI()
        ffi.cdef(CDEF)
    if not libnflog:
        try:
            libnflog = ffi.dlopen(NETFILTER_LOG)
        except OSError:
            msg = "Could not found libnetfilter-log"
            raise Exception(msg)

    return ffi, libnflog


ffi, libnflog = init_library()


def _payload(nfa):
    buf = ffi.new('char **')
    pkt_len = libnflog.nflog_get_payload(nfa, buf)
    if pkt_len <= 0:
        return None
    return ffi.buffer(buf[0], pkt_len)[:]


def decode(nfa):
    """This function will analysis nflog packet by using ryu packet library."""

    prefix = ffi.string(libnflog.nflog_get_prefix(nfa))
    packet_hdr = libnflog.nflog_get_msg_packet_hdr(nfa)
    hw_proto = socket.ntohs(packet_hdr.hw_protocol)

    msg = ''
    msg_packet_hwhdr = libnflog.nflog_get_msg_packet_hwhdr(nfa)
    if msg_packet_hwhdr != ffi.NULL:
        packet_hwhdr = ffi.string(msg_packet_hwhdr)
        if len(packet_hwhdr) >= 12:
            dst, src = struct.unpack_from('!6s6s', packet_hwhdr)
            # Dump ethernet packet to get mac addresses
            eth = ethernet.ethernet(addrconv.mac.bin_to_text(dst),
                                    addrconv.mac.bin_to_text(src),
                                    ethertype=hw_proto)
            msg = str(eth)

    # Dump IP packet
    pkt = _payload(nfa)
    if hw_proto == ether_types.ETH_TYPE_IP:
        ip_pkt, proto, data = ipv4.ipv4().parser(pkt)
        msg += str(ip_pkt)
        proto_pkt, a, b = proto.parser(data)
        msg += str(proto_pkt)
    elif hw_proto == ether_types.ETH_TYPE_IPV6:
        ip_pkt, proto, data = ipv6.ipv6().parser(pkt)
        proto_pkt, a, b = proto.parser(data)
        msg += str(proto_pkt)
    elif hw_proto == ether_types.ETH_TYPE_ARP:
        ip_pkt, proto, data = arp.arp().parser(pkt)
        msg += str(ip_pkt)
    else:
        msg += "Does not support hw_proto: " + str(hw_proto)

    return {'prefix': str(prefix), 'msg': str(msg)}


class NFLogWrapper(object):
    """A wrapper for libnetfilter_log api"""

    _instance = None

    def __init__(self):
        self.nflog_g_hanldes = {}

    @classmethod
    @runtime.synchronized("nflog-wrapper")
    def _create_instance(cls):
        if not cls.has_instance():
            cls._instance = cls()

    @classmethod
    def has_instance(cls):
        return cls._instance is not None

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    @classmethod
    def get_instance(cls):
        # double checked locking
        if not cls.has_instance():
            cls._create_instance()
        return cls._instance

    def open(self):
        self.nflog_handle = libnflog.nflog_open()
        if not self.nflog_handle:
            msg = _("Could not open nflog handle")
            raise Exception(msg)
        self._bind_pf()

    def close(self):
        if self.nflog_handle:
            libnflog.nflog_close(self.nflog_handle)

    def bind_group(self, group):
        g_handle = libnflog.nflog_bind_group(self.nflog_handle, group)
        if g_handle:
            self.nflog_g_hanldes[group] = g_handle
            self._set_mode(g_handle, 0x2, 0xffff)
            self._set_callback(g_handle, self.cb)

    def _bind_pf(self):
        for pf in (socket.AF_INET, socket.AF_INET6):
            libnflog.nflog_unbind_pf(self.nflog_handle, pf)
            libnflog.nflog_bind_pf(self.nflog_handle, pf)

    def unbind_group(self, group):
        try:
            g_handle = self.nflog_g_hanldes[group]
            if g_handle:
                libnflog.nflog_unbind_group(g_handle)
        except Exception:
            pass

    def _set_mode(self, g_handle, mode, len):
        ret = libnflog.nflog_set_mode(g_handle, mode, len)
        if ret != 0:
            msg = _("Could not set mode for nflog")
            raise Exception(msg)

    @ffi.callback("nflog_callback")
    def cb(gh, nfmsg, nfa, data):
        ev = decode(nfa)
        msg = jsonutils.dumps(ev) + '\n'
        ctx = zmq.Context(1)
        pub = ctx.socket(zmq.XREQ)
        pub.bind(ADDR_IPC)
        pub.send(msg.encode('utf-8'))
        pub.close()
        return 0

    def _set_callback(self, g_handle, cb):

        ret = libnflog.nflog_callback_register(g_handle, cb, ffi.NULL)
        if ret != 0:
            msg = _("Could not set callback for nflog")
            raise Exception(msg)

    def run_loop(self):
        fd = libnflog.nflog_fd(self.nflog_handle)
        buff = ffi.new('char[]', 4096)
        while True:
            try:
                pkt_len = libnflog.recv(fd, buff, 4096, 0)
            except OSError as err:
                # No buffer space available
                if err.errno == 11:
                    continue
                msg = _("Unknown exception")
                raise Exception(msg)
            if pkt_len > 0:
                libnflog.nflog_handle_packet(self.nflog_handle, buff, pkt_len)
            time.sleep(1.0)

    def start(self):
        nflog_process = multiprocessing.Process(target=self.run_loop)
        nflog_process.daemon = True
        nflog_process.start()
        return nflog_process.pid


@privileged.default.entrypoint
def run_nflog(namespace=None, group=0):
    """Run a nflog process under a namespace

    This process will listen nflog packets, which are sent from kernel to
    userspace. Then it decode these packets and send it to IPC address for log
    application.
    """

    with fwaas_utils.in_namespace(namespace):
        try:
            handle = NFLogWrapper.get_instance()
            handle.open()
            handle.bind_group(group)
            pid = handle.start()
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("NFLOG thread died of an exception")
                try:
                    handle.unbind_group(group)
                    handle.close()
                except Exception:
                    pass
    return pid


class NFLogApp(object):
    """Log application for handling nflog packets"""

    callback = None

    def register_packet_handler(self, caller):
        self.callback = caller

    def unregister_packet_handler(self):
        self.callback = None

    def start(self):
        def loop():
            while True:
                if self.callback:
                    ctx = zmq.Context(1)
                    sub = ctx.socket(zmq.XREQ)
                    sub.connect(ADDR_IPC)
                    msg = sub.recv()
                    if len(msg):
                        self.callback(jsonutils.loads(msg))
                    sub.close()
                time.sleep(1.0)
        # Spawn loop
        eventlet.spawn_n(loop)
