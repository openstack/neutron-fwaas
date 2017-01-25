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

NFCT_OF_SHOW_LAYER3_BIT = 0
NFCT_OF_SHOW_LAYER3 = (1 << NFCT_OF_SHOW_LAYER3_BIT)
NFCT_OF_TIME_BIT = 1
NFCT_OF_TIME = (1 << NFCT_OF_TIME_BIT)
NFCT_OF_ID_BIT = 2
NFCT_OF_ID = (1 << NFCT_OF_ID_BIT)


CONNTRACK = 0

# Callback return codes
NFCT_CB_FAILURE = -1   # failure
NFCT_CB_STOP = 0    # stop the query
NFCT_CB_CONTINUE = 1    # keep iterating through data
NFCT_CB_STOLEN = 2    # like continue, but ct is not freed


# Queries
NFCT_Q_CREATE = 0
NFCT_Q_UPDATE = 1
NFCT_Q_DESTROY = 2
NFCT_Q_GET = 3
NFCT_Q_FLUSH = 4
NFCT_Q_DUMP = 5
NFCT_Q_DUMP_RESET = 6
NFCT_Q_CREATE_UPDATE = 7
NFCT_Q_DUMP_FILTER = 8
NFCT_Q_DUMP_FILTER_RESET = 9

# Message types
NFCT_T_UNKNOWN = 0
NFCT_T_NEW_BIT = 0
NFCT_T_NEW = (1 << NFCT_T_NEW_BIT)
NFCT_T_UPDATE_BIT = 1
NFCT_T_UPDATE = (1 << NFCT_T_UPDATE_BIT)
NFCT_T_DESTROY_BIT = 2
NFCT_T_DESTROY = (1 << NFCT_T_DESTROY_BIT)

NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY
NFCT_T_ERROR_BIT = 31
NFCT_T_ERROR = (1 << NFCT_T_ERROR_BIT)

# Attributes
ATTR_ORIG_IPV4_SRC = 0                    # u32 bits
ATTR_IPV4_SRC = ATTR_ORIG_IPV4_SRC        # alias
ATTR_ORIG_IPV4_DST = 1                    # u32 bits
ATTR_IPV4_DST = ATTR_ORIG_IPV4_DST        # alias
ATTR_REPL_IPV4_SRC = 2                    # u32 bits
ATTR_REPL_IPV4_DST = 3                    # u32 bits
ATTR_ORIG_IPV6_SRC = 4                    # u128 bits
ATTR_IPV6_SRC = ATTR_ORIG_IPV6_SRC        # alias
ATTR_ORIG_IPV6_DST = 5                    # u128 bits
ATTR_IPV6_DST = ATTR_ORIG_IPV6_DST        # alias
ATTR_REPL_IPV6_SRC = 6                    # u128 bits
ATTR_REPL_IPV6_DST = 7                    # u128 bits
ATTR_ORIG_PORT_SRC = 8                    # u16 bits
ATTR_PORT_SRC = ATTR_ORIG_PORT_SRC        # alias
ATTR_ORIG_PORT_DST = 9                    # u16 bits
ATTR_PORT_DST = ATTR_ORIG_PORT_DST        # alias
ATTR_REPL_PORT_SRC = 10                   # u16 bits
ATTR_REPL_PORT_DST = 11                   # u16 bits
ATTR_ICMP_TYPE = 12                       # u8 bits
ATTR_ICMP_CODE = 13                       # u8 bits
ATTR_ICMP_ID = 14                         # u16 bits
ATTR_ORIG_L3PROTO = 15                    # u8 bits
ATTR_L3PROTO = ATTR_ORIG_L3PROTO          # alias
ATTR_REPL_L3PROTO = 16                    # u8 bits
ATTR_ORIG_L4PROTO = 17                    # u8 bits
ATTR_L4PROTO = ATTR_ORIG_L4PROTO          # alias
ATTR_REPL_L4PROTO = 18                    # u8 bits
ATTR_TCP_STATE = 19                       # u8 bits
ATTR_SNAT_IPV4 = 20                       # u32 bits
ATTR_DNAT_IPV4 = 21                       # u32 bits
ATTR_SNAT_PORT = 22                       # u16 bits
ATTR_DNAT_PORT = 23                       # u16 bits
ATTR_TIMEOUT = 24                         # u32 bits
ATTR_MARK = 25                            # u32 bits
ATTR_ORIG_COUNTER_PACKETS = 26            # u32 bits
ATTR_REPL_COUNTER_PACKETS = 27            # u32 bits
ATTR_ORIG_COUNTER_BYTES = 28              # u32 bits
ATTR_REPL_COUNTER_BYTES = 29              # u32 bits
ATTR_USE = 30                             # u32 bits
ATTR_ID = 31                              # u32 bits
ATTR_STATUS = 32                          # u32 bits
ATTR_TCP_FLAGS_ORIG = 33                  # u8 bits
ATTR_TCP_FLAGS_REPL = 34                  # u8 bits
ATTR_TCP_MASK_ORIG = 35                   # u8 bits
ATTR_TCP_MASK_REPL = 36                   # u8 bits
ATTR_MASTER_IPV4_SRC = 37                 # u32 bits
ATTR_MASTER_IPV4_DST = 38                 # u32 bits
ATTR_MASTER_IPV6_SRC = 39                 # u128 bits
ATTR_MASTER_IPV6_DST = 40                 # u128 bits
ATTR_MASTER_PORT_SRC = 41                 # u16 bits
ATTR_MASTER_PORT_DST = 42                 # u16 bits
ATTR_MASTER_L3PROTO = 43                  # u8 bits
ATTR_MASTER_L4PROTO = 44                  # u8 bits
ATTR_SECMARK = 45                         # u32 bits
ATTR_ORIG_NAT_SEQ_CORRECTION_POS = 46     # u32 bits
ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE = 47      # u32 bits
ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = 48       # u32 bits
ATTR_REPL_NAT_SEQ_CORRECTION_POS = 49     # u32 bits
ATTR_REPL_NAT_SEQ_OFFSET_BEFORE = 50      # u32 bits
ATTR_REPL_NAT_SEQ_OFFSET_AFTER = 51       # u32 bits
ATTR_SCTP_STATE = 52                      # u8 bits
ATTR_SCTP_VTAG_ORIG = 53                  # u32 bits
ATTR_SCTP_VTAG_REPL = 54                  # u32 bits
ATTR_HELPER_NAME = 55                     # string (30 bytes max)
ATTR_DCCP_STATE = 56                      # u8 bits
ATTR_DCCP_ROLE = 57                       # u8 bits
ATTR_DCCP_HANDSHAKE_SEQ = 58              # u64 bits
ATTR_MAX = 59
ATTR_GRP_ORIG_IPV4 = 0                    # struct nfct_attr_grp_ipv4
ATTR_GRP_REPL_IPV4 = 1                    # struct nfct_attr_grp_ipv4
ATTR_GRP_ORIG_IPV6 = 2                    # struct nfct_attr_grp_ipv6
ATTR_GRP_REPL_IPV6 = 3                    # struct nfct_attr_grp_ipv6
ATTR_GRP_ORIG_PORT = 4                    # struct nfct_attr_grp_port
ATTR_GRP_REPL_PORT = 5                    # struct nfct_attr_grp_port
ATTR_GRP_ICMP = 6                         # struct nfct_attr_grp_icmp
ATTR_GRP_MASTER_IPV4 = 7                  # struct nfct_attr_grp_ipv4
ATTR_GRP_MASTER_IPV6 = 8                  # struct nfct_attr_grp_ipv6
ATTR_GRP_MASTER_PORT = 9                  # struct nfct_attr_grp_port
ATTR_GRP_ORIG_COUNTERS = 10               # struct nfct_attr_grp_ctrs
ATTR_GRP_REPL_COUNTERS = 11               # struct nfct_attr_grp_ctrs
ATTR_GRP_MAX = 12
ATTR_EXP_MASTER = 0                       # pointer to conntrack object
ATTR_EXP_EXPECTED = 1                     # pointer to conntrack object
ATTR_EXP_MASK = 2                         # pointer to conntrack object
ATTR_EXP_TIMEOUT = 3                      # u32 bits
ATTR_EXP_MAX = 4

# NFCT_*printf output format
NFCT_O_PLAIN = 0
NFCT_O_DEFAULT = NFCT_O_PLAIN
NFCT_O_XML = 1
NFCT_O_MAX = 2


NFCT_CMP_ALL = 0
NFCT_CMP_ORIG = (1 << 0)
NFCT_CMP_REPL = (1 << 1)
NFCT_CMP_TIMEOUT_EQ = (1 << 2)
NFCT_CMP_TIMEOUT_GT = (1 << 3)
NFCT_CMP_TIMEOUT_GE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_GT)
NFCT_CMP_TIMEOUT_LT = (1 << 4)
NFCT_CMP_TIMEOUT_LE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_LT)
NFCT_CMP_MASK = (1 << 5)
NFCT_CMP_STRICT = (1 << 6)

# Conntrack options
CT_OPT_ORIG_SRC_BIT = 0
CT_OPT_ORIG_SRC = (1 << CT_OPT_ORIG_SRC_BIT)

CT_OPT_ORIG_DST_BIT = 1
CT_OPT_ORIG_DST = (1 << CT_OPT_ORIG_DST_BIT)

CT_OPT_ORIG = (CT_OPT_ORIG_SRC | CT_OPT_ORIG_DST)

CT_OPT_REPL_SRC_BIT = 2
CT_OPT_REPL_SRC = (1 << CT_OPT_REPL_SRC_BIT)

CT_OPT_REPL_DST_BIT = 3
CT_OPT_REPL_DST = (1 << CT_OPT_REPL_DST_BIT)

CT_OPT_REPL = (CT_OPT_REPL_SRC | CT_OPT_REPL_DST)

CT_OPT_PROTO_BIT = 4
CT_OPT_PROTO = (1 << CT_OPT_PROTO_BIT)

CT_OPT_TUPLE_ORIG = (CT_OPT_ORIG | CT_OPT_PROTO)
CT_OPT_TUPLE_REPL = (CT_OPT_REPL | CT_OPT_PROTO)

CT_OPT_TIMEOUT_BIT = 5
CT_OPT_TIMEOUT = (1 << CT_OPT_TIMEOUT_BIT)

CT_OPT_STATUS_BIT = 6
CT_OPT_STATUS = (1 << CT_OPT_STATUS_BIT)

CT_OPT_ZERO_BIT = 7
CT_OPT_ZERO = (1 << CT_OPT_ZERO_BIT)

CT_OPT_EVENT_MASK_BIT = 8
CT_OPT_EVENT_MASK = (1 << CT_OPT_EVENT_MASK_BIT)

CT_OPT_EXP_SRC_BIT = 9
CT_OPT_EXP_SRC = (1 << CT_OPT_EXP_SRC_BIT)

CT_OPT_EXP_DST_BIT = 10
CT_OPT_EXP_DST = (1 << CT_OPT_EXP_DST_BIT)

CT_OPT_MASK_SRC_BIT = 11
CT_OPT_MASK_SRC = (1 << CT_OPT_MASK_SRC_BIT)

CT_OPT_MASK_DST_BIT = 12
CT_OPT_MASK_DST = (1 << CT_OPT_MASK_DST_BIT)

CT_OPT_NATRANGE_BIT = 13
CT_OPT_NATRANGE = (1 << CT_OPT_NATRANGE_BIT)

CT_OPT_MARK_BIT = 14
CT_OPT_MARK = (1 << CT_OPT_MARK_BIT)

CT_OPT_ID_BIT = 15
CT_OPT_ID = (1 << CT_OPT_ID_BIT)

CT_OPT_FAMILY_BIT = 16
CT_OPT_FAMILY = (1 << CT_OPT_FAMILY_BIT)

CT_OPT_SRC_NAT_BIT = 17
CT_OPT_SRC_NAT = (1 << CT_OPT_SRC_NAT_BIT)

CT_OPT_DST_NAT_BIT = 18
CT_OPT_DST_NAT = (1 << CT_OPT_DST_NAT_BIT)

CT_OPT_OUTPUT_BIT = 19
CT_OPT_OUTPUT = (1 << CT_OPT_OUTPUT_BIT)

CT_OPT_SECMARK_BIT = 20
CT_OPT_SECMARK = (1 << CT_OPT_SECMARK_BIT)

CT_OPT_BUFFERSIZE_BIT = 21
CT_OPT_BUFFERSIZE = (1 << CT_OPT_BUFFERSIZE_BIT)

CT_OPT_ANY_NAT_BIT = 22
CT_OPT_ANY_NAT = (1 << CT_OPT_ANY_NAT_BIT)

CT_OPT_ZONE_BIT = 23
CT_OPT_ZONE = (1 << CT_OPT_ZONE_BIT)

CT_COMPARISON = (CT_OPT_PROTO | CT_OPT_ORIG | CT_OPT_REPL | CT_OPT_MARK |
                 CT_OPT_SECMARK | CT_OPT_STATUS | CT_OPT_ID | CT_OPT_ZONE)
