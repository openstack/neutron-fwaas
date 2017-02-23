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
#
# Some parts are based on python-conntrack:
# Copyright (c) 2009-2011,2015 Andrew Grigorev <andrew@ei-grad.ru>

import socket


CONNTRACK = 0

NFCT_O_PLAIN = 0

NFCT_OF_TIME_BIT = 1
NFCT_OF_TIME = 1 << NFCT_OF_TIME_BIT

NFCT_Q_DESTROY = 2
NFCT_Q_FLUSH = 4
NFCT_Q_DUMP = 5
NFCT_T_DESTROY_BIT = 2
NFCT_T_DESTROY = 1 << NFCT_T_DESTROY_BIT

ATTR_IPV4_SRC = 0
ATTR_IPV4_DST = 1
ATTR_IPV6_SRC = 4
ATTR_IPV6_DST = 5
ATTR_PORT_SRC = 8
ATTR_PORT_DST = 9
ATTR_ICMP_TYPE = 12
ATTR_ICMP_CODE = 13
ATTR_ICMP_ID = 14
ATTR_L3PROTO = 15
ATTR_L4PROTO = 17

NFCT_T_NEW_BIT = 0
NFCT_T_NEW = 1 << NFCT_T_NEW_BIT
NFCT_T_UPDATE_BIT = 1
NFCT_T_UPDATE = 1 << NFCT_T_UPDATE_BIT
NFCT_T_DESTROY_BIT = 2
NFCT_T_DESTROY = 1 << NFCT_T_DESTROY_BIT

NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY

NFCT_CB_CONTINUE = 1
NFCT_CB_FAILURE = -1

NFNL_SUBSYS_CTNETLINK = 0

BUFFER = 1024

IPVERSION_SOCKET = {4: socket.AF_INET, 6: socket.AF_INET6}
