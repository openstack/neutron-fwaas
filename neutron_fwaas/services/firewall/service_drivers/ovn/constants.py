# Copyright 2022 EasyStack, Inc.
# All rights reserved.
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

from neutron_lib import constants as const

OVN_FWG_EXT_ID_KEY = 'neutron:firewall_group_id'
OVN_FWR_EXT_ID_KEY = 'neutron:firewall_rule_id'
ACL_ACTION_DROP = 'drop'
ACL_ACTION_REJECT = 'reject'
ACL_ACTION_ALLOW_STATELESS = 'allow-stateless'
ACL_ACTION_ALLOW = 'allow'
ACL_PRIORITY_INGRESS = 2000
ACL_PRIORITY_EGRESS = 2000
ACL_PRIORITY_DEFAULT = 1001
OP_ADD = 'add'
OP_DEL = 'del'
OP_MOD = 'mod'
DEFAULT_RULE = 'is_default'
DEFAULT_RULE_ID = 'default_rule'

# Drop acls of ipv4 or ipv6 with two directions, so number of
# default acls is 4
DEFAULT_ACL_NUM = 4

# Group of transport protocols supported
TRANSPORT_PROTOCOLS = (const.PROTO_NAME_TCP,
                       const.PROTO_NAME_UDP,
                       const.PROTO_NAME_SCTP)

# Group of versions of the ICMP protocol supported
ICMP_PROTOCOLS = (const.PROTO_NAME_ICMP,
                  const.PROTO_NAME_IPV6_ICMP)
