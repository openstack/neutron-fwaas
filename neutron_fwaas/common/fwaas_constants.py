# Copyright 2015 Cisco Systems, Inc
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

FIREWALL = 'FIREWALL'
FIREWALL_V2 = 'FIREWALL_V2'

# Constants for "topics"
FIREWALL_PLUGIN = 'q-firewall-plugin'
FW_AGENT = 'firewall_agent'
FIREWALL_RULE_LIST = 'firewall_rule_list'

# V2 Constants
DEFAULT_FWG = 'default'
DEFAULT_FWP_INGRESS = 'default ingress'
DEFAULT_FWP_EGRESS = 'default egress'

# Firewall group events for agent-side
DELETE_FWG = 'delete_firewall_group'
UPDATE_FWG = 'update_firewall_group'
CREATE_FWG = 'create_firewall_group'

# Port events for L2 agent extension
HANDLE_PORT = 'handle_port'
DELETE_PORT = 'delete_port'

# Resource name

FIREWALL_GROUP = 'firewall_group'
FIREWALL_RULE = 'firewall_rule'
FIREWALL_POLICY = 'firewall_policy'
