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

from neutron_fwaas.db.firewall.v2 import firewall_db_v2

FIREWALL_GROUP = firewall_db_v2.FirewallGroup
FIREWALL_POLICY = firewall_db_v2.FirewallPolicy
FIREWALL_RULE = firewall_db_v2.FirewallRuleV2
