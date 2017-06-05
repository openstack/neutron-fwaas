# Copyright 2017 NEC Technologies India Pvt. Ltd.
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

from neutron_fwaas._i18n import _
from neutron_lib import exceptions


# Firewall Exceptions
class FirewallNotFound(exceptions.NotFound):
    message = _("Firewall %(firewall_id)s could not be found.")


class FirewallInUse(exceptions.InUse):
    message = _("Firewall %(firewall_id)s is still active.")


class FirewallInPendingState(exceptions.Conflict):
    message = _("Operation cannot be performed since associated Firewall "
                "%(firewall_id)s is in %(pending_state)s.")


class FirewallPolicyNotFound(exceptions.NotFound):
    message = _("Firewall Policy %(firewall_policy_id)s could not be found.")


class FirewallPolicyInUse(exceptions.InUse):
    message = _("Firewall Policy %(firewall_policy_id)s is being used.")


class FirewallPolicyConflict(exceptions.Conflict):
    """FWaaS exception for firewall policy.

    Occurs when admin policy tries to use another tenant's unshared
    policy.
    """
    message = _("Operation cannot be performed since Firewall Policy "
                "%(firewall_policy_id)s is not shared and does not belong to "
                "your tenant.")


class FirewallRuleSharingConflict(exceptions.Conflict):
    """FWaaS exception for firewall rules.

    When a shared policy is created or updated with unshared rules,
    this exception will be raised.
    """
    message = _("Operation cannot be performed since Firewall Policy "
                "%(firewall_policy_id)s is shared but Firewall Rule "
                "%(firewall_rule_id)s is not shared.")


class FirewallPolicySharingConflict(exceptions.Conflict):
    """FWaaS exception for firewall policy.

    When a policy is shared without sharing its associated rules,
    this exception will be raised.
    """
    message = _("Operation cannot be performed. Before sharing Firewall "
                "Policy %(firewall_policy_id)s, share associated Firewall "
                "Rule %(firewall_rule_id)s.")


class FirewallRuleNotFound(exceptions.NotFound):
    message = _("Firewall Rule %(firewall_rule_id)s could not be found.")


class FirewallRuleInUse(exceptions.InUse):
    message = _("Firewall Rule %(firewall_rule_id)s is being used.")


class FirewallRuleNotAssociatedWithPolicy(exceptions.InvalidInput):
    message = _("Firewall Rule %(firewall_rule_id)s is not associated "
                "with Firewall Policy %(firewall_policy_id)s.")


class FirewallRuleInvalidProtocol(exceptions.InvalidInput):
    message = _("Firewall Rule protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class FirewallRuleInvalidAction(exceptions.InvalidInput):
    message = _("Firewall rule action %(action)s is not supported. "
                "Only action values %(values)s are supported.")


class FirewallRuleInvalidICMPParameter(exceptions.InvalidInput):
    message = _("%(param)s are not allowed when protocol "
                "is set to ICMP.")


class FirewallRuleWithPortWithoutProtocolInvalid(exceptions.InvalidInput):
    message = _("Source/destination port requires a protocol.")


class FirewallRuleInvalidPortValue(exceptions.InvalidInput):
    message = _("Invalid value for port %(port)s.")


class FirewallRuleInfoMissing(exceptions.InvalidInput):
    message = _("Missing rule info argument for insert/remove "
                "rule operation.")


class FirewallIpAddressConflict(exceptions.InvalidInput):
    message = _("Invalid input - IP addresses do not agree with IP Version.")


class FirewallInternalDriverError(exceptions.NeutronException):
    """FWaas exception for all driver errors.

    On any failure or exception in the driver, driver should log it and
    raise this exception to the agent
    """
    message = _("%(driver)s: Internal driver error.")


class FirewallRuleConflict(exceptions.Conflict):
    """Firewall rule conflict exception.

    Occurs when admin policy tries to use another tenant's unshared
    rule.
    """
    message = _("Operation cannot be performed since Firewall Rule "
                "%(firewall_rule_id)s is not shared and belongs to "
                "another tenant %(tenant_id)s.")


class FirewallRouterInUse(exceptions.InUse):
    message = _("Router(s) %(router_ids)s provided already associated with "
                "other Firewall(s).")


class FirewallGroupNotFound(exceptions.NotFound):
    message = _("Firewall Group %(firewall_id)s could not be found.")


class FirewallGroupInUse(exceptions.InUse):
    message = _("Firewall %(firewall_id)s is still active.")


class FirewallGroupInPendingState(exceptions.Conflict):
    message = _("Operation cannot be performed since associated Firewall "
                "%(firewall_id)s is in %(pending_state)s.")


class FirewallGroupPortInvalid(exceptions.Conflict):
    message = _("Firewall Group Port %(port_id)s is invalid.")


class FirewallGroupPortInvalidProject(exceptions.Conflict):
    message = _("Operation cannot be performed as port %(port_id)s "
                "is in an invalid project %(tenant_id)s.")


class FirewallGroupPortInUse(exceptions.InUse):
    message = _("Port(s) %(port_ids)s provided already associated with "
                "other Firewall Group(s).")


class FirewallRuleAlreadyAssociated(exceptions.Conflict):
    """Firewall rule conflict exception.

    Occurs when there is an attempt to assign a rule to a policy that
    the rule is already associated with.
    """
    message = _("Operation cannot be performed since Firewall Rule "
                "%(firewall_rule_id)s is already associated with Firewall"
                "Policy %(firewall_policy_id)s.")
