.. _l3_agent_driver_internals:

===========================
L3 Agent Driver (iptables)
===========================

The L3 agent driver uses iptables rules applied in the router namespace.
Rules are enforced on router internal interfaces.

Architecture
------------

The L3 agent driver uses RPC-based communication between the plugin and agents.
The plugin sends firewall group operations via fanout RPC casts, and agents
report status back via RPC calls.

Key source files:

* ``neutron_fwaas/services/firewall/service_drivers/agents/agents.py``
  - Service driver
* ``neutron_fwaas/services/firewall/service_drivers/
  agents/l3reference/firewall_l3_agent_v2.py``
  - L3 agent extension
* ``neutron_fwaas/services/firewall/service_drivers/
  agents/drivers/linux/iptables_fwaas_v2.py``
  - iptables driver
* ``neutron_fwaas/services/firewall/service_drivers/
  agents/firewall_agent_api.py``
  - Agent RPC API

RPC Communication
-----------------

**Plugin to Agent** (fanout casts):

* ``create_firewall_group(firewall_group, host)``
* ``update_firewall_group(firewall_group, host)``
* ``delete_firewall_group(firewall_group, host)``

**Agent to Plugin** (RPC calls):

* ``set_firewall_group_status(fwg_id, status, host)``
* ``firewall_group_deleted(fwg_id, host)``
* ``get_firewall_groups_for_project(host)``
* ``get_projects_with_firewall_groups(host)``
* ``get_firewall_group_for_port(port_id, host)``

Stateful Connection Tracking
-----------------------------

The driver is fully stateful with two conntrack backends:

* ``ConntrackLegacy``: Uses the command-line ``conntrack`` utility.
* ``ConntrackNetlink``: Uses the netlink library (faster).

Default implicit rules are added to every chain:

* ``INVALID`` packets are dropped.
* ``ESTABLISHED`` and ``RELATED`` connections are accepted.

On firewall creation, the entire conntrack table is flushed. On updates, only
entries matching changed rules are selectively deleted.

iptables Rule Translation
--------------------------

Firewall rules are translated into iptables chains:

Chain naming:

* Ingress chains: ``i<version><fwid>`` (e.g., ``iv4fake-fw-uuid``)
* Egress chains: ``o<version><fwid>`` (e.g., ``ov4fake-fw-uuid``)

Action chains:

* **Allow**: jumps to accepted chain (``-j ACCEPT``)
* **Deny**: jumps to dropped chain (``-j DROP``)
* **Reject**: jumps to rejected chain
  (``-j REJECT --reject-with icmp-port-unreachable`` for IPv4,
  ``icmp6-port-unreachable`` for IPv6)

Port interface prefixes:

* Legacy: ``qr-`` (internal router interface)
* DVR SNAT: ``sg-`` (SNAT interface)
* DVR FIP: ``rfp-`` (router-to-FIP interface)

DVR Support
-----------

The driver handles Distributed Virtual Router mode with different interface
prefixes per DVR mode. Multiple iptables managers may be used per router
depending on the DVR configuration.

Supported Protocols
-------------------

* TCP (with port ranges)
* UDP (with port ranges)
* ICMP (IPv4)
* ICMPv6 (IPv6)
* Any (when protocol is not specified)

Logging API
-----------

The L3 agent driver is the only driver that supports the Neutron Logging API
for firewall groups. The logging implementation uses iptables NFLOG targets
to capture firewall events.

Key source files:

* ``neutron_fwaas/services/logapi/agents/drivers/iptables/driver.py``
  - Logging driver registration
* ``neutron_fwaas/services/logapi/agents/drivers/iptables/log.py``
  - Logging implementation
* ``neutron_fwaas/services/logapi/agents/l3/fwg_log.py``
  - L3 agent logging extension
