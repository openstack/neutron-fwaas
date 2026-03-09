.. _l2_agent_driver_internals:

======================
L2 Agent Driver (OVS)
======================

The L2 agent driver uses OpenFlow rules on the OVS integration bridge to
enforce firewall policies on VM ports. It operates at the hypervisor level,
filtering traffic before it reaches the network.

Architecture
------------

The L2 agent driver runs as an extension of the L2 (OVS) agent and uses
RPC-based communication with the plugin, similar to the L3 agent driver.

Key source files:

* ``neutron_fwaas/services/firewall/service_drivers/agents/l2/fwaas_v2.py``
  - L2 agent extension
* ``neutron_fwaas/services/firewall/service_drivers/
  agents/drivers/linux/l2/driver_base.py``
  - L2 driver base class
* ``neutron_fwaas/services/firewall/service_drivers/
  agents/drivers/linux/l2/openvswitch_firewall/firewall.py``
  - OVS firewall driver
* ``neutron_fwaas/services/firewall/service_drivers/
  agents/drivers/linux/l2/openvswitch_firewall/rules.py``
  - OVS flow rule generation

OpenFlow Pipeline
-----------------

The driver uses dedicated flow tables for firewall processing:

* **FW_BASE_EGRESS_TABLE (64)**: Entry point for egress traffic; handles ARP,
  DHCP, and connection tracking.
* **FW_RULES_EGRESS_TABLE (65)**: Applies firewall rules for egress traffic.
* **FW_ACCEPT_OR_INGRESS_TABLE (66)**: Dispatcher for ingress or already
  egress-filtered traffic.
* **FW_BASE_INGRESS_TABLE (68)**: Entry point for ingress traffic; handles ARP,
  DHCP, and connection tracking.
* **FW_RULES_INGRESS_TABLE (69)**: Applies firewall rules for ingress traffic.

Registers are used to track port (REG5) and network/VLAN (REG6).

Stateful Connection Tracking
-----------------------------

The driver uses OVS connection tracking (``ct()`` actions) with conntrack zones
based on VLAN tags (``REG6[0..15]``).

Connection states monitored:

* ``-trk``: Untracked traffic
* ``+trk``: Tracked traffic
* ``+new-est``: New connections
* ``+est``: Established connections
* ``+est-rel+rpl``: Reply direction of established connections
* ``-new-est+rel-inv``: Related connections
* ``+trk+inv``: Invalid packets

Conntrack marks:

* ``CT_MARK_NORMAL (0x0)``: Normal allowed traffic.
* ``CT_MARK_INVALID (0x1)``: Traffic matching removed rules.

Rule Translation
----------------

Firewall rules are translated into OpenFlow flows:

* **Allow**: Flows direct traffic to output or next table.
* **Deny**: Flows resubmit to ``DROPPED_TRAFFIC_TABLE``.
* **Reject**: Not implemented in OpenFlow flows. While the API accepts the
  ``reject`` action, only ``allow`` and ``deny`` are enforced.

IP prefix matching uses ``nw_src``/``nw_dst`` (IPv4) or
``ipv6_src``/``ipv6_dst`` (IPv6). Port ranges are expanded into individual
flow rules using port range masking.

L2 Protections
--------------

The driver provides additional L2-level protections:

* **ARP spoofing protection**: Validates source MAC addresses against allowed
  MACs.
* **DHCP server spoofing prevention**: Blocks ports 67/68 (IPv4) and 547/546
  (IPv6) from instances.
* **Router Advertisement blocking**: Prevents RA spoofing from instances.
* **IPv6 Neighbor Discovery**: Allows specific ICMPv6 types for neighbor
  discovery.

Port Security
--------------

Ports with ``port_security_enabled=False`` bypass firewall rules entirely
(trusted ports). The driver also supports allowed address pairs for MAC/IP
combinations.

Supported Protocols
-------------------

* TCP (with port ranges)
* UDP (with port ranges)
* SCTP (with port ranges)
* ICMP (IPv4, with type/code matching)
* ICMPv6 (IPv6, with type/code matching)
* Any (when protocol is not specified)
* Numeric protocol values (1-255)
