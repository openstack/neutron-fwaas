.. _drivers_comparison:

==========================
FWaaS Drivers Comparison
==========================

Neutron FWaaS supports multiple backend drivers. This document describes the
differences between the OVN driver and the agent-based drivers (L3 and L2).

Overview
--------

.. list-table::
   :header-rows: 1
   :widths: 30 25 25 20

   * - Feature
     - OVN Driver
     - L3 Agent Driver
     - L2 Agent Driver
   * - Backend
     - OVN ACLs (Port Groups)
     - iptables
     - OpenFlow (OVS)
   * - Architecture
     - Service driver (no agent)
     - Agent-based (RPC)
     - Agent-based (RPC)
   * - Supported port types
     - L3 (router ports)
     - L3 (router ports)
     - L2 (VM/compute ports)
   * - Logging API support
     - No
     - Yes (iptables-based)
     - No
   * - Rule type
     - Stateless
     - Stateful
     - Stateful

Supported Actions
-----------------

.. list-table::
   :header-rows: 1
   :widths: 30 25 25 20

   * - Action
     - OVN Driver
     - L3 Agent Driver
     - L2 Agent Driver
   * - Allow
     - Yes
     - Yes
     - Yes
   * - Deny (drop)
     - Yes
     - Yes
     - Yes
   * - Reject (ICMP error)
     - Yes
     - Yes
     - No
