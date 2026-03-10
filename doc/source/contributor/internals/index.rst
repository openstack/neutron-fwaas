.. _driver_internals:

=================
Drivers Internals
=================

This section provides detailed information about the internals of each
FWaaS backend driver implementation.

Additional Features Comparison
------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 25 25 20

   * - Feature
     - OVN Driver
     - L3 Agent Driver
     - L2 Agent Driver
   * - DVR support
     - N/A
     - Yes
     - N/A
   * - DB synchronization
     - Yes (REPAIR mode)
     - No
     - No
   * - ARP spoofing protection
     - No
     - No
     - Yes
   * - DHCP discovery bypass
     - No
     - No
     - Yes
   * - Allowed address pairs
     - No
     - No
     - Yes
   * - Port security toggle
     - No
     - No
     - Yes (trusted ports bypass)
   * - Atomic rule application
     - Yes
     - Yes
     - Yes (deferred apply)


More details about each driver can be found at:

.. toctree::
   :maxdepth: 1

   ovn
   l3_agent
   l2_agent
