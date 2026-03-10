.. _ovn_driver_internals:

==========
OVN Driver
==========

The OVN driver operates as a service driver without any agent. It translates
firewall rules into OVN ACLs attached to Port Groups in the OVN Northbound
database. Each firewall group maps to an OVN Port Group with the same ID.

Architecture
------------

The OVN driver inherits from ``FirewallDriverDB`` and interacts directly with
the OVN Northbound database through the OVN mechanism driver's ``nb_ovn`` IDL.
No RPC communication or agent is required.

Key source files:

* ``neutron_fwaas/services/firewall/service_drivers/ovn/firewall_l3_driver.py``
  - Main driver implementation
* ``neutron_fwaas/services/firewall/service_drivers/ovn/acl.py``
  - ACL translation and port group management
* ``neutron_fwaas/services/firewall/service_drivers/ovn/constants.py``
  - Protocol and action constants
* ``neutron_fwaas/services/firewall/service_drivers/ovn/ovn_db_sync.py``
  - Database synchronization

Stateless ACLs
--------------

The OVN driver uses ``allow-stateless`` ACL action for allow rules. This means
return traffic is **not** automatically allowed - explicit rules are needed for
both directions of a connection.

ACL actions mapping:

* **Allow** -> ``allow-stateless``
* **Deny** -> ``drop``
* **Reject** -> ``reject``

Rule Translation
----------------

Firewall rules are translated into OVN ACL match expressions:

* **Direction**: ``inport == @<pg_name>`` (ingress) or
  ``outport == @<pg_name>`` (egress)
* **IP version**: ``ip4`` or ``ip6`` filter
* **IP addresses**: ``ip4.src==`` / ``ip4.dst==`` or
  ``ip6.src==`` / ``ip6.dst==``
* **Protocols and ports**: TCP/UDP/SCTP with port ranges; ICMP/ICMPv6 without
  ports

Priority
~~~~~~~~

ACL priority is calculated as ``base_priority - position``:

* 2000 for user-defined rules
* 1001 for default deny rules

Default Rules
-------------

Every port group gets 4 default ACLs that drop all traffic:

* IPv4 ingress drop
* IPv4 egress drop
* IPv6 ingress drop
* IPv6 egress drop

These default rules use a special ID (``default_rule``) and are marked with
``is_default=True``.

Supported Protocols
-------------------

* TCP
* UDP
* SCTP
* ICMP (IPv4)
* ICMPv6 (IPv6)
* Any (when protocol is not specified)

Port ranges are supported for TCP, UDP, and SCTP in the format ``min:max``.

DB Synchronization
------------------

The ``OvnNbDbSync`` class provides database synchronization between Neutron DB
and OVN Northbound DB:

* **REPAIR mode**: Full synchronization - creates missing port groups and ACLs
  in OVN, removes stale port groups that no longer exist in Neutron.
* **MIGRATE mode**: Not supported for FWaaS.
* **OFF mode**: No synchronization.

The default firewall group (named ``default``) is skipped during sync
operations.
