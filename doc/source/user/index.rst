.. _user_guide:

========================
Neutron FWaaS User Guide
========================

This guide describes how to use the Firewall-as-a-Service (FWaaS) v2
features in OpenStack Networking (Neutron).

For installation instructions, see
the :ref:`Installation Guide <installation>`.
For configuration options and driver comparison, see the
:ref:`Configuration Guide <configuring>`.

Overview
--------

FWaaS v2 provides perimeter firewall management through firewall groups. A
firewall group is a collection of ingress and egress firewall policies that
can be applied to specific Neutron ports (router ports or VM ports, depending
on the backend driver).

The main resources are:

* **Firewall Rule**: Defines a single filtering rule with match criteria
  (protocol, source/destination IP, source/destination port) and an action
  (allow, deny, or reject).
* **Firewall Policy**: An ordered collection of firewall rules.
* **Firewall Group**: Associates an ingress and/or egress firewall policy with
  a set of Neutron ports.

.. note::

   FWaaS always adds an implicit **deny all** rule at the lowest precedence of
   each policy. A policy with no explicit rules will block all traffic.

Managing Firewall Rules
-----------------------

Create a firewall rule
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group rule create \
       --protocol {tcp,udp,icmp,any} \
       --source-ip-address SOURCE_IP_ADDRESS \
       --destination-ip-address DESTINATION_IP_ADDRESS \
       --source-port SOURCE_PORT_RANGE \
       --destination-port DEST_PORT_RANGE \
       --action {allow,deny,reject}

All parameters are optional:

* ``--protocol``: One of ``tcp``, ``udp``, ``icmp``, or ``any``. Use ``any``
  for protocol-agnostic rules.
* ``--source-ip-address`` / ``--destination-ip-address``: IP address or CIDR
  subnet. Source and destination must be the same IP version.
* ``--source-port`` / ``--destination-port``: Port number or range
  (e.g., ``8000:8999``). Only valid with ``tcp`` or ``udp`` protocol.
* ``--action``: One of ``allow``, ``deny``, or ``reject``. Default is
  ``deny``.

Example - allow inbound SSH traffic from a specific subnet:

.. code-block:: console

   $ openstack firewall group rule create \
       --name allow-ssh \
       --protocol tcp \
       --destination-port 22 \
       --source-ip-address 10.0.0.0/24 \
       --action allow

List firewall rules
~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group rule list

Show a firewall rule
~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group rule show RULE_NAME_OR_ID

Update a firewall rule
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group rule set RULE_NAME_OR_ID \
       --protocol tcp \
       --destination-port 443

Delete a firewall rule
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group rule delete RULE_NAME_OR_ID

Managing Firewall Policies
--------------------------

Create a firewall policy
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group policy create \
       --firewall-rule "RULE_NAME_OR_ID" \
       myfirewallpolicy

Multiple rules can be specified by repeating the ``--firewall-rule`` option.
Rules are applied in the order they are listed.

Rules can also be added later:

.. code-block:: console

   $ openstack firewall group policy insert rule POLICY_NAME_OR_ID \
       RULE_NAME_OR_ID \
       --insert-before EXISTING_RULE_NAME_OR_ID

List firewall policies
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group policy list

Show a firewall policy
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group policy show POLICY_NAME_OR_ID

Delete a firewall policy
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group policy delete POLICY_NAME_OR_ID

Managing Firewall Groups
-------------------------

Create a firewall group
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group create \
       --name myfirewallgroup \
       --ingress-firewall-policy INGRESS_POLICY_NAME_OR_ID \
       --egress-firewall-policy EGRESS_POLICY_NAME_OR_ID \
       --port PORT_NAME_OR_ID

Multiple ports can be specified by repeating the ``--port`` option.

.. note::

   A firewall group remains in ``PENDING_CREATE`` state until it is associated
   with at least one port that is bound and active. For L3 (router port) based
   drivers, this means the port must be an active router interface.

List firewall groups
~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group list

Show a firewall group
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group show FWG_NAME_OR_ID

Update a firewall group
~~~~~~~~~~~~~~~~~~~~~~~

Add or remove ports, or change associated policies:

.. code-block:: console

   $ openstack firewall group set FWG_NAME_OR_ID \
       --port PORT_NAME_OR_ID \
       --ingress-firewall-policy NEW_POLICY_NAME_OR_ID

.. note::

   To remove all ports from a firewall group, use the ``--no-port`` option.

Delete a firewall group
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   $ openstack firewall group delete FWG_NAME_OR_ID

Example: Allowing Web and SSH Traffic
--------------------------------------

This example creates a firewall group that allows SSH and HTTP/HTTPS traffic
while blocking everything else (via the implicit deny-all rule).

1. Create firewall rules:

   .. code-block:: console

      $ openstack firewall group rule create \
          --name allow-ssh --protocol tcp --destination-port 22 --action allow
      $ openstack firewall group rule create \
          --name allow-http --protocol tcp --destination-port 80 --action allow
      $ openstack firewall group rule create \
          --name allow-https --protocol tcp --destination-port 443 --action allow

2. Create an ingress firewall policy with these rules:

   .. code-block:: console

      $ openstack firewall group policy create \
          --firewall-rule allow-ssh \
          --firewall-rule allow-http \
          --firewall-rule allow-https \
          my-ingress-policy

3. **(OVN driver only)** When using the OVN backend driver, firewall rules are
   stateless. This means return traffic is not automatically allowed, so an
   egress policy with rules allowing the response traffic is also required:

   .. code-block:: console

      $ openstack firewall group rule create \
          --name allow-ssh-reply --protocol tcp --source-port 22 --action allow
      $ openstack firewall group rule create \
          --name allow-http-reply --protocol tcp --source-port 80 --action allow
      $ openstack firewall group rule create \
          --name allow-https-reply --protocol tcp --source-port 443 --action allow
      $ openstack firewall group policy create \
          --firewall-rule allow-ssh-reply \
          --firewall-rule allow-http-reply \
          --firewall-rule allow-https-reply \
          my-egress-policy

   For stateful drivers (L3 agent, L2 agent), this step is not needed as
   return traffic for established connections is automatically allowed.

4. Create a firewall group and associate it with a router port:

   .. code-block:: console

      $ openstack firewall group create \
          --name my-firewall-group \
          --ingress-firewall-policy my-ingress-policy \
          --port PORT_ID

   When using the OVN driver, include the egress policy as well:

   .. code-block:: console

      $ openstack firewall group create \
          --name my-firewall-group \
          --ingress-firewall-policy my-ingress-policy \
          --egress-firewall-policy my-egress-policy \
          --port PORT_ID

5. Verify the firewall group status:

   .. code-block:: console

      $ openstack firewall group show my-firewall-group
