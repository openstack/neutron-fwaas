.. _configuring:

=================================
Neutron FWaaS Configuration Guide
=================================

This section provides a list of all possible options for each
configuration file.

Configuration
-------------

Neutron FWaaS supports various Neutron backend drivers, such as:

* ML2/OVN.
* ML2/OVS and L3 agent.

Differences between drivers are described in the
:ref:`drivers_comparison` document.

Neutron FWaaS uses the following configuration files for its various services.

.. toctree::
   :maxdepth: 1

   drivers_comparison
   neutron_fwaas
   fwaas_driver

The following are sample configuration files for Neutron FWaaS and utilities.
These are generated from code and reflect the current state of code
in the neutron-fwaas repository.

.. toctree::
   :glob:
   :maxdepth: 1

   samples/*

Policy
------

Neutron FWaaS, like most OpenStack projects, uses a policy language to restrict
permissions on REST API actions.

.. toctree::
   :maxdepth: 1

   Policy Reference <policy>
   Sample Policy File <policy-sample>
