=========================
neutron-fwaas in DevStack
=========================

This is setup as a DevStack plugin.  For more information on DevStack plugins,
see the `DevStack Plugins documentation
<https://docs.openstack.org/devstack/latest/plugins.html>`_.

Please note that the old 'q-fwaas' keyword still exists, and will run FWaaS V1.
This default will be changed during the Ocata cycle.  The introduction of two
new keywords, 'q-fwaas-v1' and 'q-fwaas-v2' allow you to explicitly select the
version you with to run.

How to run FWaaS V2 in DevStack
===============================

Add the following to the localrc section of your local.conf to configure
FWaaS v2.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
   enable_service q-fwaas-v2

To check a specific patchset that is currently under development, use a form
like the below example, which is checking out change 214350 patch set 14 for
testing.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://review.openstack.org/p/openstack/neutron-fwaas refs/changes/50/214350/14
   enable_service q-fwaas-v2

How to run FWaaS V1 in DevStack
===============================

Add the following to the localrc section of your local.conf to configure
FWaaS v1.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
   enable_service q-fwaas-v1

To check a specific patchset that is currently under development, use a form
like the below example, which is checking out change 214350 patch set 14 for
testing.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://review.openstack.org/p/openstack/neutron-fwaas refs/changes/50/214350/14
   enable_service q-fwaas-v1
