neutron-fwaas in DevStack
=========================

This is setup as a DevStack plugin.  For more information on DevStack plugins,
see the `DevStack Plugins documentation
<http://docs.openstack.org/developer/devstack/plugins.html>`_.

This was created using the `devstack-plugin-cookiecutter
<https://github.com/openstack-dev/devstack-plugin-cookiecutter>`_ tool.

How to run FWaaS in DevStack
=========================

Add the following to the localrc section of your local.conf:

.. code-block:: none
   [[local|localrc]]
   enable_plugin neutron-fwaas http://git.openstack.org/openstack/neutron-fwaas
   enable_service q-fwaas

To check a specific patchset that is currently under development, use a form
like the below example, which is checking out change 214350 patch set 14 for
testing.

.. code-block:: none
   [[local|localrc]]
   enable_plugin neutron-fwaas https://review.openstack.org/p/openstack/neutron-fwaas refs/changes/50/214350/14
   enable_service q-fwaas
