Neutron FWaaS Style Commandments
================================

Please see the Neutron HACKING.rst file for style commandments for
neutron-fwaas:

`Neutron HACKING.rst <https://opendev.org/openstack/neutron/src/branch/master/HACKING.rst>`_

Type Annotations
----------------

- New code must be fully annotated: every parameter and return value of new
  or modified functions and methods should have a type annotation. This is a
  reviewer-enforced convention for now; it only becomes gate-enforced by
  ``tox -e mypy`` for modules listed in the ratchet below.
- As a module becomes fully annotated, add it to the
  ``[[tool.mypy.overrides]]`` section of ``pyproject.toml``. Modules listed
  there are enforced with ``disallow_untyped_defs`` by ``tox -e mypy`` (which
  is also run as part of ``tox -e pep8``). Do not remove a module from that
  list.
- Avoid ``Any`` in public signatures where a more specific type is available.
- Annotations must not change runtime behaviour.
