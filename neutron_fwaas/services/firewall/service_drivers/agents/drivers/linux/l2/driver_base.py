# Copyright (C) 2017 Fujitsu Limited
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc
from collections.abc import Generator
import contextlib
import typing


class FirewallL2DriverBase(metaclass=abc.ABCMeta):
    """Abstract firewall L2 driver base"""

    def __init__(self, integration_bridge: str,
                 sg_enabled: bool = False) -> None:
        pass

    def filter_defer_apply_on(self) -> None:
        """Defer application of filtering rule."""
        pass

    def filter_defer_apply_off(self) -> None:
        """Turn off deferral of rules and apply the rules now."""
        pass

    @property
    def ports(self) -> typing.Any:
        """Returns filtered ports."""
        pass

    @contextlib.contextmanager
    def defer_apply(self) -> Generator[None, None, None]:
        """Defer apply context."""
        self.filter_defer_apply_on()
        try:
            yield
        finally:
            self.filter_defer_apply_off()

    def create_firewall_group(self, ports: list[dict[str, typing.Any]],
                              firewall_group: dict[str, typing.Any]) -> None:
        """Called when a firewall group is created.
        """
        raise NotImplementedError()

    def update_firewall_group(self, ports: list[dict[str, typing.Any]],
                              firewall_group: dict[str, typing.Any]) -> None:
        """Called when a firewall group is updated.
        """
        raise NotImplementedError()

    def delete_firewall_group(self, ports: list[dict[str, typing.Any]],
                              firewall_group: dict[str, typing.Any]) -> None:
        """Called when a firewall group is deleted.
        """
        raise NotImplementedError()
