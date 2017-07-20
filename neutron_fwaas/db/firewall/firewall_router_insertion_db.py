# Copyright 2015 Cisco Systems Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib.db import model_base
from neutron_lib.exceptions import firewall_v1 as fwrtrins
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import sqlalchemy as sa


LOG = logging.getLogger(__name__)


class FirewallRouterAssociation(model_base.BASEV2):

    """Tracks FW Router Association"""

    __tablename__ = 'firewall_router_associations'

    fw_id = sa.Column(sa.String(36),
        sa.ForeignKey('firewalls.id', ondelete="CASCADE"),
        primary_key=True)
    router_id = sa.Column(sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)


class FirewallRouterInsertionDbMixin(object):

    """Access methods for the firewall_router_associations table."""

    @log_helpers.log_method_call
    def set_routers_for_firewall(self, context, fw):
        """Sets the routers associated with the fw."""
        with context.session.begin(subtransactions=True):
            for r_id in fw['router_ids']:
                fw_rtr_db = FirewallRouterAssociation(fw_id=fw['fw_id'],
                                   router_id=r_id)
                context.session.add(fw_rtr_db)

    @log_helpers.log_method_call
    def get_firewall_routers(self, context, fwid):
        """Gets all routers associated with a firewall."""
        with context.session.begin(subtransactions=True):
            fw_rtr_qry = context.session.query(
                FirewallRouterAssociation.router_id)
            fw_rtr_rows = fw_rtr_qry.filter_by(fw_id=fwid)
            fw_rtrs = [entry.router_id for entry in fw_rtr_rows]
        LOG.debug("get_firewall_routers(): fw_rtrs: %s", fw_rtrs)
        return fw_rtrs

    @log_helpers.log_method_call
    def validate_firewall_routers_not_in_use(
            self, context, router_ids, fwid=None):
        """Validate if router-ids not associated with any firewall.

        If any of the router-ids in the list is already associated with
        a firewall, raise an exception else just return.
        """
        fw_rtr_qry = context.session.query(FirewallRouterAssociation.router_id)
        fw_rtrs = fw_rtr_qry.filter(
            FirewallRouterAssociation.router_id.in_(router_ids),
            FirewallRouterAssociation.fw_id != fwid).all()
        if fw_rtrs:
            router_ids = [entry.router_id for entry in fw_rtrs]
            raise fwrtrins.FirewallRouterInUse(router_ids=router_ids)

    @log_helpers.log_method_call
    def update_firewall_routers(self, context, fw):
        """Update the firewall with new routers.

        This involves removing existing router associations and replacing
        it with the new router associations provided in the update method.
        """
        with context.session.begin(subtransactions=True):
            fw_rtr_qry = context.session.query(FirewallRouterAssociation)
            fw_rtr_qry.filter_by(fw_id=fw['fw_id']).delete()
            if fw['router_ids']:
                self.set_routers_for_firewall(context, fw)

            # TODO(sridar): Investigate potential corner case if rpc failure
            # happens on PENDING_UPDATE and agent did not restart. Evaluate
            # complexity vs benefit of holding on to old entries until ack
            # from agent.

        return fw
