# Copyright 2015 Cisco Systems, Inc.
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

from neutron.db import model_base
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import sqlalchemy as sa

LOG = logging.getLogger(__name__)


class CiscoFirewallAssociation(model_base.BASEV2):

    """Represents FW association with CSR interface and attributes"""
    __tablename__ = 'cisco_firewall_associations'

    fw_id = sa.Column(sa.String(36),
                      sa.ForeignKey('firewalls.id', ondelete="CASCADE"),
                      primary_key=True)
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"))
    direction = sa.Column(sa.String(16))
    acl_id = sa.Column(sa.String(36))
    router_id = sa.Column(sa.String(36))


class CiscoFirewall_db_mixin(object):

    @log_helpers.log_method_call
    def add_firewall_csr_association(self, context, fw):
        with context.session.begin(subtransactions=True):
            firewall_db = CiscoFirewallAssociation(fw_id=fw['id'],
                                   port_id=fw['port_id'],
                                   direction=fw['direction'],
                                   acl_id=fw['acl_id'],
                                   router_id=fw['router_id'])
            context.session.add(firewall_db)

    @log_helpers.log_method_call
    def lookup_firewall_csr_association(self, context, fwid):
        with context.session.begin(subtransactions=True):
            csr_fw_qry = context.session.query(CiscoFirewallAssociation)
            csr_fw = csr_fw_qry.filter_by(fw_id=fwid).first()
        return csr_fw

    @log_helpers.log_method_call
    def update_firewall_csr_association(self, context, fwid, firewall):
        with context.session.begin(subtransactions=True):
            csr_fw_qry = context.session.query(CiscoFirewallAssociation)
            csr_fw = csr_fw_qry.filter_by(fw_id=fwid).first()
            csr_fw.update(firewall)
        return firewall
