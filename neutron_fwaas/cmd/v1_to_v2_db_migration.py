# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron.common import config
from neutron.db import models_v2
from oslo_config import cfg
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging

from neutron_fwaas._i18n import _
from neutron_fwaas.db.firewall import firewall_db as firewall_db_v1
from neutron_fwaas.db.firewall.v2 import firewall_db_v2


LOG = logging.getLogger(__name__)


def setup_conf():
    cli_opts = [
        cfg.StrOpt('neutron-db-connection',
                   required=True,
                   help=_('neutron database connection string')),
    ]
    conf = cfg.CONF
    conf.register_cli_opts(cli_opts)
    conf()


def migrate_fwaas_v1_to_v2(db_session):
    # the entire migration process will be done under the same transaction to
    # allow full rollback in case of error
    with db_session.begin(subtransactions=True):
        # Read all V1 policies
        v1_policies = db_session.query(firewall_db_v1.FirewallPolicy)

        for v1_pol in v1_policies:
            LOG.info("Migrating FWaaS V1 policy %s", v1_pol.id)
            # read the rules of this policy
            v1_rules = db_session.query(firewall_db_v1.FirewallRule).filter_by(
                firewall_policy_id=v1_pol.id).all()
            # Create the V2 policy
            v2_pol = firewall_db_v2.FirewallPolicy(
                id=v1_pol.id,
                tenant_id=v1_pol.tenant_id,
                name=v1_pol.name,
                description=v1_pol.description,
                shared=v1_pol.shared,
                audited=v1_pol.audited,
                rule_count=len(v1_rules))
            db_session.add(v2_pol)

            # Add the rules and associate them with the policy
            for v1_rule in v1_rules:
                LOG.info("Migrating FWaaS V1 rule %s", v1_rule.id)
                v2_rule = firewall_db_v2.FirewallRuleV2(
                    id=v1_rule.id,
                    name=v1_rule.name,
                    description=v1_rule.description,
                    tenant_id=v1_rule.tenant_id,
                    shared=v1_rule.shared,
                    protocol=v1_rule.protocol,
                    ip_version=v1_rule.ip_version,
                    source_ip_address=v1_rule.source_ip_address,
                    destination_ip_address=v1_rule.destination_ip_address,
                    source_port_range_min=v1_rule.source_port_range_min,
                    source_port_range_max=v1_rule.source_port_range_max,
                    destination_port_range_min=(
                        v1_rule.destination_port_range_min),
                    destination_port_range_max=(
                        v1_rule.destination_port_range_max),
                    action=v1_rule.action,
                    enabled=v1_rule.enabled)
                db_session.add(v2_rule)
                v2_link = firewall_db_v2.FirewallPolicyRuleAssociation(
                    firewall_policy_id=v1_pol.id,
                    firewall_rule_id=v1_rule.id,
                    position=v1_rule.position)
                db_session.add(v2_link)

        # Read all V1 firewalls
        v1_fws = db_session.query(firewall_db_v1.Firewall)
        for v1_fw in v1_fws:
            LOG.info("Migrating FWaaS V1 firewall %s", v1_fw.id)
            # create the V2 firewall group
            v2_fw_group = firewall_db_v2.FirewallGroup(
                id=v1_fw.id,
                name=v1_fw.name,
                description=v1_fw.description,
                tenant_id=v1_fw.tenant_id,
                shared=v1_fw.shared,
                admin_state_up=v1_fw.admin_state_up,
                status=v1_fw.status,
                ingress_firewall_policy_id=v1_fw.firewall_policy_id,
                egress_firewall_policy_id=v1_fw.firewall_policy_id)
            db_session.add(v2_fw_group)

            # for every router in the V1 Firewall router association, add all
            # its interface ports to the V2 FirewallGroupPortAssociation
            v1_routers = db_session.query(
                firewall_db_v1.FirewallRouterAssociation).filter_by(
                fw_id=v1_fw.id)
            for v1_router in v1_routers:
                rtr_id = v1_router.router_id
                LOG.info("Migrating FWaaS V1 %s router %s", v1_fw.id, rtr_id)
                if_ports = db_session.query(models_v2.Port).filter_by(
                    device_id=rtr_id,
                    device_owner="network:router_interface")
                for port in if_ports:
                    fw_port = firewall_db_v2.FirewallGroupPortAssociation(
                        firewall_group_id=v2_fw_group.id,
                        port_id=port.id)
                    db_session.add(fw_port)


def main():
    # Initialize the cli options
    setup_conf()
    config.setup_logging()

    # Get the neutron DB session
    neutron_context_manager = enginefacade.transaction_context()
    neutron_context_manager.configure(
        connection=cfg.CONF.neutron_db_connection)
    n_session_maker = neutron_context_manager.writer.get_sessionmaker()
    n_session = n_session_maker(autocommit=True)

    # Run DB migration
    migrate_fwaas_v1_to_v2(n_session)
    LOG.info("DB migration done.")
