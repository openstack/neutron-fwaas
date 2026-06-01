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

from neutron_lib.api.definitions import constants as api_const
from neutron_lib import constants as lib_constants
from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils
from oslo_versionedobjects import fields as obj_fields

from neutron.objects import base

from neutron_fwaas.db.firewall.v2 import models


FW_VALID_STATUS_VALUES = [
    lib_constants.ACTIVE,
    lib_constants.CREATED,
    lib_constants.DOWN,
    lib_constants.ERROR,
    lib_constants.INACTIVE,
    lib_constants.PENDING_CREATE,
    lib_constants.PENDING_DELETE,
    lib_constants.PENDING_UPDATE,
]


class FirewallRuleActionEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(
        valid_values=api_const.FW_VALID_ACTION_VALUES)


class FirewallGroupStatusEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=FW_VALID_STATUS_VALUES)


@base.NeutronObjectRegistry.register
class FirewallRuleV2(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FirewallRuleV2

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'shared': obj_fields.BooleanField(default=False),
        'protocol': common_types.IpProtocolEnumField(nullable=True),
        'ip_version': common_types.IPVersionEnumField(nullable=True),
        'source_ip_address': common_types.IPNetworkField(nullable=True),
        'destination_ip_address': common_types.IPNetworkField(nullable=True),
        'source_port_range_min': common_types.PortRangeWith0Field(
            nullable=True),
        'source_port_range_max': common_types.PortRangeWith0Field(
            nullable=True),
        'destination_port_range_min': common_types.PortRangeWith0Field(
            nullable=True),
        'destination_port_range_max': common_types.PortRangeWith0Field(
            nullable=True),
        'action': FirewallRuleActionEnumField(nullable=True),
        'enabled': obj_fields.BooleanField(default=True),
    }

    fields_no_update = ['project_id']

    @classmethod
    def modify_fields_to_db(cls, fields):
        """Convert IP address fields to strings before storing in DB."""
        result = super().modify_fields_to_db(fields)
        for field in ('source_ip_address', 'destination_ip_address'):
            if result.get(field):
                result[field] = cls.filter_to_str(result[field])
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        """Convert IP address strings from DB to AuthenticIPNetwork."""
        fields = super().modify_fields_from_db(db_obj)
        for field in ('source_ip_address', 'destination_ip_address'):
            if fields.get(field):
                fields[field] = net_utils.AuthenticIPNetwork(fields[field])
        return fields


@base.NeutronObjectRegistry.register
class FirewallPolicyRuleAssociation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FirewallPolicyRuleAssociation

    primary_keys = ['firewall_policy_id', 'firewall_rule_id']

    foreign_keys = {
        'FirewallPolicy': {'firewall_policy_id': 'id'},
        'FirewallRuleV2': {'firewall_rule_id': 'id'},
    }

    fields = {
        'firewall_policy_id': common_types.UUIDField(),
        'firewall_rule_id': common_types.UUIDField(),
        'position': obj_fields.IntegerField(nullable=True),
    }

    fields_no_update = ['firewall_policy_id', 'firewall_rule_id']

    @classmethod
    def delete_policy_associations(cls, context, firewall_policy_id):
        context.session.query(cls.db_model).filter_by(
            firewall_policy_id=firewall_policy_id).delete()


@base.NeutronObjectRegistry.register
class FirewallPolicy(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FirewallPolicy

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'rule_count': obj_fields.IntegerField(nullable=True),
        'audited': obj_fields.BooleanField(default=False),
        'shared': obj_fields.BooleanField(default=False),
        'rule_associations': obj_fields.ListOfObjectsField(
            'FirewallPolicyRuleAssociation', nullable=True),
    }

    synthetic_fields = ['rule_associations']

    fields_no_update = ['project_id']


@base.NeutronObjectRegistry.register
class FirewallGroupPortAssociation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FirewallGroupPortAssociation

    primary_keys = ['firewall_group_id', 'port_id']

    foreign_keys = {
        'FirewallGroup': {'firewall_group_id': 'id'},
    }

    fields = {
        'firewall_group_id': common_types.UUIDField(),
        'port_id': common_types.UUIDField(),
    }

    fields_no_update = ['firewall_group_id', 'port_id']

    @classmethod
    def delete_group_port_associations(cls, context, firewall_group_id):
        context.session.query(cls.db_model).filter_by(
            firewall_group_id=firewall_group_id).delete()


@base.NeutronObjectRegistry.register
class FirewallGroup(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FirewallGroup

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'ingress_firewall_policy_id': common_types.UUIDField(nullable=True),
        'egress_firewall_policy_id': common_types.UUIDField(nullable=True),
        'admin_state_up': obj_fields.BooleanField(default=True),
        'status': FirewallGroupStatusEnumField(nullable=True),
        'shared': obj_fields.BooleanField(default=False),
        'port_associations': obj_fields.ListOfObjectsField(
            'FirewallGroupPortAssociation', nullable=True),
        'ingress_firewall_policy': obj_fields.ObjectField(
            'FirewallPolicy', nullable=True),
        'egress_firewall_policy': obj_fields.ObjectField(
            'FirewallPolicy', nullable=True),
    }

    # Maps each policy synthetic field to the FK column on this object
    # that references FirewallPolicy.id
    _policy_synthetic_field_keys = {
        'ingress_firewall_policy': 'ingress_firewall_policy_id',
        'egress_firewall_policy': 'egress_firewall_policy_id',
    }

    synthetic_fields = [
        'port_associations',
        'ingress_firewall_policy',
        'egress_firewall_policy',
    ]

    fields_no_update = ['project_id']

    @classmethod
    def update_status(cls, context, id, status, not_in=None):
        not_in = not_in or []
        return context.session.query(cls.db_model).filter(
            cls.db_model.id == id
        ).filter(
            ~cls.db_model.status.in_(not_in)
        ).update({'status': status}, synchronize_session=False)

    def load_synthetic_db_fields(self, db_obj=None):
        """Override to handle multiple FK references to FirewallPolicy.

        The base implementation raises NeutronSyntheticFieldMultipleForeignKeys
        when a child class declares more than one foreign key for the same
        parent. FirewallGroup references FirewallPolicy twice (ingress and
        egress), so we load those fields from the side-loaded relationship
        data in db_obj and delegate the remaining synthetic fields to the
        base class.
        """
        for field, fk_column in self._policy_synthetic_field_keys.items():
            synth_db_name = self.fields_need_translation.get(field, field)
            synth_db_obj = (db_obj.get(synth_db_name, None)
                            if db_obj else None)
            if synth_db_obj is not None:
                setattr(self, field,
                        FirewallPolicy._load_object(
                            self.obj_context, synth_db_obj))
            else:
                setattr(self, field, None)
            self.obj_reset_changes([field])

        # Temporarily narrow synthetic_fields so the base class only
        # processes fields we haven't already handled (e.g. port_associations)
        all_synthetic = self.synthetic_fields
        self.synthetic_fields = [
            f for f in all_synthetic
            if f not in self._policy_synthetic_field_keys
        ]
        try:
            super().load_synthetic_db_fields(db_obj)
        finally:
            self.synthetic_fields = all_synthetic


@base.NeutronObjectRegistry.register
class DefaultFirewallGroup(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.DefaultFirewallGroup

    primary_keys = ['project_id']

    fields = {
        'project_id': obj_fields.StringField(),
        'firewall_group_id': common_types.UUIDField(),
    }

    fields_no_update = ['firewall_group_id']
