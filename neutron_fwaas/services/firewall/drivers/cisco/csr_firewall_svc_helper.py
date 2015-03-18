# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

from networking_cisco.plugins.cisco.cfg_agent.service_helpers import (
    service_helper)
from neutron.common import log
from neutron.common import rpc as n_rpc
from neutron import context as n_context
from neutron.i18n import _LE
from neutron.plugins.common import constants
from oslo_log import log as logging
import oslo_messaging

from neutron_fwaas.services.firewall.drivers.cisco import csr_acl_driver

LOG = logging.getLogger(__name__)

CSR_FW_EVENT_Q_NAME = 'csr_fw_event_q'
CSR_FW_EVENT_CREATE = 'FW_EVENT_CREATE'
CSR_FW_EVENT_UPDATE = 'FW_EVENT_UPDATE'
CSR_FW_EVENT_DELETE = 'FW_EVENT_DELETE'


class CsrFirewalllPluginApi(object):
    """CsrFirewallServiceHelper (Agent) side of the ACL RPC API."""

    @log.log
    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    @log.log
    def get_firewalls_for_device(self, context, **kwargs):
        """Get Firewalls with rules for a device from Plugin."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_firewalls_for_device', host=self.host)

    @log.log
    def get_firewalls_for_tenant(self, context, **kwargs):
        """Get Firewalls with rules for a tenant from the Plugin."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_firewalls_for_tenant', host=self.host)

    @log.log
    def get_tenants_with_firewalls(self, context, **kwargs):
        """Get Tenants that have Firewalls configured from plugin."""
        cctxt = self.client.prepare()
        return cctxt.call(context,
                         'get_tenants_with_firewalls', host=self.host)

    @log.log
    def set_firewall_status(self, context, fw_id, status, status_data=None):
        """Make a RPC to set the status of a firewall."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_firewall_status', host=self.host,
                         firewall_id=fw_id, status=status,
                         status_data=status_data)

    def firewall_deleted(self, context, firewall_id):
        """Make a RPC to indicate that the firewall resources are deleted."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'firewall_deleted', host=self.host,
                         firewall_id=firewall_id)


class CsrFirewallServiceHelper(object):

    @log.log
    def __init__(self, host, conf, cfg_agent):
        super(CsrFirewallServiceHelper, self).__init__()
        self.conf = conf
        self.cfg_agent = cfg_agent
        self.fullsync = True
        self.event_q = service_helper.QueueMixin()
        self.fw_plugin_rpc = CsrFirewalllPluginApi(
            'CISCO_FW_PLUGIN', conf.host)
        self.topic = 'CISCO_FW'
        self._setup_rpc()

        self.acl_driver = csr_acl_driver.CsrAclDriver()

    def _setup_rpc(self):
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [self]
        self.conn.create_consumer(self.topic,
                                  self.endpoints, fanout=True)
        self.conn.consume_in_threads()

    ### Notifications from Plugin ####

    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""
        LOG.debug("create_firewall: firewall %s", firewall)
        event_data = {'event': CSR_FW_EVENT_CREATE,
                      'context': context,
                      'firewall': firewall,
                      'host': host}
        self.event_q.enqueue(CSR_FW_EVENT_Q_NAME, event_data)

    def update_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to update a firewall."""
        LOG.debug("update_firewall: firewall %s", firewall)
        event_data = {'event': CSR_FW_EVENT_UPDATE,
                      'context': context,
                      'firewall': firewall,
                      'host': host}
        self.event_q.enqueue(CSR_FW_EVENT_Q_NAME, event_data)

    def delete_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to delete a firewall."""
        LOG.debug("delete_firewall: firewall %s", firewall)
        event_data = {'event': CSR_FW_EVENT_DELETE,
                      'context': context,
                      'firewall': firewall,
                      'host': host}
        self.event_q.enqueue(CSR_FW_EVENT_Q_NAME, event_data)

    def _invoke_firewall_driver(self, context, firewall, func_name):
        LOG.debug("_invoke_firewall_driver: %s", func_name)
        try:
            if func_name == 'delete_firewall':
                return_code = self.acl_driver.__getattribute__(func_name)(
                    None, None, firewall)
                if not return_code:
                    LOG.debug("firewall %s", firewall['id'])
                    self.fw_plugin_rpc.set_firewall_status(
                        context, firewall['id'], constants.ERROR)
                else:
                    self.fw_plugin_rpc.firewall_deleted(
                        context, firewall['id'])
            else:
                return_code, status = self.acl_driver.__getattribute__(
                    func_name)(None, None, firewall)
                if not return_code:
                    LOG.debug("firewall %s", firewall['id'])
                    self.fw_plugin_rpc.set_firewall_status(
                        context, firewall['id'], constants.ERROR)
                else:
                    LOG.debug("status %s", status)
                    self.fw_plugin_rpc.set_firewall_status(
                        context, firewall['id'], constants.ACTIVE, status)
        except Exception:
            LOG.debug("_invoke_firewall_driver: PRC failure")
            self.fullsync = True

    def _process_firewall_pending_op(self, context, firewall_list):
        for firewall in firewall_list:
            firewall_status = firewall['status']
            if firewall_status == 'PENDING_CREATE':
                self._invoke_firewall_driver(
                    context, firewall, 'create_firewall')
            elif firewall_status == 'PENDING_UPDATE':
                self._invoke_firewall_driver(
                    context, firewall, 'update_firewall')
            elif firewall_status == 'PENDING_DELETE':
                self._invoke_firewall_driver(
                    context, firewall, 'delete_firewall')

    def _process_fullsync(self):
        LOG.debug("_process_fullsync")
        try:
            context = n_context.get_admin_context()
            tenants = self.fw_plugin_rpc.get_tenants_with_firewalls(
                context)
            LOG.debug("tenants with firewall: %s", tenants)
            for tenant_id in tenants:
                ctx = n_context.Context('', tenant_id)
                firewall_list = self.fw_plugin_rpc.get_firewalls_for_tenant(
                    ctx)
                self._process_firewall_pending_op(ctx, firewall_list)

        except Exception:
            LOG.debug("_process_fullsync: RPC failure")
            self.fullsync = True

    def _process_devices(self, device_ids):
        LOG.debug("_process_devices: device_ids %s", device_ids)
        try:
            for device_id in device_ids:
                ctx = n_context.Context('', device_id)
                firewall_list = self.fw_plugin_rpc.get_firewalls_for_device(
                    ctx)
                self._process_firewall_pending_op(ctx, firewall_list)

        except Exception:
            LOG.debug("_process_devices: RPC failure")
            self.fullsync = True

    def _process_event_q(self):
        while True:
            try:
                event_data = self.event_q.dequeue(CSR_FW_EVENT_Q_NAME)
                if not event_data:
                    return
            except ValueError:
                LOG.debug("_process_event_q: no queue yet")
                return

            LOG.debug("_process_event_q: event_data %s", event_data)
            event = event_data['event']
            context = event_data['context']
            firewall = event_data['firewall']
            if event == CSR_FW_EVENT_CREATE:
                self._invoke_firewall_driver(
                    context, firewall, 'create_firewall')
            elif event == CSR_FW_EVENT_UPDATE:
                self._invoke_firewall_driver(
                    context, firewall, 'update_firewall')
            elif event == CSR_FW_EVENT_DELETE:
                self._invoke_firewall_driver(
                    context, firewall, 'delete_firewall')
            else:
                LOG.error(_LE("invalid event %s"), event)

    def process_service(self, device_ids=None, removed_devices_info=None):
        try:
            if self.fullsync:
                self.fullsync = False
                self._process_fullsync()

            else:
                if device_ids:
                    self._process_devices(device_ids)

                if removed_devices_info:
                    LOG.debug("process_service: removed_devices_info %s",
                              removed_devices_info)
                    # do nothing for now
                else:
                    self._process_event_q()

        except Exception:
            LOG.exception(_LE('process_service exception ERROR'))
