# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# Copyright 2015 Yalei Wang <yalei.wang at intel com>
#
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
#
#  This script uses SMC-API to get/post elements from SMC server
#

import abc
import netaddr
import requests
import six

from contextlib import contextmanager
from neutron.common import exceptions as n_exc
from neutron.i18n import _LE, _LI, _LW
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron_fwaas.services.firewall.drivers.mcafee import constants as const

LOG = logging.getLogger(__name__)


class SMCAPIResult(object):
    """Class for returning result to API caller"""

    def __init__(self, tp):
        self.type = tp
        self.result = "N/A"
        self.code = "200"
        self.headers = None

    def is_json(self):
        return self.type == "json"

    def is_text(self):
        return self.type == "text"

    def __str__(self):
        return self.result


class SMCAPIConnection(object):
    """Provide the REST API method to connect to the SMC server.

    For login/logout operation, users should set server IP, API version and
    auth key first. For get/put/delete operation, users should provide the
    target element'path, and special json format data section followed "SMC
    API User's Guide".
    """
    def __init__(self, host, api_version, authentication_key):
        self.cookies = {}
        self.host = host
        self.api_version = api_version
        self.host_api_url = self.host + "/" + self.api_version
        self.auth_key = authentication_key
        self.session = None

    @contextmanager
    def login_server(self):
        if self.session:
            yield
        else:
            ret = self.login()
            LOG.debug("SMC server LOGIN successfully.")

            if ret:
                try:
                    yield
                except Exception:
                    LOG.exception(_LE("exception while connect to server!"))
                    raise n_exc.ServiceUnavailable(resource='SMC server',
                                                   msg=_("OPERATION failed"))

                finally:
                    self.logout()

            else:
                raise n_exc.BadRequest(resource='SMC server',
                                       msg=_("LOGIN failed!"))

    def login(self):
        self.session = requests.session()

        post_addr = ("%s/login?authenticationkey=%s&beta=true" %
                     (self.host_api_url, self.auth_key))
        res = self.session.post(post_addr)

        if res.status_code == 200:
            return True

        LOG.error(_LE("connect to %(host)s failed"
                      " (%(msg)s/ code %(code)s)"),
                  {'host': post_addr,
                   'msg': res.reason,
                   'code': res.status_code})

        return False

    def logout(self):
        result = self.session.put("%s/logout" % (self.host_api_url))
        self.session = None
        LOG.debug("LOGOUT from SMC server result %s", result)

    def session_op(self, attr, path, raw=False, data=None, headers=None):
        op = getattr(self.session, attr)

        if raw:
            result = op(path, headers=headers, data=data)
        else:
            result = op("%s/%s" %
                        (self.host_api_url, path), headers=headers, data=data)

        if result.status_code == "404":
            LOG.error(_LE("SMC Error 404 %s"), result.reason)

        return result

    def get(self, path, etag=None, raw=False):
        json_result = None
        etag_out = None
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        if etag:
            headers['ETag'] = etag

        try:
            result = self.session_op("get", path, raw, headers=headers)

            if 'etag' in result.headers:
                etag_out = result.headers['etag']

            json_result = result.json()

            if result.status_code == "404":
                LOG.error(_LE("%(msg)s %(detail)s"),
                          {'msg': json_result["message"],
                           'detail': json_result["details"]})

        except Exception:
            LOG.error(_LE("exception when GET operation"))
            raise

        r = [json_result]
        if etag_out:
            r.append(etag_out)

        return [json_result]

    def check_ret(self, string, path, ret, updated_result):
        if ret.status_code != 200:
            LOG.info(_LI("%(str)s ELEMENT result code: %(stat)d "
                         "%(path)s %(reason)s text=%(text)s"),
                    {'str': string, 'path': path,
                     'stat': ret.status_code,
                     'reason': ret.reason,
                     'text': ret.text})

            updated_result.type = "text"
            updated_result.result = ret.text
        else:
            if ret.headers.get('content-type') == "application/json":
                updated_result.type = "json"
                updated_result.result = ret.json
            else:
                updated_result.type = "text"
                updated_result.result = ret.content
        updated_result.code = ret.status_code

    def delete(self, path, raw=False):
        del_result = SMCAPIResult("text")

        try:
            result = self.session_op("delete", path, raw)
            self.check_ret("DELETE", path, result, del_result)

        except Exception:
            LOG.error(_LE("exception when DELETE operation"))
            raise

        return del_result

    def post(self, path, json_element, raw=False):
        headers = {'accept': '*/*',
                   'content-type': 'application/json'}
        post_result = SMCAPIResult("text")

        try:
            result = self.session_op(
                "post", path, raw, headers=headers, data=json_element)
            self.check_ret("POST", path, result, post_result)
            post_result.headers = result.headers
        except Exception:
            LOG.error(_LE("exception when POST operation"))
            raise

        return post_result

    def post_element(self, element_type, json_element):
        return self.post("elements/%s" % (element_type), json_element)


@six.add_metaclass(abc.ABCMeta)
class SMCAPIElement(object):
    """
    Base class of elements, used by L2/L3 single firewall class
    """
    element_type = "N/A"

    @staticmethod
    def usage(extra_info=None):
        if extra_info:
            LOG.error(_LE("Error -> %s"), extra_info)
        raise ValueError(_('Wrong initial data!'))

    def __init__(self, name, smc_api_connection, control_ip=None):

        if not name:
            self.usage("name of element missing.")

        self.name = name
        self.element_id = 0
        self.json_element = None
        self.element_template = None
        self.smc_api_connection = smc_api_connection
        self.keyboard = None
        self.timezone = None
        if control_ip:
            self.control_ip = netaddr.IPNetwork(control_ip)
            if self.control_ip.prefixlen == 32:
                self.usage(
                        "Control_ip %s needs to netmask bits e.g x.x.x.x/yy"
                        % (self.control_ip))
        else:
            self.control_ip = None

    def to_json(self):
        return jsonutils.dumps(self.json_element)

    @abc.abstractmethod
    def create(self):
        raise NotImplementedError(
            "not support SMCAPIElement create")

    @abc.abstractmethod
    def update(self):
        raise NotImplementedError(
            "not support SMCAPIElement update")

    @abc.abstractmethod
    def delete(self):
        raise NotImplementedError(
            "not support SMCAPIElement delete")

    def get_element(self, path):
        LOG.debug("Getting path: %s", path)
        return self.smc_api_connection.get("elements/%s" % (path))

    def get_elements(self, element_type=None):
        if not element_type:
            element_type = self.element_type

        return self.smc_api_connection.get("elements/%s" % (element_type))

    def fetch_element_id(self):
        json_result = self.get_elements()

        if not json_result[0]['result']:
            LOG.warn(_LW("No #{element_type} defined in SMC"))
        else:
            for element in json_result[0]['result']:
                href = element['href']
                self.element_id = int(href.split('/')[-1])
                if element['name'] == self.name:
                    LOG.debug("%(type)s element with name %(name)s FOUND "
                              "%(href)s",
                              {'type': self.element_type,
                               'name': self.name,
                               'href': href})
                    break

        LOG.debug("Got ID %s", self.element_id)
        return self.element_id

    def get_initial_contact_data(self):
        """Get the element's configuration data used to contact to SMC server.

        Contact data is a configuration string including the SMC server's IP,
        interfaces defined and special one-time password.
        eg. first create the L3 element on behalf of sg-engine in SMC server
        and generate the contact data, then boot the sg-engine with it and
        engine will init properly and connect to SMC server finally.
        """

        data = None
        result = self.get_element("%s/%s/node" %
                                  (self.element_type, self.element_id))
        LOG.debug("resule = %s", result)

        node_ref = result[0]['result'][0]['href'].replace(
            self.smc_api_connection.host_api_url + "/elements/", "")

        LOG.debug("Node ref is %s", node_ref)

        extra_options = []
        if self.keyboard:
            extra_options.append("keyboard=%s" % (self.keyboard))
        if self.timezone:
            extra_options.append("time_zone=%s" % (self.timezone))

        if extra_options:
            extra_options = "&" + extra_options
        else:
            extra_options = ""

        result = self.smc_api_connection.post_element(
            "%s/initial_contact?enable_ssh=true%s" %
            (node_ref, extra_options), "")
        if result.is_text():
            d1 = str(result).split("\n")
            idx = 0
            for l in d1:
                if l.find("ssh/enabled") != -1:
                    l = l.replace("false", "true")
                    d1[idx] = l
                idx += 1
            result.result = "\n".join(d1)
            data = result

        result = self.smc_api_connection.post_element(
            "%s/bind_license" % (node_ref), "")

        if result.code != 200:
            LOG.error(_LE("Could not bind license. "
                          "Maybe SMC license pool is empty. "
                          "SMC API details: %s"), result)
        return data


class SMCAPIElementL2FWSingle(SMCAPIElement):
    """L2 single firewall element."""
    element_type = "single_layer2"

    def __init__(self, name, smc_api_connection, control_ip):
        SMCAPIElement.__init__(self, name, smc_api_connection, control_ip)
        self.element_id = 0
        self.json_element = None

    def create(self):
        json_result = self.get_elements("log_server")
        log_server_ref = json_result[0]['result'][0]['href']
        LOG.debug("Using log server '%(name)s', ref %(ref)s",
                  {'name': json_result[0]['result'][0]['name'],
                   'ref': log_server_ref})

        json_result = self.get_elements("logical_interface")

        logical_interfaces = dict((logical_iface['name'],
            logical_iface['href']) for logical_iface in
            json_result[0]['result'] if logical_iface['name']
            in ('default_eth', 'capture'))

        for name, ref in logical_interfaces.iteritems():
            LOG.debug("Using logical interface %(name)s ref %(href)s",
                      {'name': name, 'href': ref})

        json_data = jsonutils.loads(const.L2_ELEMENT_TEMPLATE)

        json_data[const.JSON_LOG_SERVER_REF] = log_server_ref
        json_data[const.JSON_NAME] = self.name
        json_data[const.JSON_NODES][0]['fwlayer2_node']['name'] = (self.name +
                                                                   " node 1")

        physical_ifaces = json_data[const.JSON_PHY_INTERFACES]
        for phys_iface in physical_ifaces:
            for iface in phys_iface[const.JSON_PHY_INTF]['interfaces']:
                if 'inline_interface' in iface:
                    inline_iface = iface['inline_interface']
                    inline_iface['logical_interface_ref'] = (
                        logical_interfaces['default_eth']['href'])
                elif 'capture_interface' in iface:
                    capture_iface = iface['capture_interface']
                    capture_iface['logical_interface_ref'] = (
                        logical_interfaces['capture']['href'])
                elif 'node_interface' in iface:
                    node_iface = iface['node_interface']
                    if not node_iface['primary_mgt']:
                        continue
                    node_iface[const.JSON_NODE_NET_ADDR] = (
                                                    str(self.control_ip.ip))
                    node_iface[const.JSON_NODE_NET_VALUE] = (
                                                    str(self.control_ip.cidr))

        self.json_element = json_data
        self.smc_api_connection.post_element(self.element_type, self.to_json())
        self.fetch_element_id()

    def update(self):
        """Update element """
        pass

    def delete(self):
        """Delete element """
        pass


class SMCAPIElementL3FWSingle(SMCAPIElement):
    """L3 single firewall element."""
    element_type = "single_fw"

    def __init__(self, name, smc_api_connection, control_ip):
        super(SMCAPIElementL3FWSingle, self).__init__(self, name,
                smc_api_connection, control_ip)
        self.element_id = 0
        self.json_element = None
        self.physical_interfaces = []

    def modify_interface_property(self, physical_interface, name, value):
        iface = physical_interface[const.JSON_PHY_INTF]
        iface = iface['interfaces'][0]['single_node_interface']
        iface[name] = value

    def add_physical_interface(self, ip_and_network, interface_id):
        ip = netaddr.IPNetwork(ip_and_network)

        json_data = jsonutils.loads(const.PHYSICAL_INTERFACE_TEMPLATE)
        phys_iface = json_data[const.JSON_PHY_INTF]
        phys_iface['interface_id'] = interface_id
        iface = json_data[const.JSON_PHY_INTF]['interfaces'][0]
        iface = iface['single_node_interface']
        iface[const.JSON_NODE_NET_ADDR] = str(ip.ip)
        iface[const.JSON_NODE_NET_VALUE] = str(ip.cidr)
        self.physical_interfaces.append(json_data)
        return json_data

    def create(self):
        json_result = self.get_elements("log_server")
        log_server_ref = json_result[0]['result'][0]['href']

        LOG.debug(
            "Using log server '%(name)s' ref %(ref)s",
            {'name': json_result[0]['result'][0]['name'],
             'ref': log_server_ref})

        json_data = jsonutils.loads(const.L3_ELEMENT_TEMPLATE)
        json_data[const.JSON_LOG_SERVER_REF] = log_server_ref
        json_data[const.JSON_NAME] = self.name
        json_data[const.JSON_NODES][0]['firewall_node']['name'] = (self.name +
                                                                   " node 1")
        iface = self.add_physical_interface(self.control_ip, 0)
        self.modify_interface_property(iface, "primary_mgt", True)
        for phys_iface in self.physical_interfaces:
            json_data[const.JSON_PHY_INTERFACES].append(phys_iface)

        LOG.debug("%s",
                  jsonutils.dumps(json_data, sort_keys=False,
                                  indent=2, separators=(',', ': ')))

        self.json_element = json_data
        self.smc_api_connection.post_element(self.element_type, self.to_json())
        self.fetch_element_id()
