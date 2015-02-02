# Copyright 2015 Intel Corporation.
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


JSON_PHY_INTERFACES = 'physicalInterfaces'
JSON_NAME = 'name'
JSON_NODES = 'nodes'
JSON_LOG_SERVER_REF = 'log_server_ref'
JSON_NODE_NET_VALUE = 'network_value'
JSON_NODE_NET_ADDR = 'address'
JSON_PHY_INTF = 'physical_interface'

L2_ELEMENT_TEMPLATE = ("""
        {
            'log_server_ref':
                'http://localhost:8082/5.7/elements/log_server/1441',
            'name': '@PLACE_HOLDER@ L2 FW',
            'nodes':
            [
                {
                    'fwlayer2_node': {
                        'name': '@PLACE_HOLDER@ L2 FW node 1',
                        'nodeid': 1
                    }
                }
            ],
            'physicalInterfaces':
            [
                {
                    'physical_interface': {
                        'interface_id': '1',
                        'interfaces':
                        [
                            {
                                'inline_interface': {
                                    'failure_mode': 'normal',
                                    'logical_interface_ref':
                                    'http://localhost:8082/5.7/elements/logical_interface/1',
                                    'nicid': '1-2'
                                }
                            }
                        ]
                    }
                },
                {
                    'physical_interface': {
                        'interface_id': '0',
                        'interfaces':
                        [
                            {
                                'node_interface': {
                                    'address': '192.168.2.10',
                                    'network_value': '192.168.2.0/24',
                                    'nicid': '0',
                                    'nodeid': 1,
                                    'outgoing': true,
                                    'primary_mgt': true
                                }
                            }
                        ]
                    }
                },
                {
                    'physical_interface': {
                        'interface_id': '3',
                        'interfaces':
                        [
                            {
                                'capture_interface': {
                                    'logical_interface_ref':
                                    'http://localhost:8082/5.7/elements/logical_interface/1073741835',
                                    'nicid': '3'
                                }
                            }
                        ]
                    }
                }
            ]
        }
        """)

L3_ELEMENT_TEMPLATE = ("""
        {
            "alias_value": [
            ],
            "antivirus": {
                "antivirus_enabled": false,
                "virus_log_level": "none",
                "virus_mirror": "database.clamav.net"
            },
            "auto_reboot_timeout": 10,
            "connection_limit": 0,
            "connection_timeout": [
                {
                    "protocol": "icmp",
                    "timeout": 5
                },
                {
                    "protocol": "other",
                    "timeout": 180
                },
                {
                    "protocol": "tcp",
                    "timeout": 1800
                },
                {
                    "protocol": "udp",
                    "timeout": 50
                }
            ],
            "contact_timeout": 60000,
            "default_nat": false,
            "domain_server_address": [
            ],
            "dos_protection": "always_off",
            "excluded_interface": -1,
            "is_cert_auto_renewal": true,
            "is_config_encrypted": true,
            "is_fips_compatible_operating_mode": false,
            "is_loopback_tunnel_ip_address_enforced": false,
            "is_virtual_defrag": true,
            "log_moderation": [
                {
                    "burst": 1000,
                    "log_event": "1",
                    "rate": 100
                },
                {
                    "log_event": "2"
                }
            ],
            "log_server_ref": "@PLACE_HOLDER@",
            "log_spooling_policy": "discard",
            "loopback_cluster_virtual_interface": [
            ],
            "name": "@PLACE_HOLDER@",
            "nodes": [
                {
                    "firewall_node": {
                        "activate_test": true,
                        "disabled": false,
                        "loopback_node_dedicated_interface": [
                        ],
                        "name": "@NODE_NAME_PLACE_HOLDER@",
                        "nodeid": 1
                    }
                }
            ],
            "passive_discard_mode": false,
            "physicalInterfaces": [
            ],
            "read_only": false,
            "rollback_timeout": 60,
            "scan_detection": {
                "scan_detection_icmp_events": 252,
                "scan_detection_icmp_timewindow": 60,
                "scan_detection_tcp_events": 252,
                "scan_detection_tcp_timewindow": 60,
                "scan_detection_type": "default off",
                "scan_detection_udp_events": 252,
                "scan_detection_udp_timewindow": 60
            },
            "slow_request_blacklist_timeout": 300,
            "slow_request_sensitivity": "off",
            "strict_tcp_mode": false,
            "syn_flood_sensitivity": "off",
            "syn_mode": "off",
            "system": false,
            "tcp_reset_sensitivity": "OFF",
            "tester_parameters": {
                "alert_interval": 3600,
                "auto_recovery": true,
                "boot_delay": 30,
                "boot_recovery": true,
                "restart_delay": 5,
                "status_delay": 5
            },
            "tracking_mode": "normal"
        }
        """)

PHYSICAL_INTERFACE_TEMPLATE = ("""
        {
            "physical_interface": {
                "aggregate_mode": "none",
                "arp_entry": [
                ],
                "cvi_mode": "none",
                "dhcp_server_on_interface": {
                    "dhcp_range_per_node": [
                    ]
                },
                "interface_id": "@PLACE_HODLER@",
                "interfaces": [
                    {
                        "single_node_interface": {
                            "address": "@PLACE_HOLDER_IP@",
                            "auth_request": false,
                            "auth_request_source": false,
                            "backup_heartbeat": false,
                            "backup_mgt": false,
                            "dynamic_ip": false,
                            "igmp_mode": "none",
                            "key": 200,
                            "modem": false,
                            "network_value": "@PLACE_HOLDER_IP_NETWORK@",
                            "nicid": "0",
                            "nodeid": 1,
                            "outgoing": false,
                            "pppoa": false,
                            "pppoe": false,
                            "primary_heartbeat": false,
                            "primary_mgt": false,
                            "relayed_by_dhcp": false,
                            "reverse_connection": false,
                            "vrrp": false,
                            "vrrp_id": -1,
                            "vrrp_priority": -1
                        }
                    }
                ],
                "log_moderation": [
                    {
                        "burst": 1000,
                        "log_event": "1",
                        "rate": 100
                    },
                    {
                        "log_event": "2"
                    }
                ],
                "managed_address_flag": false,
                "mtu": -1,
                "other_configuration_flag": false,
                "qos_limit": -1,
                "qos_mode": "no_qos",
                "router_advertisement": false,
                "syn_mode": "default",
                "virtual_engine_vlan_ok": false,
                "vlanInterfaces": [
                ]
            }
        }
        """)
