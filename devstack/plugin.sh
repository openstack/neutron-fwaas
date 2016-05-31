#!/bin/bash

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

# Dependencies:
#
# ``functions`` file
# ``DEST`` must be defined

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

# Source in L2 and L3 agent extension management
LIBDIR=$DEST/neutron-fwaas/devstack/lib
source $LIBDIR/l2_agent
source $LIBDIR/l3_agent

function install_fwaas() {
    # Install the service.
    :
    setup_develop $DEST/neutron-fwaas
}

function configure_fwaas_v1() {
    cp $NEUTRON_FWAAS_DIR/etc/neutron_fwaas.conf.sample $NEUTRON_FWAAS_CONF
    neutron_fwaas_configure_driver fwaas
    iniset_multiline $Q_L3_CONF_FILE fwaas agent_version v1
    iniset_multiline $Q_L3_CONF_FILE fwaas conntrack_driver conntrack
    iniset_multiline $Q_L3_CONF_FILE fwaas driver $FWAAS_DRIVER_V1
}

function configure_fwaas_v2() {
    # Add conf file
    cp $NEUTRON_FWAAS_DIR/etc/neutron_fwaas.conf.sample $NEUTRON_FWAAS_CONF
    neutron_fwaas_configure_driver fwaas_v2
    iniset_multiline $Q_L3_CONF_FILE fwaas agent_version v2
    iniset_multiline $Q_L3_CONF_FILE fwaas driver $FWAAS_DRIVER_V2
    iniset $NEUTRON_CORE_PLUGIN_CONF fwaas firewall_l2_driver $FW_L2_DRIVER
    iniset $NEUTRON_CORE_PLUGIN_CONF agent extensions fwaas_v2
}

function neutron_fwaas_generate_config_files {
    (cd $NEUTRON_FWAAS_DIR && exec ./tools/generate_config_file_samples.sh)
}

function init_fwaas() {
    # Initialize and start the service.
    :
    if [ ! -d /etc/neutron/policy.d ]; then
        mkdir /etc/neutron/policy.d
    fi
    cp $DEST/neutron-fwaas/etc/neutron/policy.d/neutron-fwaas.json /etc/neutron/policy.d/neutron-fwaas.json
    # Using sudo to gain the root privilege to be able to copy file to rootwrap.d
    sudo cp $DEST/neutron-fwaas/etc/neutron/rootwrap.d/fwaas-privsep.filters /etc/neutron/rootwrap.d/fwaas-privsep.filters
}

function shutdown_fwaas() {
    # Shut the service down.
    :
}

function cleanup_fwaas() {
    # Cleanup the service.
    :
}

function neutron_fwaas_configure_common {
    if is_service_enabled q-fwaas-v1 neutron-fwaas-v1; then
        neutron_service_plugin_class_add $FWAAS_PLUGIN_V1
    elif is_service_enabled q-fwaas-v2 neutron-fwaas-v2; then
        neutron_service_plugin_class_add $FWAAS_PLUGIN_V2
    else
        neutron_service_plugin_class_add $FWAAS_PLUGIN_V1
    fi
}

function neutron_fwaas_configure_driver {
    plugin_agent_add_l3_agent_extension $1
    configure_l3_agent
    iniset_multiline $Q_L3_CONF_FILE fwaas enabled True
}

# check for service enabled
if is_service_enabled q-svc neutron-api && is_service_enabled q-fwaas q-fwaas-v1 q-fwaas-v2 neutron-fwaas-v1 neutron-fwaas-v2; then

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing neutron-fwaas"
        install_fwaas

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        neutron_fwaas_configure_common
        neutron_fwaas_generate_config_files
        if is_service_enabled q-fwaas-v1 neutron-fwaas-v1; then
            echo_summary "Configuring neutron-fwaas for FWaaS v1"
            configure_fwaas_v1
        elif is_service_enabled q-fwaas-v2 neutron-fwaas-v2; then
            echo_summary "Configuring neutron-fwaas for FWaaS v2"
            configure_fwaas_v2
        else
            echo_summary "Configuring neutron-fwaas for FWaaS v1"
            configure_fwaas_v1
        fi

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the neutron-fwaas service
        echo_summary "Initializing neutron-fwaas"
        init_fwaas
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down neutron-fwaas services
        # no-op
        shutdown_fwaas
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        cleanup_fwaas
    fi
fi

# Restore xtrace
$XTRACE
