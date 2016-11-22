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

function pre_install_fwaas() {
    # Install OS packages if necessary with "install_package ...".
    :
    neutron_fwaas_configure_common
}

function install_fwaas() {
    # Install the service.
    :
    setup_develop $DEST/neutron-fwaas
}

function configure_fwaas_v1() {
    neutron_fwaas_configure_driver fwaas
    iniset_multiline $Q_L3_CONF_FILE fwaas agent_version v1
}

function configure_fwaas_v2() {
    neutron_fwaas_configure_driver fwaas_v2
    iniset_multiline $Q_L3_CONF_FILE fwaas agent_version v2
}

function init_fwaas() {
    # Initialize and start the service.
    :
    if [ ! -d /etc/neutron/policy.d ]; then
        mkdir /etc/neutron/policy.d
    fi
    cp $DEST/neutron-fwaas/etc/neutron/policy.d/neutron-fwaas.json /etc/neutron/policy.d/neutron-fwaas.json
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
    if is_service_enabled q-fwaas-v1; then
        _neutron_service_plugin_class_add $FWAAS_PLUGIN_V1
    elif is_service_enabled q-fwaas-v2; then
        _neutron_service_plugin_class_add $FWAAS_PLUGIN_V2
    else
        _neutron_service_plugin_class_add $FWAAS_PLUGIN_V1
    fi
}

function neutron_fwaas_configure_driver {
    plugin_agent_add_l3_agent_extension $1
    configure_l3_agent
    iniset_multiline $Q_L3_CONF_FILE fwaas enabled True
    iniset_multiline $Q_L3_CONF_FILE fwaas driver $FWAAS_DRIVER
}

# check for service enabled
if is_service_enabled q-svc && ( is_service_enabled q-fwaas || is_service_enabled q-fwaas-v1 || is_service_enabled q-fwaas-v2 ) then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services q-fwaas"
        pre_install_fwaas

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing q-fwaas"
        install_fwaas

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        if is_service_enabled q-fwaas-v1; then
            echo_summary "Configuring q-fwaas for FWaaS v1"
            configure_fwaas_v1
        elif is_service_enabled q-fwaas-v2; then
            echo_summary "Configuring q-fwaas for FWaaS v2"
            configure_fwaas_v2
        else
            echo_summary "Configuring q-fwaas for FWaaS v1"
            configure_fwaas_v1
        fi

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the q-fwaas service
        echo_summary "Initializing q-fwaas"
        init_fwaas
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down q-fwaas services
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
