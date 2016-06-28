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

function configure_fwaas() {
    neutron_fwaas_configure_driver
}

function init_fwaas() {
    # Initialize and start the service.
    :
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
    _neutron_service_plugin_class_add $FWAAS_PLUGIN
}

function neutron_fwaas_configure_driver {
    # Uses oslo config generator to generate FWaaS sample configuration files
    (cd $NEUTRON_FWAAS_DIR && exec ./tools/generate_config_file_samples.sh)

    cp $NEUTRON_FWAAS_DIR/etc/$FWAAS_DRIVER_CONF_FILENAME.sample $FWAAS_CONF_FILE

    iniset_multiline $FWAAS_CONF_FILE fwaas enabled True
    iniset_multiline $FWAAS_CONF_FILE fwaas driver $FWAAS_DRIVER
    #iniset $NEUTRON_CONF DEFAULT service_plugins $Q_SERVICE_PLUGIN_CLASSES
}

# check for service enabled
if is_service_enabled q-svc && is_service_enabled q-fwaas; then

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
        echo_summary "Configuring q-fwaas"
        configure_fwaas

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
