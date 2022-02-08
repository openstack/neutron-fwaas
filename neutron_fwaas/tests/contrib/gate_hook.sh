#!/bin/bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
FWAAS_PATH=$GATE_DEST/neutron-fwaas
DEVSTACK_PATH=$GATE_DEST/devstack


case $VENV in
    "dsvm-functional"|"dsvm-fullstack")
    # The following need to be set before sourcing
    # configure_for_fwaas_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=neutron-fwaas
    IS_GATE=True

    source $FWAAS_PATH/tools/configure_for_fwaas_func_testing.sh

    configure_host_for_func_testing
    if is_ubuntu || is_suse; then
        install_package libnetfilter-log1
    elif is_fedora; then
        install_package libnetfilter-log
    fi
    ;;
esac
