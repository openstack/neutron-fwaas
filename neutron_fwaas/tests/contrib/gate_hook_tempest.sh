#!/bin/bash

set -ex

FWAAS_VERSION=$1

GATE_DEST=$BASE/new
GATE_HOOKS=$GATE_DEST/neutron-fwaas/neutron_fwaas/tests/contrib/hooks
DEVSTACK_PATH=$GATE_DEST/devstack
LOCAL_CONF=$DEVSTACK_PATH/local.conf

# Inject config from hook into localrc
function load_rc_hook {
    local hook="$1"
    config=$(cat $GATE_HOOKS/$hook)
    export DEVSTACK_LOCAL_CONFIG+="
# generated from hook '$hook'
${config}
"
}

load_rc_hook api_extensions-base
load_rc_hook api_extensions-${FWAAS_VERSION}
$BASE/new/devstack-gate/devstack-vm-gate.sh
