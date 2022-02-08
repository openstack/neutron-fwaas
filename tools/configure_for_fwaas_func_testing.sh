set -e


IS_GATE=${IS_GATE:-False}
USE_CONSTRAINT_ENV=${USE_CONSTRAINT_ENV:-False}
PROJECT_NAME=${PROJECT_NAME:-neutron-fwaas}
REPO_BASE=${GATE_DEST:-$(cd $(dirname "$BASH_SOURCE")/../.. && pwd)}

source $REPO_BASE/neutron/tools/configure_for_func_testing.sh
NEUTRON_FWAAS_DIR=$REPO_BASE/neutron-fwaas
source $NEUTRON_FWAAS_DIR/devstack/plugin.sh

function _install_fw_package {
    echo_summary "Installing fw packs"
    if is_ubuntu; then
        install_package conntrack
    else
        # EPEL
        install_package conntrack-tools
    fi
}

function configure_host_for_fwaas_func_testing {
    echo_summary "Configuring for Fwaas functional testing"
    if [ "$IS_GATE" == "True" ]; then
        configure_host_for_func_testing
    fi
    _install_fw_package
}


if [ "$IS_GATE" != "True" ]; then
    configure_host_for_fwaas_func_testing
fi
