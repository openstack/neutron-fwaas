#!/usr/bin/env bash

set -xe

FWAAS_DIR="$BASE/new/neutron-fwaas"
NEUTRON_DIR="$BASE/new/neutron"
TEMPEST_DIR="$BASE/new/tempest"
SCRIPTS_DIR="/usr/os-testr-env/bin"

venv=${1:-"dsvm-functional"}

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .stestr
    if [ -f ".stestr/0" ] ; then
        .tox/$venv/bin/subunit-1to2 < .stestr/0 > ./stestr.subunit
        $SCRIPTS_DIR/subunit2html ./stestr.subunit testr_results.html
        gzip -9 ./stestr.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}

function dsvm_functional_prep_func {
    :
}

if [[ "$venv" == dsvm-functional* ]]
then
    owner=stack
    sudo_env=
    # Set owner permissions according to job's requirements.
    cd $FWAAS_DIR
    sudo chown -R $owner:stack $FWAAS_DIR
    sudo chown -R $owner:stack $NEUTRON_DIR
    # Prep the environment according to job's requirements.
    $prep_func

    # Run tests
    echo "Running neutron-fwaas $venv test suite"
    set +e
    sudo -H -u $owner $sudo_env tox -e $venv
    testr_exit_code=$?
    set -e

    # Collect and parse results
    generate_testr_results
    exit $testr_exit_code
fi
