#!/bin/bash

set -xe

FWAAS_DIR="$BASE/new/neutron-fwaas"
NEUTRON_DIR="$BASE/new/neutron"
TEMPEST_DIR="$BASE/new/tempest"
SCRIPTS_DIR="/usr/os-testr-env/bin"

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .testrepository
    if [ -f ".testrepository/0" ] ; then
        .tox/dsvm-functional/bin/subunit-1to2 < .testrepository/0 > ./testrepository.subunit
        $SCRIPTS_DIR/subunit2html ./testrepository.subunit testr_results.html
        gzip -9 ./testrepository.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}


function dsvm_functional_prep_func {
    :
}


owner=stack
prep_func="dsvm_functional_prep_func"

# Set owner permissions according to job's requirements.
cd $FWAAS_DIR
sudo chown -R $owner:stack $FWAAS_DIR
sudo chown -R $owner:stack $NEUTRON_DIR
# Prep the environment according to job's requirements.
$prep_func

# Run tests
echo "Running neutron dsvm-functional test suite"
set +e
sudo -H -u $owner tox -e dsvm-functional
testr_exit_code=$?
set -e

# Collect and parse results
generate_testr_results
exit $testr_exit_code
