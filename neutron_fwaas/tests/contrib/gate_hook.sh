#!/bin/bash

set -ex

# Below variables are set to execute this script
IS_GATE=${IS_GATE:-False}
INSTALL_MYSQL_ONLY=${INSTALL_MYSQL_ONLY:-False}

CONTRIB_DIR="$BASE/new/neutron-fwaas/neutron_fwaas/tests/contrib"

$BASE/new/devstack-gate/devstack-vm-gate.sh

# Add a rootwrap filter to support test-only
# configuration (e.g. a KillFilter for processes that
# use the python installed in a tox env).
FUNC_FILTER=$CONTRIB_DIR/filters.template
sed -e "s+\$BASE_PATH+$BASE/new/neutron-fwaas/.tox/dsvm-functional+" \
    $FUNC_FILTER | sudo tee /etc/neutron/rootwrap.d/functional.filters > /dev/null

# Use devstack functions to install mysql and psql servers
TOP_DIR=$BASE/new/devstack
source $TOP_DIR/functions
source $TOP_DIR/inc/meta-config
source $TOP_DIR/stackrc
source $TOP_DIR/lib/database
source $TOP_DIR/localrc

# Install_databases [install_pg]
# Tweak the script accordingly if we need psql in future
function _install_databases {
    local install_pg=${1:-True}

    echo_summary "Installing databases"

    # Avoid attempting to configure the db if it appears to already
    # have run.  The setup as currently defined is not idempotent.
    if mysql openstack_citest > /dev/null 2>&1 < /dev/null; then
        echo_summary "DB config appears to be complete, skipping."
        return 0
    fi

    enable_service mysql
    initialize_database_backends
    install_database
    configure_database_mysql

    if [[ "$install_pg" == "True" ]]; then
        enable_service postgresql
        initialize_database_backends
        install_database
        configure_database_postgresql
    fi

    # Set up the 'openstack_citest' user and database in each backend
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    cat << EOF > $tmp_dir/mysql.sql
CREATE DATABASE openstack_citest;
CREATE USER 'openstack_citest'@'localhost' IDENTIFIED BY 'openstack_citest';
CREATE USER 'openstack_citest' IDENTIFIED BY 'openstack_citest';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest'@'localhost';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest';
FLUSH PRIVILEGES;
EOF
    /usr/bin/mysql -u root < $tmp_dir/mysql.sql

    if [[ "$install_pg" == "True" ]]; then
        cat << EOF > $tmp_dir/postgresql.sql
CREATE USER openstack_citest WITH CREATEDB LOGIN PASSWORD 'openstack_citest';
CREATE DATABASE openstack_citest WITH OWNER openstack_citest;
EOF

        # User/group postgres needs to be given access to tmp_dir
        setfacl -m g:postgres:rwx $tmp_dir
        sudo -u postgres /usr/bin/psql --file=$tmp_dir/postgresql.sql
    fi
}

if [[ "$IS_GATE" != "True" ]]; then
    if [[ "$INSTALL_MYSQL_ONLY" == "True" ]]; then
        _install_databases nopg
    else
        _install_databases
    fi
fi
