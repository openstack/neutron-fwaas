set -e


IS_GATE=${IS_GATE:-False}
USE_CONSTRAINT_ENV=${USE_CONSTRAINT_ENV:-False}
PROJECT_NAME=${PROJECT_NAME:-neutron-fwaas}
REPO_BASE=${GATE_DEST:-$(cd $(dirname "$BASH_SOURCE")/../.. && pwd)}

source $REPO_BASE/neutron/tools/configure_for_func_testing.sh
