#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
backend_only=false
py=.venvs/whatsapp/bin/python
results=work/test-results
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-only) backend_only=true; shift ;;
    --python|--results-dir)
      if [[ $# -lt 2 || -z "$2" ]]; then echo "Missing value for $1" >&2; exit 2; fi
      if [[ "$1" == --python ]]; then py=$2; else results=$2; fi
      shift 2 ;;
    *) echo "Usage: $0 [--backend-only] [--python PATH] [--results-dir PATH]" >&2; exit 2 ;;
  esac
done
if [[ ! -x "$py" ]]; then echo 'Run tools/cloud/bootstrap.sh first.' >&2; exit 1; fi
mkdir -p "$results"
export PLUGINS_TEST_PYTHON="$py"
export PLUGINS_TEST_RESULTS_DIR="$results"
"$py" tools/check_repository.py
"$py" tools/cloud/sync_dependencies.py
"$py" -m pip check
"$py" -m pytest plugins/whatsapp/tests -q --tb=short --junitxml="$results/backend.xml"
"$py" -m pytest tools/tests -q --tb=short --junitxml="$results/tooling.xml"
if $backend_only; then
  echo 'PASS backend and packaging; browser checks not run.'
else
  # Only this suite owns the fixed fixture ports 8875/8876 and legacy screenshots.
  # Independent Python commands and other plugins do not need this lock.
  (
    mkdir -p .venvs
    exec {port_lock}>.venvs/whatsapp.browser-test.lock
    flock -n "$port_lock" || { echo 'WhatsApp browser fixtures are in use (ports 8875/8876).' >&2; exit 1; }
    npm run test:browser
  )
  echo 'PASS complete PLUGINS development checks.'
fi
git rev-parse HEAD
git status --short

