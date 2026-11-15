#!/usr/bin/env bash
# Prepare only the selected plugin/runtime. The shared base owns interpreters.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
for script in tools/cloud/*.sh; do bash -n "$script"; done
if [[ $# -eq 0 || ( $# -eq 1 && "$1" == --dependencies-only ) ]]; then
  python3 tools/project.py list
  echo 'Select: prepare-environment.sh PLUGIN --python PATH [--runtime 3.13|3.14] [--slot NAME]'
  exit 0
fi
plugin=$1
shift
cloud_tools=${PLUGINS_CLOUD_TOOLS:-$(dirname "$root")/.cloud-tools}
export PIP_CACHE_DIR=${PIP_CACHE_DIR:-$cloud_tools/pip-cache}
export npm_config_cache=${npm_config_cache:-$cloud_tools/npm-cache}
export PLAYWRIGHT_BROWSERS_PATH=${PLAYWRIGHT_BROWSERS_PATH:-$cloud_tools/browsers}
exec python3 tools/project.py prepare "$plugin" "$@"
