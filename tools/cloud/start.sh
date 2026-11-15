#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# Read-only startup: no installs, Git writes, services or automatic dispatch.
py=${PLUGINS_TOOL_PYTHON:-$(command -v python3 || command -v python || true)}
if [[ ! -x "$py" ]]; then
  echo 'Python 3.12+ required; no global packages are needed.' >&2
  exit 1
fi
if [[ $# -eq 0 ]]; then exec "$py" "$root/tools/project.py" list; fi
exec "$py" "$root/tools/project.py" start "$@"
