#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
browser_deps=false
if [[ "${1:-}" == "--with-browser-deps" ]]; then browser_deps=true
elif [[ $# -ne 0 ]]; then echo "Usage: $0 [--with-browser-deps]" >&2; exit 2; fi
python_bin="${PYTHON_BIN:-}"
if [[ -z "$python_bin" ]]; then
  for candidate in python3.13 python3.14 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; assert (3,13) <= sys.version_info[:2] <= (3,14)' 2>/dev/null; then
      python_bin="$candidate"; break
    fi
  done
fi
if [[ -z "$python_bin" ]]; then echo 'Python 3.13 or 3.14 required; set PYTHON_BIN.' >&2; exit 1; fi
"$python_bin" -c 'import sys; assert (3,13) <= sys.version_info[:2] <= (3,14); print(sys.version)'
node -e 'if(process.versions.node.split(".")[0]!=="24") throw Error("Node.js 24.x required"); console.log(process.version)'
mkdir -p .venvs
# Shared with project.py prepare. Always browser first, then the Python venv;
# hold both through npm/Chromium preparation, including --with-browser-deps.
exec 8>.venvs/browser.setup.lock
flock -n 8 || { echo 'The shared browser environment is being prepared by another process.' >&2; exit 1; }
exec 9>.venvs/whatsapp.setup.lock
flock -n 9 || { echo 'The default virtualenv is being prepared by another process.' >&2; exit 1; }
if [[ -x .venvs/whatsapp/bin/python ]]; then
  expected_version=$("$python_bin" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  .venvs/whatsapp/bin/python -c 'import sys; assert "%d.%d" % sys.version_info[:2] == sys.argv[1], "Existing venv uses another Python version"' "$expected_version"
fi
"$python_bin" -m venv .venvs/whatsapp
py=.venvs/whatsapp/bin/python
"$py" -m pip --disable-pip-version-check install -q -r plugins/whatsapp/requirements-test.lock
"$py" -m pip --disable-pip-version-check install -q --no-deps -e plugins/whatsapp
"$py" tools/cloud/sync_dependencies.py --prune
"$py" -m pip check
npm ci --ignore-scripts --no-audit --no-fund
if $browser_deps; then
  npx --no-install playwright install --with-deps chromium
else
  npx --no-install playwright install chromium
fi
mkdir -p work/test-results
echo 'PLUGINS setup complete. Run bash tools/cloud/check.sh.'

