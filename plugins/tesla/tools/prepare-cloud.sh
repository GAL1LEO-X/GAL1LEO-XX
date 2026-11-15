#!/usr/bin/env bash
# Project-local preparation only; no global tools, credentials, server or tests.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [[ $# -ne 2 ]]; then
  echo 'Usage: bash plugins/tesla/tools/prepare-cloud.sh /absolute/python3.13 /absolute/python3.14' >&2
  exit 2
fi
python3 "$repo_root/tools/project.py" prepare tesla --runtime 3.13 --python "$1"
python3 "$repo_root/tools/project.py" prepare tesla --runtime 3.14 --python "$2"
