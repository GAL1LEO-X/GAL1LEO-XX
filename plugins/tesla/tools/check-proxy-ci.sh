#!/usr/bin/env bash
# Public dependency setup followed by isolated offline tests/native compilation.
set -euo pipefail
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=${RUNNER_TEMP:?}/tesla-proxy-check
mkdir -p "$work/modules"
readarray -t pin < <(python3 - "$project/deploy/components.lock.json" <<'PY'
import json,sys
lock=json.load(open(sys.argv[1]))
print(lock['vehicle_command']['repository'])
print(lock['vehicle_command']['commit'])
print(lock['go_build_image'])
PY
)
git init -q "$work/upstream"
git -C "$work/upstream" remote add origin "${pin[0]}"
git -C "$work/upstream" fetch -q --depth 1 origin "${pin[1]}"
git -C "$work/upstream" checkout -q --detach FETCH_HEAD
docker --host=unix:///var/run/docker.sock run --rm -v "$work/upstream:/source:ro" -v "$work/modules:/go/pkg/mod" -w /source "${pin[2]}" go mod download
python3 "$project/tools/build-proxy.py" --upstream-checkout "$work/upstream" --module-cache "$work/modules" --work "$work/build"
cat "$work/build/tests.log"
