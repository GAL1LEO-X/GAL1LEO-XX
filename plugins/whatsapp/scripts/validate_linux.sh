#!/bin/sh
# Run only in the isolated project checkout. Does not install/start system services.
set -eu
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/python -m pip --disable-pip-version-check install -q -r requirements-test.lock
.venv/bin/python -m pip --disable-pip-version-check install -q --no-deps -e .
.venv/bin/python -m pytest -q --tb=short --junitxml=validation-linux.xml

