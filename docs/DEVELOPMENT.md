# Development and verification

Use Linux or WSL, Python 3.13 or 3.14, Git and Node.js 24. Operational
WhatsApp tooling depends on POSIX ownership, file locks and systemd concepts.
Do not run operational installers on a development machine.

From the repository root, create a dedicated environment:

```sh
python3.14 -m venv .venvs/development
.venvs/development/bin/python -m pip install -r plugins/tesla/requirements-test.lock -r plugins/whatsapp/requirements-test.lock
.venvs/development/bin/python -m pip install --no-deps -e plugins/tesla -e plugins/whatsapp
npm ci --ignore-scripts
npx playwright install chromium
```

Run the application suites separately because their fixture modules have
overlapping names. Tests generate synthetic keys and temporary databases.

```sh
.venvs/development/bin/python tools/check_public.py
.venvs/development/bin/python -m pytest plugins/tesla/tests -q
.venvs/development/bin/python -m pytest plugins/whatsapp/tests -q
.venvs/development/bin/python -m pytest tools/tests -q
PLUGINS_TEST_PYTHON=.venvs/development/bin/python npm run test:browser
```

Tesla browser tests use ephemeral loopback HTTPS endpoints. WhatsApp browser
fixtures own loopback ports 8875/8876. They exercise real UI assets while
simulating provider and identity responses; they do not pair a phone or
contact a vehicle. Chromium system libraries must be installed on the host.

`python tools/project.py list` discovers the projects. The existing project
controller also supports explicit per-project/runtime preparation, slots,
checks and builds; `python tools/project.py --help` lists the commands.
Start checks do not install dependencies or operate production services.

`tools/build_source.py` builds a deterministic source archive for either
project, including its required shared host/tool source and license files.
Build Python wheels with `python -m build --wheel plugins/<project>` in a
build environment. Install the wheel into a fresh environment and verify its
CLI and packaged assets before distributing it.

On Windows, run the ownership-sensitive suites inside WSL with the checkout and
virtualenv on a native Linux filesystem (for example, under your WSL home).
A checkout on `/mnt/c` may report writable ancestors and cannot satisfy the
Unix permission guards; do not disable those guards to make tests pass.
