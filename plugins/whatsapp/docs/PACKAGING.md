# Packaging

Build a deterministic source distribution from the public checkout:

```sh
python tools/build_source.py whatsapp --output outputs/whatsapp-source.zip
```

The source bundle includes the shared host/tool code needed by the project.
A Python wheel installs the backend only; server provisioning and app
registration are separate. Source and wheel distributions include license,
attribution and third-party notices.

## Portable MCP client package

After deploying your own service, supply its actual endpoint and portal:

```sh
python tools/build_plugin.py --mode portable --name whatsapp-personal --version 0.3.0 --mcp-url https://YOUR_HOST/mcp --connect-url https://YOUR_HOST/connect --output outputs/whatsapp-portable.zip
```

Replace YOUR_HOST with the independently verified hostname. The package
includes manifest, skills, icon, CONFIGURATION.md and mcp.json. ChatGPT may
classify portable remote-server packages as desktop-only.

## Account-bound web package

Register and authorize your own MCP connection in the destination account,
then build `--mode web` with its verified `--app-id asdk_app_...` and
`--connect-url`. Omit `--mcp-url`. This includes exactly one required app
dependency in .app.json and no alternate MCP connection. The builder checks
ID syntax, not ownership. Never copy another account's app registration.

Validate a completed package using `--validate-zip`, the expected mode,
`--expected-name` and, for web packages, the verified `--app-id`.
Updating an existing installation must preserve its verified identity and
use its existing update workflow. Repository publication does not update
personal plugin installations or submit a public app-directory listing.
