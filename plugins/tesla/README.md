# Tesla MCP integration

Self-hosted Tesla Fleet API and MCP integration by **GAL1LEO** — **info@gal1leo.com**.
Original code is licensed under [Apache-2.0](LICENSE).

Source version **1.0.4** includes authenticated MCP tools, an owner dashboard,
Tesla OAuth, regional Fleet API transport, a pinned signed-command adapter,
persistent telemetry, history, configurable rules and event subscriptions.
The console, skills and descriptive tool output are in English.

## Start here

- [Installation and configuration](docs/INSTALLATION.md)
- [Behavior, privacy and capabilities](docs/BEHAVIOR.md)
- [Packaging](docs/PACKAGING.md)
- [Development and tests](../../docs/DEVELOPMENT.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

Run one owner-bound instance with your own application registration,
credentials, HTTPS endpoint and OAuth identity provider. Live access is
disabled initially. Reading local state never implicitly wakes a vehicle.
Commands require explicit intent and confirmation; events do not execute
commands. Secrets are entered through protected local/owner interfaces.

The catalogue inventories 131 operations and 278 telemetry keys. Counts
describe software contracts, not vehicle qualification or universal hardware
support. Read each operation's schema, availability and limitations. Some
functionality is outside the personal-vehicle scope or unavailable on the
originally supported Model Y hardware. Illustrations are decorative and do
not identify the connected vehicle. Home energy is outside this integration.

This public import does not attest a live deployment, every vehicle model,
delivery of native ChatGPT notifications or device-side command effects.

## Test evidence

See [validation history and anonymized regression data](docs/VALIDATION.md),
including the scope and limits of historical results and current import checks.
