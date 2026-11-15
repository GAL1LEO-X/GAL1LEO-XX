# Installation and configuration

Use Linux, Python 3.13/3.14, an HTTPS domain, an OIDC provider supporting public
OAuth clients with PKCE, and your own Tesla Fleet API application registration.
Read the [Tesla Fleet API documentation](https://developer.tesla.com/docs/fleet-api).
API eligibility, billing and vehicle capabilities remain provider-controlled.

## Install the backend

From a checkout of this public repository:

```sh
python3.14 -m venv .venvs/tesla
.venvs/tesla/bin/python -m pip install -r plugins/tesla/requirements.lock
.venvs/tesla/bin/python -m pip install --no-deps ./plugins/tesla
.venvs/tesla/bin/tesla-plugin --help
```

Copy `deploy/settings.example.json` into a private configuration directory on
the destination host. Replace every example URL, subject, path and client ID.
Keep configuration and state outside the checkout and protect secret files
against other users. Generate new local keys and an owner passphrase hash:

```sh
.venvs/tesla/bin/tesla-plugin init --directory /absolute/private/tesla-keys
.venvs/tesla/bin/tesla-plugin check-config --config /absolute/private/settings.json
```

`init` prompts for a passphrase and refuses to overwrite existing material.
Point the configuration at its generated files. Never copy developer secrets.

## Configure identities and endpoints

The MCP resource must end in `/mcp`. The Tesla callback uses the same HTTPS
origin and base path, ending in `/oauth/callback`. Configure an exact owner
subject, issuer, JWKS URL (or local verification key) and a nonempty allowlist
of registered MCP client IDs. The MCP client and Tesla application client
are separate registrations. Select the appropriate Fleet API region and an
IANA timezone; the public default is UTC. Configure retention and API budget
deliberately; the API limit is separate from streaming billing.

Start with `live_enabled: false`. Serve the backend on loopback behind your
HTTPS reverse proxy. The owner panel is at the base path plus `/owner`.
`tesla-plugin serve --config /absolute/private/settings.json --port 8018`
does not configure DNS, TLS or the identity provider for you. Disable access
logs that would expose OAuth codes and preserve origin/CSRF protections.

## Commands and telemetry

Signed commands require the pinned official vehicle-command proxy with this
project's adapter, a protected signing key, trusted TLS and vehicle-side key
enrollment by the owner. `deploy/components.lock.json` pins upstream sources;
`tools/build-proxy.py` and `tools/build-components.py` provide build entrypoints.
Their help lists required explicit inputs. Do not substitute an unrelated proxy.

Streaming additionally requires a configured Fleet Telemetry receiver, Kafka
broker and the `consume` process. `deploy/receiver.example.json` and the systemd
templates are examples to adapt to your service accounts and paths. Keep
telemetry infrastructure private. Collection changes require a cost review,
confirmation and Tesla readback. Do not enable collection merely to install.

Once the instance is configured, explicitly enable live mode, connect your
own Tesla account and grant only the needed permissions. Pairing a vehicle,
enrolling keys and performing physical commands are owner operations, separate
from the synthetic development tests.
