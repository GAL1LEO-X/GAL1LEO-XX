# Installation and configuration

Use Linux, Python 3.13/3.14, systemd, rootless Podman, an HTTPS reverse proxy,
DNS/TLS for your own domain and an OIDC provider supporting public PKCE
clients. Runtime and administration accounts must be separate. Existing
files, sessions and data require an explicit upgrade plan and backup.

## Install backend dependencies

```sh
python3.14 -m venv .venvs/whatsapp
.venvs/whatsapp/bin/python -m pip install -r plugins/whatsapp/requirements.lock
.venvs/whatsapp/bin/python -m pip install --no-deps ./plugins/whatsapp
.venvs/whatsapp/bin/sally-whatsapp --help
```

The legacy Python import and CLI names are retained for compatibility.
Source alone does not initialize the host installation identity.

## Prepare a destination-specific installation

1. Copy `deploy/installation.example.json` outside the checkout. Set distinct
   durable roots for code, configuration, data, gateway sessions, backups and
   administration. Choose dedicated service accounts and noncolliding ports.
2. Copy `deploy/instance.example.json`. Supply the exact owner subject, HTTPS
   hostname, issuer/JWKS and distinct registered MCP and pairing client IDs.
   Use external OIDC for a new general installation.
3. Validate and render local artifacts using the installation compiler:

   ```sh
   python plugins/whatsapp/scripts/installation_command.py --profile /absolute/installation.json --profile-sha256 SHA256_OF_THAT_FILE validate
   python plugins/whatsapp/scripts/installation_command.py --profile /absolute/installation.json --profile-sha256 SHA256_OF_THAT_FILE render-identity --output work/identity-marker.json
   python plugins/whatsapp/scripts/installation_command.py --profile /absolute/installation.json --profile-sha256 SHA256_OF_THAT_FILE render-runtime --instance /absolute/instance.json --discovery /absolute/reviewed-oidc-discovery.json --output work/rendered-runtime
   ```

   These commands create reviewable files only. They do not configure DNS,
   reserve accounts/ports or install the host marker. Use the actual SHA-256
   of the reviewed input file; the compiler also reports its canonical
   installation identity digest.
4. Build the generic [host components](../../../host/README.md) and the
   application administration bundle. The installation compiler exposes
   `build-administration`, `compile-fresh-administration` and
   `compile-administration`; inspect their help and review the generated
   manifests, owners, paths and effects before installation on your host.
5. Install the protected identity marker and configured profile locator,
   then the reviewed host/administration artifacts. Configuration and
   private keys belong outside the source tree. Runtime startup fails when
   installation identity is missing or mismatched; do not bypass that check.
6. Provision the rootless gateway, service units and HTTPS frontend for the
   selected installation. The scripts in `scripts/` expose explicit plan/
   apply boundaries; they are operational tools, not development bootstrap.
   Choose `frontend: existing` to use a suitable existing reverse proxy.

## Provider and first connection

Reconstruct the companion source with `provider-checkpoint/reconstruct.py`.
Build the paired WAHA/GOWS provider using the pinned recipes and retain the
required third-party sources/notices before redistributing images. The
public repository includes patches and source recipes, not a prebuilt image.
An unmodified or different upstream image does not supply the eight patched
operations. Capability discovery checks the contract before execution.

Start with live account access and sending disabled. Enable phone linking
through the reviewed administration channel, open `/connect`, sign in as
the owner and approve the QR or temporary code on that owner's phone.
QR/codes stay in the portal and never belong in chat, tools or logs.
Separately register/authorize the MCP connection in the target client.
MCP `oauth_client_ids` must be a nonempty allowlist of exact registered IDs.
Pairing and MCP grants are distinct; panel login does not prove either grant.

## Optional transcription and operations

Local transcription uses an isolated worker and the pinned Whisper model in
`transcription-model.json`; automatic model downloads and external inference
fallback are disabled. Follow the transcription skill for explicit job and
language selection. Install optional dependencies in a separate worker
environment only when that feature is requested.

Back up database, encryption keys and gateway session consistently. The
runtime backup/restore tools validate identity and file ownership. Restores
leave a maintenance gate until administrative reconciliation is complete;
restoring is not permission to reconnect or send. Never use live accounts
to run development tests.
