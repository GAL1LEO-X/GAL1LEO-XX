# Packaging

From the repository root, build a deterministic, self-contained source bundle:

```sh
python tools/build_source.py tesla --output outputs/tesla-source.zip
```

The project-local `build.py --kind source` is also available. Source bundles
are distinct from installable client packages. Python wheels install the
backend; they do not register an app or deploy a server.

The client-package builder requires your real deployed MCP resource, issuer
and registered MCP client ID. Its authenticated discovery check reads a
private token file and verifies the remote tool inventory; the token is not
archived. Run `python plugins/tesla/build.py --help` for explicit arguments.
Example URLs are documentation only and must never be advertised as a working
shared connector. Initial synthetic-pilot packaging has a separate label and
explicitly disables live vehicle calls.

Preserve the existing identity when updating your own installed package.
This public source distribution does not alter a personal app registration
or submit a plugin to a public app directory. Include LICENSE, NOTICE and
third-party notices in every distributed source/backend package.
