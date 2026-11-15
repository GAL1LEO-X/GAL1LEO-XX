# GAL1LEO-XX

Public, self-hosted projects by **GAL1LEO**. Contact: **info@gal1leo.com**.

| Project | Purpose | Source version |
| --- | --- | --- |
| [Tesla](plugins/tesla/README.md) | Tesla Fleet API, owner console, confirmed commands and telemetry | 1.0.4 |
| [WhatsApp](plugins/whatsapp/README.md) | Searchable archive, messaging, attachments and MCP events | 0.8.13 |

Each operator supplies their own accounts, server, HTTPS domain, identity
provider and credentials. These sources do not connect to a developer-hosted
service and contain no shared account registration or personal data.
Software is available without a license fee; hosting, provider/API usage and
optional model downloads are separate resources supplied by the operator.

## Repository layout

- `plugins/tesla/` and `plugins/whatsapp/`: application code, manifests,
  skills, deployment templates, dependency locks and synthetic tests.
- `host/`: optional shared host administration components used by WhatsApp.
- `tools/`: local project preparation, source packaging and verification.
- `tests/browser/`: isolated desktop and mobile browser fixtures.
- `apps/`: reserved for future public applications.

Start with each project's installation guide and [development instructions](docs/DEVELOPMENT.md).
English is the language for public documentation, interfaces and contributions.
Protocol identifiers and legacy compatibility namespaces are preserved.

## License and attribution

Original GAL1LEO code is licensed under [Apache-2.0](LICENSE).
Third-party components retain their own licenses and notices; see
[Tesla notices](plugins/tesla/THIRD_PARTY_NOTICES.md) and
[WhatsApp notices](plugins/whatsapp/THIRD_PARTY_NOTICES.md).
These independent projects are not official Tesla, WhatsApp or OpenAI products.

See [public import scope](docs/PUBLICATION.md), [security reporting](SECURITY.md)
and [contributing](CONTRIBUTING.md). Test results describe synthetic behavior,
separately from account access, native host integration and device acceptance.
