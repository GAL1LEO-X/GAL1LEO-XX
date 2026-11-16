# WhatsApp MCP bridge

Self-hosted bridge by **GAL1LEO** — **info@gal1leo.com**.
Original code is licensed under [Apache-2.0](LICENSE).

Source version **0.8.14**, companion provider **0.8.7**, SQLite schema **8**.
The bridge provides 27 MCP tools and a catalogue of 120 operations, including
archive search, queued sends, streaming attachments, history acquisition,
group operations, subscriptions and optional local audio transcription.
Counts describe implemented contracts; consult capabilities before an action.

- [Installation and configuration](docs/INSTALLATION.md)
- [Behavior and privacy](docs/BEHAVIOR.md)
- [Packaging](docs/PACKAGING.md)
- [Public companion-provider sources](provider-checkpoint/README.md)
- [Development and tests](../../docs/DEVELOPMENT.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

Architecture: personal WhatsApp account → WAHA/GOWS → bridge/SQLite →
HTTPS/OAuth → MCP client. Each instance owns its service account, phone
session, database, keys, queues and OAuth registrations. A server
administrator still has administrative access; this is not isolation from root.

A linked device supplies a working archive, not a guaranteed complete mirror
of the phone. A queued/submitted message is not proof of delivery or reading.
Creating/voting on polls is unsupported; eight operations require the matching
`gows-ab-v1` provider contract. WAHA is an unofficial personal-account
connection with provider-dependent limitations.

Every user supplies their own deployment and account registration. Live
account access, sending and account actions are disabled by default. Phone
pairing and ChatGPT OAuth consent are separate owner steps. The optional
administration panel is disabled unless explicitly configured.

## Test evidence

See [validation history and anonymized regression data](docs/VALIDATION.md),
including the scope and limits of historical results and current import checks.
