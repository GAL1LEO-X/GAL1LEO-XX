# Public import scope

This distribution provides Tesla 1.0.5 and WhatsApp 0.8.14 source with English
presentation, standalone configuration examples and developer attribution.
Versions identify the application source, not a hosted service deployment.
WhatsApp's companion provider candidate is 0.8.7; SQLite schema remains 8.

The public tree contains selected application code, synthetic regression
fixtures, dependency pins, provider patches and generic host components.
It excludes operational accounts, server snapshots, private Git history,
personal diagnostics, deployment receipts and cross-repository operations.
All example URLs and subjects require operator configuration.

Backend tests, source reconstruction, provider compilation, native client
connection and device-side acceptance are separate checks. Historical
digests in compatibility fixtures and patch manifests describe their
specific source inputs; they do not qualify this public revision or claim
availability of prebuilt releases. No provider runtime image is included.

The public provider reconstruction tool fetches pinned public upstreams,
verifies all patch hashes and checks the resulting Git trees. It needs no
private asset server. The public source lock records the reconstructed trees.
Native compilation and runtime-image redistribution additionally require
dependency-license compliance, corresponding sources where required, and
a fresh runtime qualification. Existing release automation is operator
tooling: configure and qualify your own artifacts before using it.

Anonymized historical test summaries are included in each project’s validation
guide. Public compatibility fixture hashes identify the sanitized source corpus,
not installed private releases. An operator must independently review source
pins before applying administrative tools to an existing installation.
The provider release policy is deliberately unconfigured: start from
`tools/templates/provider-release.example.json` and qualify your own artifacts.
