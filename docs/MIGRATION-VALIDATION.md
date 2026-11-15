# Public import validation

Import date: 2026-11-15. Developer: **GAL1LEO — info@gal1leo.com**.

The authoritative full-suite execution records are the
[checks on the public import PR](https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/2/checks).
The publication gate requires every Python 3.13/3.14 matrix job to pass before
integration. The matrix runs Tesla, WhatsApp, shared tooling and desktop/mobile
browser suites independently. Consult the linked jobs for exact commit,
interpreter versions, pass counts, subtests, skips and elapsed time.

## Import checks and scope

| Check | Evidence |
| --- | --- |
| Public source boundaries | Local `tools/check_public.py` validated 795 source files, JSON, relative documentation links, developer metadata and required license notices. Private state, account files, keys, databases and private Git history are excluded. |
| Credential/content review | Gitleaks 8.30.1 reported no findings on the selected source snapshot. Manual checks also covered personal markers, private endpoints, filenames, image metadata and embedded text encodings. Synthetic idempotency identifiers have narrow, explained inline exceptions. This is a bounded import review, not a guarantee about future contributions. |
| Manifest format | Both plugin manifests passed the published [Agent Plugins 1.0.0 schema](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json). Runtime/client-specific requirements remain separate. |
| Provider reconstruction | A fresh reconstruction fetched pinned public upstream commits, checked all 12 patch hashes and applicable base/result trees, and matched the two public source-tree pins below. No private release asset was required. |
| Installed wheels | Both wheels built with Apache-2.0 metadata, GAL1LEO attribution and LICENSE/NOTICE/third-party notices. Isolated Python 3.13 installations loaded packaged assets and CLI entrypoints. Tesla's installed catalogue contained 131 operations and 278 telemetry fields. |
| WhatsApp first/repeat startup | The installed-wheel probe passed both phases with synthetic state, schema 8, expected authorization/disabled-action behavior, closed provider clients and zero IPv4/IPv6 connection attempts. |
| Regression checks | Targeted runs included 155 Tesla cases after text alignment, a later 108-case Tesla package/UI subset, and eight synthetic backup/restore cases. Full cross-runtime qualification is recorded in the PR jobs, rather than inferred from these overlapping subsets. |
| Source archives | The public source builder includes required shared code and notices, verifies inputs, refuses links/private artifacts, produces a SHA-256 inventory and tests deterministic output. Each selected-project archive is checked again after extraction. |

Provider trees reconstructed for this import:

```text
gows 58522088e517c1f53f2cb0eaa8fc43807d96fbff
waha c85875e674ec49d9bc8e3dbc1cc179b6f220b341
```

The checks operate on synthetic owners, vehicle references, chat identities,
media and temporary databases. No live Tesla/WhatsApp account or physical device
was used. No installed private service, production database or private project
was updated. Publication is a new source import into this public repository.

## Interpreting results

The Tesla external Kafka integration is opt-in and was not exercised by this
import's default suite. A skipped integration is not a pass. Ownership-sensitive
administration tests require a Linux checkout with protected ancestors; writable
or shared temporary filesystem ancestors do not satisfy their source guards.
Do not relax those guards to accommodate a workstation environment.

Provider compilation, complete runtime-image qualification, live OAuth/client
connection, actual device commands, WhatsApp delivery/read receipts, native
image perception and production restoration are not established by these
checks. Companion-provider compiled redistribution also has separate third-party
license obligations. This import distributes source, not a qualified provider
runtime image or a shared hosted service.

Historical results and anonymized test-data descriptions are documented in the
[Tesla validation guide](https://github.com/GAL1LEO-X/GAL1LEO-XX/blob/main/plugins/tesla/docs/VALIDATION.md) and
[WhatsApp validation guide](https://github.com/GAL1LEO-X/GAL1LEO-XX/blob/main/plugins/whatsapp/docs/VALIDATION.md). Those results
refer to earlier revisions and are explicitly separated from this import.
