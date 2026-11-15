# Validation history and reproducible test data

Developer: GAL1LEO — info@gal1leo.com.

## Evidence and anonymization

This is an English, anonymized digest of historical development and release
notes. Counts are **reported historical results**, not reruns of this public
revision. Original operational receipts, private CI links and runtime accounts
are not distributed. See the [migration validation record](../../../docs/MIGRATION-VALIDATION.md)
for current public-source runs and [structured checkpoints](validation-history.json)
for the historical counts and scope.

No chat export, phone number, contact name, message body, voice recording,
account identifier, private endpoint or production database is included.
Public fixtures use fictional identities, synthetic content and temporary roots.
Media samples are generated test assets. Host compatibility tests use fictional
accounts and simulated services; they do not operate an installed instance.

## Historical checkpoints

| Source checkpoint | Backend passed | Shared tooling passed | Browser / provider checks | Scope |
| --- | ---: | ---: | --- | --- |
| 0.5.0 | 2,385 + 7 subtests | 597 + 62 subtests | 2 browser checks reported | Isolated Linux, Python 3.13; candidate application and packaging |
| 0.8.11 | 5,758 + 7 subtests per Python | 1,442 + 1,292 subtests per Python | 48 Chromium checks | Python 3.13 and 3.14; MCP resources and reliability |
| 0.8.12 | 5,808 + 7 subtests per Python | 1,442 + 1,300 subtests per Python; 10 skips | 48 Chromium checks | Python 3.13 and 3.14; inline image result path |
| 0.8.13 / provider 0.8.7 candidate | Separate final application run required | Separate final tooling run required | GOWS: 503 passed / 29 skipped; race: 450 / 29; 51 targeted regressions; 7 compiled regression groups | Historical provider build qualification |

Subtests are reported separately. Suites overlap and change over time; counts
must not be summed as unique cases or compared as coverage percentages. A
candidate label or a historical image hash does not prove a current release,
installation or availability of a distributable provider image.

The provider notes also reported two identical GOWS builds, matching WAHA
inventories, synthetic authentication, protocol checks, audio conversion,
shutdown and cleanup in isolated container stores. No real account or message
was used for those checks. This public import reconstructs the provider source
from public upstream commits and pinned patches; compilation and container
qualification remain separate from reconstruction.

## Reusable regression data and lessons

| Boundary | Test evidence and interpretation |
| --- | --- |
| Archive versus provider | Pagination and per-chat coverage are explicit. Reaching the last page does not prove a complete account history. |
| Identity and revocation | Owner, scopes, source/grant, PN/LID identity evidence and revocation are checked before projection and again before delivery. Similar identifiers do not establish an alias. |
| Media integrity | [Generated media fixtures](../tests/fixtures/media-integrity/README.md) cover byte hashes, MIME/type metadata, cached originals, truncation, replacement, revocation and expiry. Transport success does not prove a client's rendering or model perception. |
| Backup and restore | [Synthetic round trips](../tests/test_backup_restore.py) preserve logical SQLite content, WAL-visible rows, isolation, encryption and idempotency, with network access blocked. Missing/corrupt inputs and occupied destinations fail before restoration. |
| Unknown send outcomes | Recovering `sending` as `uncertain` never authorizes another send. Accepted/submitted is distinct from delivered/read. Historical incidents are not automatically resolved by a fix. |
| Administrative lifecycle | Interrupted operations resume against exact public fixture hashes and protected temporary roots. This proves protocol behavior, not compatibility with an arbitrary old installation. |
| Connection UI | Lost or malformed pairing responses remain unverified; no automatic second pairing request. Desktop/mobile browser fixtures use synthetic provider responses. |
| Local transcription | Audio integrity, authorization, deadlines and reference cleanup are tested separately from model quality and live service operation. Model weights are not shipped. |

Historical media tests drove two useful distinctions: a cached file is not
verified merely because a provider supplied an ID; and an HTTPS download or
`resources/read` response does not establish that a client passes image pixels
to a model. The inline image path must be checked in the intended client with
an authorized, previously unseen image. Document and video perception are not
implied by static JPEG/PNG/WebP support.

Synthetic restore notes reported seven targeted tests on both Python 3.13 and
3.14. They verified isolation, revocation, deduplication, identity checks,
checksums and refusal to overwrite an existing destination. They did not
perform a production restore or prove that a live provider session can restart.

## Running and interpreting the tests

Use Linux or WSL with a native Linux filesystem for ownership and mode checks.
Follow [development setup](../../../docs/DEVELOPMENT.md), then run:

```sh
python -m pytest plugins/whatsapp/tests -q --tb=short
python -m pytest tools/tests -q --tb=short
npm run test:browser
```

The complete tooling suite requires the full public repository. Tests use
simulated kernels, service managers, account providers and local HTTP fixtures.
Never substitute a real configuration or account for a synthetic fixture.

Native WhatsApp history availability, remote EOF/503 causes, device connection,
actual send/delivery/read results, client rendering, transcription accuracy and
recovery of an installed service require separate acceptance. System DNS lookup
cannot be interrupted by a socket deadline; late results are rejected before
connection. Releasing Python references does not promise memory zeroization.
