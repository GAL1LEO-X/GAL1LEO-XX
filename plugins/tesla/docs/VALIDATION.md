# Validation history and reproducible test data

Developer: GAL1LEO — info@gal1leo.com.

## Evidence and anonymization

The checkpoints below are **historical results reported in development notes**.
They were translated and summarized for this public import; original private
logs and service receipts are not included. They do not certify this public
revision, current provider behavior or a physical vehicle. The separate
[migration validation record](../../../docs/MIGRATION-VALIDATION.md) records new
runs on the public source. [Machine-readable checkpoints](validation-history.json)
preserve counts and their scope without account or device identifiers.

No VIN, owner identity, location, route, personal document, credential, private
host address or operational log is included. Public tests use generated keys,
synthetic vehicle references and temporary databases. The fixture names identify
technical behavior, not an owner or a vehicle nickname.

## Historical checkpoints

The backend results below were reported for **each** Python 3.13 and 3.14 run.
Counts describe different revisions and test inventories; do not add them or
interpret their growth as a measured coverage percentage.

| Source version | Backend passed per Python | External Kafka case skipped | Historical scope |
| --- | ---: | ---: | --- |
| 0.1.8 | 200 | 1 | Extended collection profile and rejection isolation |
| 0.1.9 | 219 | 1 | Autonomous collection editor, local previews and cost agreement |
| 0.1.10 | 227 | 1 | Shared panel/chat settings and concurrent revision checks |
| 0.3.0 | 405 | 1 | Catalogue, command policy, desktop/mobile HTTPS browser paths |
| 0.3.2 | 567 | 0 | Full suite; synthetic Docker Kafka case reported exercised |
| 0.3.3, 2026-10-28 | 657 | 0 | Consolidation, acquisition and source packaging |
| 0.3.4, 2026-10-29 | 726 | 0 | Charging-history envelopes and comfort rejection reasons |

The 0.3.0 notes also reported Go race checks for the proxy and vehicle packages
and a proxy build. Those are historical source-build results, not a guarantee
that a compiled binary is shipped here. Later 1.0 consolidation notes focused
on the boundaries below rather than a single release-wide test count.

## Regression boundaries retained in public source

| Boundary | What synthetic data establishes | Reproduction entrypoints |
| --- | --- | --- |
| Park and physical state | Invalid, stale, conflicting or missing gear never becomes a fresh P; history is separate from admission | [Gear policy](../tests/test_operation_park_policy.py), [state evidence](../tests/test_state_evidence.py) |
| Value quality | Invalid envelopes preserve provenance, not a usable numeric value; opaque protocol fields remain unqualified | [Value quality](../tests/test_vehicle_data_quality.py), [legacy values](../tests/test_operating_context_legacy_values.py) |
| Commands | One dispatch under concurrency, expiry/revocation checks, accepted/rejected/uncertain outcomes, no inferred physical effect | [Chat actions](../tests/test_chat_actions.py), [operation diagnostics](../tests/test_operation_diagnostics.py) |
| Shared collection | Stale proposals and changed dependencies fail before provider writes; explicit cost review and confirmation | [Atomicity](../tests/test_collection_atomicity.py), [trigger dependencies](../tests/test_trigger_dependencies.py) |
| Temporary collection | A later owner configuration wins; lost responses do not authorize retries or establish restoration | [Temporary windows](../tests/test_temporary_collection.py), [ordering](../tests/test_vehicle_readback_ordering.py) |
| Privacy | Permission rechecks and scalar-type checks also protect deliberately malformed persisted legacy values | [Legacy value privacy](../tests/test_operating_context_legacy_values.py) |
| Owner UI | Desktop/mobile login, review, cancel, logout, accessible forms and no incidental vehicle request | [Browser harness](../tests/test_owner_browser.py), [evidence UI](../tests/test_v1_ui.py) |

The data-quality work reported nine protobuf-only keys without a specific
per-field value contract. The public catalogue preserves their `unqualified`
semantics. Testing every key with synthetic containers does not establish that
any particular vehicle emits those combinations. A later invalid sample does
not recover an earlier valid gear value. Speed alone does not prove movement.

The legacy-value privacy reproductions deliberately inserted malformed rows in
a test database. They verify a defensive boundary; they do not establish that
live ingestion generated those rows or that a production disclosure occurred.

## Running and interpreting the tests

Follow [development setup](../../../docs/DEVELOPMENT.md), then run:

```sh
python -m pytest plugins/tesla/tests -q --tb=short
```

Chromium tests use a local HTTPS fixture and ephemeral certificates. The external
Kafka integration is opt-in (`TESLA_TEST_KAFKA=1`) and requires a deliberately
provisioned synthetic broker. A skip means that integration was not exercised;
it is not a pass. No test requires a real Tesla account or a physical command.

OAuth with a real provider, native client discovery, actual streaming delivery,
vehicle firmware/hardware behavior, physical effects and restoration on a real
vehicle require separately authorized acceptance. No blanket vehicle
qualification, complete route reconstruction or guaranteed collection cadence
is claimed.
