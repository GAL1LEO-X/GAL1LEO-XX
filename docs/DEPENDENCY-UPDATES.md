# Dependency maintenance

Dependabot proposes weekly version updates for the two Python manifests, the
browser npm lock and GitHub Actions. The schedule uses Monday at 08:00
Europe/Berlin and permits up to two open version-update pull requests per
ecosystem. Compatible updates of the same Python dependency are grouped across
the plugins. This configuration uses the existing Dependabot service; security
updates and Dependency Graph retain their separate GitHub settings.

A proposal does not qualify a package or update an installed service. Review
the runtime and test locks, optional transcription requirements, wheel policy
and component source/image pins together where affected. Custom `.lock` files,
`tools/whatsapp-deploy-wheels.lock.json`, Tesla `components.lock.json` and model
pins are not automatically refreshed by a manifest update. Verify official
metadata and exact wheel bytes before accepting new URLs or hashes. Keep the
public builder policy and repository identity intact.

Use fresh, separate Python 3.13 and 3.14 environments for each affected plugin,
run `pip check`, application/tooling tests and the applicable synthetic browser
tests, and build and inspect the public source archives. CI retains read-only
repository permissions. No automatic merge, publication
or deployment is enabled by this schedule.

Promote fixes selectively between public and private source trees. Record the
two source revisions and selected changes, preserve intentional public defaults
and never import private profiles, sessions or operational data. Source, built
artifact, installed version and running process remain separate evidence.

The OpenTelemetry API 1.45.2 maintenance change updates only the two runtime
locks and its wheel-policy entry; test locks include those runtime locks. The
public setuptools 84.0.0 builder and database schemas remain unchanged. The
source candidates are Tesla 1.0.5 and WhatsApp 0.8.14; the provider and ChatGPT
plugin-package versions remain separate. Review the [official release metadata](https://pypi.org/pypi/opentelemetry-api/1.45.2/json)
alongside the [public import scope](PUBLICATION.md).

Tesla's generic `plugins/tesla/deploy/patch105_update.py` accepts only the
reviewed 1.0.4 to 1.0.5 transition with that exact OpenTelemetry change and
unchanged schema 3. It verifies previous and candidate fingerprints and uses
the public setuptools 84.0.0 builder. Historical adapters retain their original
pins; synthetic tests use a frozen pre-1.0.5 requirements fixture for them.
Before use, qualify the destination profile, stopped writers, consistent backup
and health checks independently. Recovery before candidate writers start keeps
the existing database; after they may have run, preserve the current database
and use the adapter's explicit forward-recovery path. Do not substitute a
private deployment profile or infer live acceptance from the source tests.

WhatsApp's schema-8 offline copy probe admits the exact 0.8.14 candidate while
rejecting unreviewed versions and prereleases. Its administration restore helper
pins the new runtime version file, so build and qualify the matching
administration bundle before activation; an older helper can reject the new
runtime intentionally. This source qualification does
not authorize installation, pairing, sending or a production restore.
