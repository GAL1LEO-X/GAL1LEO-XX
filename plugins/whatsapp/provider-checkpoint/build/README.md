# Companion build recipes

Current provider **0.8.2** applies the original patches, then QA120 (WAHA),
then [QA125](../qa125/README.md) (GOWS and WAHA). The runtime Dockerfile now
requires GOWS SHA-256 `3e0f1688128c3d0618882de734a40598d19e9b647aff866b1ca9de201f198778`
(48,348,000 bytes), from tree `7893e93b3ede394e2e639f33a4c9a793cd4619ea`.
The same pinned toolchain and module locks built this binary offline. The full
Go suite passed 301 entries and 29 existing skips; Nest compilation and two new
transport-transition tests passed. Static inspection found identical Debian/NPM
dependency records and selected native files to provider 0.8.1. This cycle does
not claim a second independent byte-reproduction build.

The older measurements below remain historical evidence for their named trees
and binaries. Exact current runtime identities and qualification are recorded
in the QA125 manifest and the separately distributed source-evidence archive.

These recipes preserve the compiler inputs and the API-only paired runtime
configuration used for the checkpoint. [../patches/manifest.json](../patches/manifest.json)
records exact source bases, patched trees, tool versions, recipe hashes and measured
artifact identities. No binary, `dist`, `node_modules`, image archive, CA or session
data is included here. This directory alone is not an automatic image build from
the patches: the runtime recipe requires the compiled inputs described below.

## Compiler and GOWS

`Dockerfile.gows-builder` fixes the official Go 1.26.4 image by digest, Debian
2026-06-23 snapshot, protobuf plugins and native compiler dependencies. It installs
only inside the builder image. An optional `proxy_ca` BuildKit secret is for the
builder's environment-specific public CA; do not export this compiler image as
the application runtime or put CA material in the source context. Without such a
requirement, build without the secret:

```sh
docker build -f Dockerfile.gows-builder -t local-gows-builder .
```

Apply the companion GOWS patch first. Mount that new source clone into the builder
and run `make build-proto` from its root. The expected generated hashes are in the
manifest. Resolve modules from the unchanged `src/go.mod`/`src/go.sum` and run
`go mod vendor` only in a separate build copy, not the source checkout. Preserve
that generated source and vendor tree as the corresponding source for the binary.
The measured build used the following command from that copy's `src` directory:

```sh
export GOTOOLCHAIN=local GOWORK=off GOENV=off
export CGO_ENABLED=1 GOOS=linux GOARCH=amd64 GOAMD64=v1 CC=gcc CXX=g++
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1792052386
# After exact modules have been vendored, public dependency access is unnecessary.
export GOPROXY=off GOSUMDB=off
# Give each independent build new empty GOPATH/GOMODCACHE/GOCACHE/GOTMPDIR.
go build -p=2 -mod=vendor -trimpath -buildvcs=false -pgo=off \
  -ldflags='-buildid= -linkmode=external -extldflags=-Wl,--build-id=none' \
  -o /out/gows-linux-amd64 .
```

Two clean source paths and independent empty caches, with networking disabled,
produced the same CGO binary SHA-256:
`66bd25d343ad6748521e02cab675e3189925b90537b048120ec450f909f02be1`
(48,347,592 bytes), from GOWS tree
`d9152004928b121dc4794e8843e38be763126d00`.
The binary needs the measured Linux amd64/glibc/libvips ABI; it is not static.
The exported compiler recipe documents the inputs, but a new compiler image's
identity and a new image build's byte reproducibility are not established by that
binary comparison. Compare the output hash before using the runtime recipe;
its explicit assertion rejects a different GOWS binary.

## WAHA compilation and runtime context

Use the patched WAHA source tree and the checked-in contract. The checkpoint used
Node 24.19.0, Yarn 4.17.1, `yarn install --immutable` with the original lockfile, then
`node node_modules/@nestjs/cli/bin/nest.js build`. Set
`PUPPETEER_SKIP_DOWNLOAD=True` while installing for this API-only GOWS context.
Do not substitute dependency versions or execute the application's entrypoint to
compile. Remove dashboard and Plus assets from the staged `dist` context; do not
alter the original source checkout. Full immutable installation and Nest
compilation passed separately from the minimal fixture tests.

Stage a separate context containing exactly:

```text
Dockerfile                  # this directory's runtime Dockerfile
.dockerignore               # this directory's allowlist
gows-linux-amd64            # own verified source build, hash above
waha/package.json           # patched provider tree
waha/yarn.lock              # unchanged upstream lock
waha/.yarnrc.yml
waha/LICENSE
waha/entrypoint.sh
waha/dist/**                # compiled patched source, dashboard/Plus assets omitted
```

The runtime Dockerfile pins the official Node 24.19.0 base digest, Yarn 4.17.1,
Debian snapshot and libvips version, includes FFmpeg and Tini, and checks the own
GOWS hash. It does not download an upstream GOWS release binary. Native Node
dependencies are installed from the unchanged lockfile in its dependency stage.
The upstream lock enables optional platform packages; their presence is not proof
that those code paths were exercised in the Linux/Core/GOWS smoke test.

The final build layer fixes root ownership and explicit modes for staged application
artifacts: directories and entrypoints 0755, regular dist and metadata files 0644.
This avoids inheriting a private staging umask. Installed dependencies and the
default runtime user remain unchanged; no host permissions are changed.

```sh
# From the separate prepared context; builds only, does not start the application.
docker build --platform=linux/amd64 -t local-whatsapp-ab-paired .
```

If public dependency access requires a custom CA, pass a BuildKit `ca_bundle`
secret containing the appropriate public trust bundle. The runtime recipe reads
it directly in the relevant clients, never writes it to the runtime trust store,
and does not retain proxy or CA environment settings. Never pass account secrets
as build arguments or include them in the context.

## Current qualification

The 0.7.0 GOWS full suite passed with 296 passing test entries and 29 skipped
unsupported forwarding variants. The race suite passed with 243 passing entries,
the same 29 skips and no data race reports. These counts include subtests.
The two independent binary builds above used network-disabled containers,
unchanged module locks and separately empty caches. WAHA's full Nest build
passed on the patched tree recorded in the manifest.

The manifest's `qualification` object records the current runtime status and
artifact identities. Binary reproducibility does not establish image byte
reproducibility or a live account test. The worker default remains
`WAHA_WORKER_RESTART_SESSIONS=true`; a temporary test may override this while
using empty storage, but its no-session setting must not become the deployment
default.

The isolated runtime gate uses network disabled, a read-only root, empty
temporary storage, no published ports and lifecycle guards. It checks API 401
without a key, an authorized empty session list, the real stateless
`GetABContract`, GOWS hash/ELF/native loader, compiled audio conversion and zero
account lifecycle attempts. The measured 0.7.0 image passed this gate with UID 1000, all capabilities dropped
and no account lifecycle attempts. The real converter produced decodable
Ogg/Opus mono at 48 kHz. A separate synthetic vertical passed 11 Nest controller
cases and 13 plugin queue/worker cases with a fake Go backend. Its Nest fixture
overrides the auth guard; API authentication and MCP authorization are tested
separately. Image, manifest and transport hashes are recorded in the manifest.

The nine-layer OCI archive passed independent blob/config/diff-ID validation and
a Docker load in the existing daemon, preserving the tested image identity.
That load reused existing layers; it is not a fresh-daemon or Podman result.
The test explicitly clears client-injected proxy settings after verifying that
the image itself has none; the original probe and lifecycle guards stay active.

Archive validation, Docker load, Podman/Quadlet operation, production migration
and live account behavior are separate checks; a result for one does not certify
the others. The backend updater does not upgrade the provider. A future provider
installation must explicitly select the matching image. These recipes do not
authorize a deployment or change the historical provider pin.

## Historical 0.6.0 evidence

`previous_qualification` in the manifest preserves the 0.6.0 binary and image
identities. That image passed an isolated startup and a Docker load with layers
already present. Its final worker setting came from a config-only derivative;
the combined Dockerfile was not then rebuilt separately. None of those results
qualifies the 0.7.0 source trees or a fresh build of this recipe.

## Distribution limits

The copied provider license is in [../patches/APACHE-2.0.txt](../patches/APACHE-2.0.txt).
The runtime's dependencies have separate licenses; FFmpeg is GPL-enabled and
GOWS links native libraries. The current runtime inventory identifies 328 Debian binary packages, with all
237 corresponding source versions collected and verified against signed indexes,
plus signed Node 24.19.0 source and Go 1.26.4 toolchain source. Installed NPM
metadata identifies 1,523 unique name/version pairs; the separate collection
covers selected copyleft/native dependencies and installed notices, not the
complete source of every NPM package. The final metadata-only image layer was
checked against the prior measured layers: package bytes and notices are unchanged.
This does not establish native binary reproducibility or complete license clearance. Selected native
NPM provenance limits include unavailable WASM CI logs, mutable build references,
unknown effective Cargo locks and unreproduced generated build inputs. Large
source collections, notices and the installable OCI archive are separate private
deliverables; they are not embedded in this text-only PR.
