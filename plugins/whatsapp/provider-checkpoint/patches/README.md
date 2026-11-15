# Companion provider source patches

These patches implement the matching GOWS/WAHA `gows-ab-v1` contract for the
plugin's eight provider operations. They contain production changes and synthetic
tests, with local protobuf generation instead of a release download. They are
source material for review and reconstruction; they do not install a provider or
change the active deployment image.

[manifest.json](manifest.json) fixes the upstream bases, local checkpoint commits,
resulting Git trees, patch hashes, protobuf tools and qualified artifact identities.
The checkpoint commits are local provenance identifiers. They are not advertised
as commits available from either upstream repository.

## Apply and verify

Run in a new working directory. Set `PATCH_DIR` to this directory's absolute path.
The commands require Git and public upstream access, and modify only the new clones.

```sh
PATCH_DIR=/absolute/path/to/provider-checkpoint/patches

git clone https://github.com/devlikeapro/gows-plus.git gows
git -C gows checkout --detach 5f093fe7c38c41faead8e6ce78ee70cb7f815404
git -C gows apply --check --index --whitespace=error-all "$PATCH_DIR/gows.patch"
git -C gows apply --index --whitespace=error-all "$PATCH_DIR/gows.patch"
test "$(git -C gows write-tree)" = d9152004928b121dc4794e8843e38be763126d00

git clone https://github.com/devlikeapro/waha.git waha
git -C waha checkout --detach 90ba445a0e765701c8910f0fac08176250c3e0fd
git -C waha apply --check --index --whitespace=error-all "$PATCH_DIR/waha.patch"
git -C waha apply --index --whitespace=error-all "$PATCH_DIR/waha.patch"
test "$(git -C waha write-tree)" = 7eff6a71bcf6077b1253a0d3cf7e8ed39da045e9
```

Verify the two patch SHA-256 values in the manifest before applying them. Both
patches were independently applied to isolated indexes at their pinned bases;
`git write-tree` matched the trees above. The patches reproduce file trees,
including modes, rather than checkpoint commit metadata. `go.mod`, `go.sum`, WAHA
dependency declarations and its original `yarn.lock` are unchanged. WAHA's
`package.json` script changes remove the release-fetch generation path. The new
minimal fixture has its own locked dependencies.

## Generate the companion protobuf bindings

GOWS ignores `src/proto`, so its generated Go files are deliberately absent from
the patch. In the patched GOWS root, use Go 1.26.4 (`GOTOOLCHAIN=local`), protoc
3.21.12, protoc-gen-go 1.36.12 and protoc-gen-go-grpc 1.5.1. The pinned compiler
recipe and build details are in [../build/README.md](../build/README.md).

```sh
make build-proto
# Equivalent command, without changing upstream's go_package or output layout:
# protoc -I=. --go_out=./src/proto --go-grpc_out=./src/proto \
#   --experimental_allow_proto3_optional proto/*.proto
sha256sum proto/gows.proto src/proto/gows.pb.go src/proto/gows_grpc.pb.go
(cd src && go test ./...)
```

Compare the three hashes with the manifest. Do not use `make tidy` or `up-meow`
for reconstruction: those targets can change the pinned dependency graph.

WAHA's patch includes its matching local `.proto`, generated bindings and their
hash manifest. In the patched WAHA root, Node 24.19.0 and the fixture lockfile
provide the regeneration path:

```sh
npm ci --prefix checkpoints/offline-ab
npm run generate --prefix checkpoints/offline-ab
node scripts/gows-proto.js check
npm test --prefix checkpoints/offline-ab
```

The lock pins grpc-tools 1.13.0, protoc-gen-ts 0.8.7, TypeScript 5.9.2,
grpc-js 1.14.1 and google-protobuf 3.21.4. Go and Node must use the same contract
SHA-256 recorded in the manifest. Regeneration uses the checked-in contract;
review any contract change in both repositories together. Dependency preparation
requires public downloads unless the exact caches have already been populated.
The Node tests and Go service tests use synthetic fixtures; they do not establish
phone-side delivery or live account compatibility.

## License and distribution scope

Both pinned provider repositories contain the same Apache-2.0
[LICENSE text](APACHE-2.0.txt), retained here with its notices. WAHA's package
metadata still says `UNLICENSED`; this discrepancy is preserved, not silently
resolved. The patch does not grant rights to Plus features, dashboard assets or
third-party packages. The API-only runtime context omits dashboard and Plus assets.

Compiled distribution has additional obligations. Examples include GPL-3.0
libsignal, MPL-2.0 Whatsmeow, LGPL libvips and GPL-enabled FFmpeg. Historical separately
qualified artifacts included corresponding Debian/Node source collections
and notices; those large payloads are not in this PR. Selected NPM native source
provenance still has recorded limits, including mutable build references and an
unavailable historical WASM build log. This text-only source delivery is not a
legal clearance or a claim that every compiled dependency can be reproduced.
