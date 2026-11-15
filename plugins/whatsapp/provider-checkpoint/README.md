# Companion provider sources

The bridge requires the paired WAHA/GOWS `gows-ab-v1` contract for eight
operations. Source patches for companion provider **0.8.7** are included.
No prebuilt provider image, private release asset or account session is bundled.

## Reconstruct from public upstreams

From the repository root, select a new output directory:

```sh
python plugins/whatsapp/provider-checkpoint/reconstruct.py --output work/provider-sources
```

The script fetches the exact upstream commits from devlikeapro/waha and
devlikeapro/gows-plus. It verifies every patch hash and applicable base/result
tree, applies the complete chain through qa174, and checks public-sources.lock.json.
It never starts WAHA or opens a WhatsApp session. The resulting checkout
includes upstream Git metadata for inspection, outside source distribution.
The output reconstruction.json records the resulting trees and patch hashes.

`patches/` supplies the baseline. The ordered incremental source patches are
qa120, qa125, qa129, qa131, qa136, qa158, qa162 and qa174. Other directories
contain intermediate runtime recipes. These identifiers are technical patch
checkpoints, not instructions to use a developer's deployment.

## Compile and qualify separately

Inspect [build recipes](build/README.md), the manifests and the latest
qa174 inputs before compiling. GOWS protobuf bindings are generated locally;
the paired WAHA bindings and contract must match. Pin Go, Node, protobuf and
native dependencies as declared by each recipe. Do not use an upstream
Dockerfile that silently fetches a different, unpatched GOWS binary.

A source tree match does not prove a native build, complete image
reproducibility, rootless Podman compatibility, phone behavior or delivery.
Runtime publishing additionally requires third-party dependency notices and
corresponding sources where their licenses require them. See
[third-party notices](../THIRD_PARTY_NOTICES.md). Dashboard/Plus assets are
outside this source-only integration; WAHA's pinned package metadata has a
license discrepancy that must be resolved for the exact packaged materials.
