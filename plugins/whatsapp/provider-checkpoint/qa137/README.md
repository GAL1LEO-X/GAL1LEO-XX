# Provider checkpoint qa137

This directory contains the versioned inputs for this step of the paired
WAHA/GOWS source or runtime recipe. The manifest identifies the patch hashes,
source bases, contract changes and relevant toolchain pins. Do not apply an
incremental patch directly to an arbitrary upstream revision.

Use the [public source reconstruction tool](../README.md) for the complete
chain. Its result is bound by public-sources.lock.json. Historical runtime
digests in the manifest describe their original input artifacts, not a
qualification or installation of this public revision. New runtime builds
require their own dependency-license inventory and synthetic checks.
