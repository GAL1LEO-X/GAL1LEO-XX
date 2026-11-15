# Isolated OCI qualification

Reconstruct the pinned source chain first. Build the matched GOWS and WAHA
inputs with the declared toolchains, dependency pins and source inventory.
The OCI helpers accept explicit compiled inputs and verify their manifests,
layers and expected native ABI. Do not substitute a base-image digest for
the custom runtime image digest.

Test in a new isolated store with networking disabled and no production
session/data mounts. Verify API authentication, empty session lists,
the provider contract and synthetic media handling. Preserve rootless,
readonly-root and capability constraints. Record exact digests and actual
test results. This source delivery does not itself build or distribute an
OCI image and makes no live phone or fresh-daemon acceptance claim.
