# Generic host components

Optional host-owned administration for WhatsApp: immutable source bundles,
lifecycle journaling, filesystem ownership, service control, HTTPS frontends,
certificate handling and resource-priority contracts. These components are
distributed here so public installation does not depend on another repository.

Only the **general** bundle profile is published. Observed server profiles,
machine-specific configuration and private cross-product orchestration are
excluded. Compatibility namespaces remain technical identifiers; new
installations supply explicit profiles and exact protected identities.

From the root of a clean committed checkout:

```sh
python host/build_bundle.py --profile general --source-revision COMMIT_SHA40 --output work/host-bundle
python host/install_bundle.py inspect --bundle work/host-bundle --sha256 SHA256_OF_BUNDLE_JSON
```

Use the actual checkout commit and independently reviewed metadata digest.
Building/inspection is local and has no service effects. Installation requires
an administrator on the destination host and protected physical paths.
It does not configure an application, issue certificates or activate services.

Review the generated manifest and the selected frontend/QoS contract before
applying it. Foreign Apache modules are not bundled. Existing services and
resources outside the admitted owner/path set must be preserved. A source
bundle or a local test is not a host-acceptance receipt.
