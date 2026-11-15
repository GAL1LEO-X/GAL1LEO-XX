# Development tools

`project.py` selects an explicitly named project and Python runtime.
`check_public.py` verifies public-source privacy, attribution and package inputs.
`build_source.py` produces deterministic project source distributions.
`build_plugin.py` builds WhatsApp portable or account-bound packages from
explicit operator configuration. Tesla has its own `plugins/tesla/build.py`.

Release helpers are opt-in operator tools, not a ready hosted release
channel. Use an artifact lock for your own independently verified release.
See [development](../docs/DEVELOPMENT.md) and each project's packaging guide.
