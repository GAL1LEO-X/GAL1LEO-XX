# Public repository development

- Use English in documentation, presentation strings, comments and new code.
- Developer identity: GAL1LEO, info@gal1leo.com. Original code is Apache-2.0;
  preserve third-party licenses, copyright, source pins and notices.
- Work on `task/<purpose>` and integrate through a pull request. Preserve
  concurrent work. Verify the exact revision; never reset or force-push it.
- Read the selected plugin's AGENTS.md and installation guide first. Prepare
  only required dependencies; development checks use synthetic fixtures.
- Never commit credentials, personal messages, VINs, account registrations,
  production configuration, raw diagnostics or operational server profiles.
  Check archives as well as source files before the first public upload.
- Keep live defaults disabled and preserve authorization, isolation,
  idempotency, uncertain-result handling and explicit command confirmation.
- Do not provision hosts, pair phones, send messages, wake vehicles or deploy
  services as part of a source edit or a test run.
- Use `work/` for temporary material and `outputs/` for generated deliveries.
  Neither is a source input. Do not add nested Git repositories or submodules.
- Run the affected application, tooling and browser tests. Record actual
  results and distinguish source qualification from live acceptance.
- Prefer the generic host profile. Observed server profiles and private
  cross-repository administration are intentionally outside this repository.
