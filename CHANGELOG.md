# Changelog

## 0.3.0

- Add controlled containment proofs with `ALLOWED`, `DENIED`, and `INDETERMINATE` states.
- Add optional subject-and-control witnessing so provider outages cannot become false passes.
- Add per-target containment SLOs and consecutive denial confirmation.
- Measure first control-validated denial and proof-completion time from the containment request.
- Treat GitHub throttling and unexpected HTTP responses as indeterminate.
- Harden HTTP URL validation and strip query strings from stored evidence.
- Validate the event hash chain when verifying signed evidence.
- Add a safe `containmentci demo`, `--version`, signed JSON and JUnit outputs, and a composite
  GitHub Action with artifact-path outputs.
- Build and clean-install both wheel and source distributions before publishing releases.
- Require non-default signing keys and layered authorization for API-triggered live runs.
- Add serial target execution and cross-process fixture leases to prevent overlapping live runs.
- Bind GitHub tokens to authenticated owners and separate HTTP subject/admin/control credentials.
- Add the complete Apache-2.0 license and community maintenance files.

## 0.2.0

- Add direct GitHub repository-access containment provider.
- Add offline scenario and required-secret preflight validation.
- Require explicit approval before executing live providers.
- Disable API-triggered live execution by default.
- Require GitHub synthetic-identity acknowledgement and resource consistency.
- Add real-world GitHub test and restoration runbook.

## 0.1.0

- Initial execution engine, simulation provider, generic HTTP provider, evidence store,
  reports, dashboard, API, and Docker deployment.
