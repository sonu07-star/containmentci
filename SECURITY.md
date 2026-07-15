# Security Policy

ContainmentCI is designed for synthetic identities and dedicated test resources.

Do not run containment tests against real employees, customer identities, production
service accounts, or resources whose temporary loss would cause operational impact.

## Reporting Vulnerabilities

Report vulnerabilities privately to the project maintainers before public disclosure.
Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Deployment Requirements

- Set `CONTAINMENTCI_SIGNING_KEY` to at least 32 random bytes.
- Live CLI and API runs reject missing or known default signing keys.
- Restrict scenario authoring and API access to trusted operators; scenarios select endpoints and
  actions and are trusted executable security configuration.
- Keep `CONTAINMENTCI_API_ALLOW_LIVE` disabled unless API-triggered live runs are required.
- Set `CONTAINMENTCI_API_TOKEN` to at least 32 bytes to protect stored-run API and dashboard
  routes. Live API execution always requires it; each live request must also include
  `approve_live=true` and send the token as an `Authorization: Bearer` credential. Never reuse
  the evidence signing key as the API token; the server rejects equal values. If they were ever
  reused, rotate both secrets before trusting new evidence.
- Keep the API bound to loopback by default. If it must be exposed, place it behind TLS,
  network access controls, and an authenticated reverse proxy.
- Keep credentials in environment variables or a secret manager.
- The HTTP provider requires a synthetic-identity acknowledgement, explicit denial semantics,
  authenticated subject and containment credentials, and distinct values for every configured
  subject/control/containment credential. Review every configured endpoint.
- The GitHub provider sends credentials only to `https://api.github.com`, validates safe path
  segments, and binds subject/admin/control tokens to authenticated GitHub accounts.
- Isolate synthetic identities from production data.
- Require explicit live-run approval and provider-specific synthetic-identity acknowledgement.
- Local live executions use cross-process fixture leases. Use CI concurrency controls or an
  external global lock when runners do not share the same state directory.
