# Security Policy

ContainmentCI is designed for synthetic identities and dedicated test resources.

Do not run containment tests against real employees, customer identities, production
service accounts, or resources whose temporary loss would cause operational impact.

## Reporting Vulnerabilities

Report vulnerabilities privately to the project maintainers before public disclosure.
Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Deployment Requirements

- Replace the default `CONTAINMENTCI_SIGNING_KEY`.
- Restrict scenario authoring and API access to trusted operators.
- Keep credentials in environment variables or a secret manager.
- Review HTTP provider endpoints to prevent unintended requests.
- Isolate synthetic identities from production data.
- Require explicit live-run approval and provider-specific synthetic-identity acknowledgement.
