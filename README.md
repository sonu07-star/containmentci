# ContainmentCI

[![CI](https://github.com/sonu07-star/containmentci/actions/workflows/ci.yml/badge.svg)](https://github.com/sonu07-star/containmentci/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

ContainmentCI tests whether an identity is actually locked out after a containment action.

Disabling an account or revoking a session is easy to record as successful when the provider
API returns `200` or `204`. That response does not prove the original credential stopped
working. ContainmentCI starts with a working synthetic identity, triggers containment, then
retries the same access path until it is denied or the deadline expires.

```text
Microsoft Entra account       PASS    0.101s
AWS temporary credentials     PASS    0.544s
GitHub personal access token  PASS    0.000s
Slack mobile session          FAIL    Access remained active after deadline
VPN certificate               PASS    0.212s

Containment coverage: 80.0%
```

The project is early-stage. It currently includes a simulation provider, a generic HTTPS
provider, and a direct GitHub repository-collaborator test.

## Why This Exists

Incident-response playbooks usually confirm that a disable or revoke request was accepted.
They rarely verify the outcome using the credential or session that an attacker would still
hold.

ContainmentCI measures that gap:

1. Prove the synthetic identity can access a dedicated test resource.
2. Request containment.
3. Repeat the original access attempt.
4. Pass only after access is denied.
5. Record timing and signed evidence.

Use dedicated synthetic identities and disposable test resources. Do not point this tool at
employee accounts or production resources.

## Installation

Requires Python 3.11 or newer.

```powershell
git clone https://github.com/sonu07-star/containmentci.git
cd containmentci
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Linux and macOS:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run The Simulation

The included scenario intentionally leaves one session active, so it exits with status `1`.

```powershell
containmentci run examples/compromised-user.yaml --report containment-report.html
containmentci serve
```

Open `http://127.0.0.1:8080` to view stored runs.

## Run A Real GitHub Test

The GitHub provider removes a dedicated synthetic collaborator from a dedicated private
repository, then verifies the same synthetic user's token can no longer read it.

```powershell
$env:CONTAINMENTCI_GITHUB_PROBE_TOKEN = "github_pat_probe"
$env:CONTAINMENTCI_GITHUB_ADMIN_TOKEN = "github_pat_admin"

containmentci check examples/github-repository-access.yaml
containmentci run examples/github-repository-access.yaml `
  --approve-live `
  --report .containmentci/github-report.html
```

Edit the example scenario before running it. The complete setup and restoration procedure is
in [docs/github-real-world-test.md](docs/github-real-world-test.md).

## Commands

```text
containmentci check SCENARIO              Validate configuration without network requests
containmentci run SCENARIO                Execute a simulation scenario
containmentci run SCENARIO --approve-live Execute providers that make live changes
containmentci export RUN_ID FILE          Export signed JSON evidence
containmentci verify FILE                 Verify an evidence signature
containmentci serve                       Start the API and dashboard
```

Set `CONTAINMENTCI_SIGNING_KEY` before producing evidence outside local development.

## Providers

| Provider | Purpose | Status |
| --- | --- | --- |
| `simulation` | Deterministic local scenarios and CI | Available |
| `http` | Connect existing access probes and containment APIs | Available |
| `github-repository-access` | Remove and verify a synthetic repository collaborator | Available |
| Microsoft Entra ID | Account and session containment | Planned |
| AWS IAM/STS | Credential containment | Planned |
| Slack | Session containment | Planned |

Live providers require `--approve-live`. API-triggered live execution is disabled unless
`CONTAINMENTCI_API_ALLOW_LIVE=true`.

## Evidence

Each run stores:

- Baseline access result
- Containment request result
- Every post-containment access attempt
- Effective containment time
- Hash-chained execution events
- HMAC-signed JSON evidence
- Standalone HTML report

Run history is stored locally in `.containmentci/runs.db`.

## Development

```powershell
pip install -e ".[dev]"
ruff check .
pytest -q
```

Provider implementations extend `ContainmentProvider` with `verify_access`, `contain`, and
optional offline validation. See [docs/architecture.md](docs/architecture.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Read [SECURITY.md](SECURITY.md) before implementing or running a live provider. Security
issues should be reported privately rather than opened as public issues.

