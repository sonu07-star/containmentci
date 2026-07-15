# ContainmentCI

[![CI](https://github.com/sonu07-star/containmentci/actions/workflows/ci.yml/badge.svg)](https://github.com/sonu07-star/containmentci/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/sonu07-star/containmentci/blob/main/LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![Project status: alpha](https://img.shields.io/badge/status-alpha-f59e0b.svg)](https://github.com/sonu07-star/containmentci/blob/main/CHANGELOG.md)

> **The revoke API returned `204`. Can the stolen credential still get in?**

ContainmentCI is open-source **identity containment validation**. It proves a dedicated
synthetic credential works, triggers containment, replays the original access path until
explicit denial, and gates on a measurable containment SLO.

Unlike a simple poller, ContainmentCI can pair the subject credential with a distinct untouched
control credential. The control must work before containment and during every counted denial.
A same-resource control produces the strongest controlled proof; a different endpoint is
explicitly labeled an availability witness. Provider-classified outages, rate limits, redirects,
and ambiguous responses are `INDETERMINATE`—never a false `PASS`.

![ContainmentCI records explicit subject denial while a control credential remains healthy](https://raw.githubusercontent.com/sonu07-star/containmentci/main/docs/assets/causal-proof.svg)

```text
                         CONTAIN
Subject credential   ALLOWED ──────────▶ DENIED ─▶ DENIED
Control credential   ALLOWED ────────────────────▶ ALLOWED
                                                   └─ PASS within 2.0s SLO
```

**Containment verification as code:** repeatable scenarios, controlled denial confirmation, first-denial
and proof-completion timing, hash-chained events, signed evidence, HTML reports, JUnit XML, and
a reusable GitHub Action.

## 60-Second Safe Demo

Requires Python 3.11 or newer. This installs directly from GitHub until the first PyPI release:

```bash
python -m pip install "git+https://github.com/sonu07-star/containmentci.git"
containmentci demo --report containment-report.html --junit containment-junit.xml \
  --evidence containment-evidence.json
```

The demo is local, deterministic, makes no network requests, and exits `0`:

```text
Revoked API token            PASS     0.05s/0.08s/0.25s  Explicit denial confirmed 2 times while control access stayed healthy
Terminated web session       PASS     0.10s/0.13s/0.40s  Explicit denial confirmed 2 times while control access stayed healthy

Containment coverage: 100.0%
Result: PASS
```

To see a broken control correctly fail the gate:

```bash
git clone https://github.com/sonu07-star/containmentci.git
cd containmentci
containmentci run examples/compromised-user.yaml --report containment-report.html
```

That scenario is explicitly simulated and intentionally leaves one session active.

## What Makes A Controlled Containment Proof

For every target, the engine:

1. Proves the subject credential can access a dedicated test resource.
2. Requests account disablement, credential revocation, session termination, or access removal.
3. Starts the target's containment SLO clock at the containment request.
4. Replays the same subject access path until it receives an explicit authorization denial.
5. When configured, verifies an untouched control before containment and during each denial.
6. Requires consecutive denial samples and records the full witness transcript as evidence.

Provider probes return one of three semantic states:

| State | Meaning | Can pass? |
| --- | --- | --- |
| `ALLOWED` | The subject can still reach the protected resource | No |
| `DENIED` | A provider-recognized authorization denial occurred | Only with enough confirmations and a healthy required control |
| `INDETERMINATE` | Throttling, outage, unexpected status, or ambiguous result | Never |

This is the core distinction: ContainmentCI tests the security outcome, not the management API
acknowledgement.

## How It Differs

| Tool type | What it usually verifies |
| --- | --- |
| IAM posture scanner | Policy and configuration |
| SOAR or incident-response runbook | The containment request was accepted |
| BAS or adversary emulation | Attack, prevention, and detection behavior |
| **ContainmentCI** | Controlled evidence that the original attacker-held access path is explicitly denied within its SLO while a witness remains healthy |

ContainmentCI complements BAS, SOAR, and posture tools; it is purpose-built for the last-mile
question: **did access actually stop?**

## Define A Scenario

```yaml
name: github-synthetic-collaborator-containment
description: Prove a synthetic collaborator loses private-repository access.
identity: containmentci-synthetic
timeout_seconds: 120
poll_interval_seconds: 5
targets:
  - name: GitHub synthetic collaborator
    provider: github-repository-access
    resource: github://YOUR_OWNER/containmentci-test-resource
    max_containment_seconds: 30
    denial_confirmation_attempts: 2
    control_required: true
    metadata:
      owner: YOUR_OWNER
      repo: containmentci-test-resource
      username: containmentci-synthetic
      safety_acknowledgement: dedicated-synthetic-identity
      probe_token_env: CONTAINMENTCI_GITHUB_PROBE_TOKEN
      admin_token_env: CONTAINMENTCI_GITHUB_ADMIN_TOKEN
```

The GitHub admin token is also used as the healthy control witness unless
`metadata.control_token_env` names a separate token. Use only a dedicated synthetic account and
a disposable private repository.

Validate configuration without network requests, then explicitly approve the live change:

```bash
export CONTAINMENTCI_GITHUB_PROBE_TOKEN="replace-with-probe-token"
export CONTAINMENTCI_GITHUB_ADMIN_TOKEN="replace-with-admin-token"
export CONTAINMENTCI_SIGNING_KEY="replace-with-at-least-32-random-bytes"

containmentci check examples/github-repository-access.yaml
containmentci run examples/github-repository-access.yaml \
      --approve-live \
      --report .containmentci/github-report.html \
      --junit .containmentci/github-junit.xml \
      --evidence .containmentci/github-evidence.json
```

See the complete [GitHub lab and restoration runbook](https://github.com/sonu07-star/containmentci/blob/main/docs/github-real-world-test.md).

## Use It In CI

The repository includes a composite action. After a `v0` release, consumers can pin it directly.
Use a fixture-specific workflow concurrency group so separate runners cannot operate on the same
identity at once:

```yaml
concurrency:
  group: containmentci-github-synthetic-fixture
  cancel-in-progress: false
```

Then invoke the Action in the job's `steps`:

```yaml
- uses: sonu07-star/containmentci@v0
  with:
    scenario: security/containment.yaml
    report: artifacts/containment-report.html
    junit: artifacts/containment-junit.xml
    evidence: artifacts/containment-evidence.json
    approve-live: "true"
  env:
    CONTAINMENTCI_SIGNING_KEY: ${{ secrets.CONTAINMENTCI_SIGNING_KEY }}
```

ContainmentCI exits nonzero when a target misses its SLO, remains accessible, becomes
indeterminate, or errors. See [CI integration](https://github.com/sonu07-star/containmentci/blob/main/docs/ci-integration.md) for a scheduled workflow
and artifact upload example.

## Providers

Available now:

| Provider | Purpose | Controlled witness |
| --- | --- | --- |
| `simulation` | Deterministic local demos, tests, and CI | Built in |
| `http` | Connect an access probe and containment API | Distinct control credential, optionally against a separate endpoint |
| `github-repository-access` | Remove and verify a synthetic private-repository collaborator | Admin token or dedicated control token |

Roadmap—not implemented yet:

- Microsoft Entra ID account, session, and Continuous Access Evaluation containment
- AWS IAM/STS credentials and assumed-role sessions
- Slack sessions, VPN certificates, SSH keys, and OAuth/CAEP signals
- Safe automatic fixture restoration and multi-region witness quorum

Provider implementations extend `ContainmentProvider` with `verify_access`, `contain`, and
optional control-probe behavior. Read [the architecture](https://github.com/sonu07-star/containmentci/blob/main/docs/architecture.md) and
[contribution guide](https://github.com/sonu07-star/containmentci/blob/main/CONTRIBUTING.md).

## Commands

```text
containmentci demo                         Run a safe all-pass controlled proof
containmentci check SCENARIO               Validate config and required secrets offline
containmentci run SCENARIO                 Execute a simulation scenario
containmentci run SCENARIO --approve-live  Authorize state-changing providers
containmentci export RUN_ID FILE           Export signed JSON evidence
containmentci verify FILE                  Verify signature and event hash chain
containmentci serve                        Start the local API and dashboard
containmentci --version                    Show the installed version
```

## Evidence And Trust Model

Each run records the baseline decision, containment response, every subject and control sample,
first control-validated denial time, proof-completion time, SLO, proof mode, consecutive confirmations,
hash-chained events, and an HMAC-signed JSON bundle. `containmentci verify` validates both the
signature and the complete event chain.

A healthy control rules out a broad service outage, but it cannot rule out every outside event,
such as independent token expiry or another administrator revoking the subject at the same time.
ContainmentCI therefore produces strong controlled evidence—not an absolute causal attestation.

HMAC evidence is tamper-evident inside one shared-key administrative domain; it is not an
independent public attestation. Live CLI/API runs reject the known development signing keys.
Asymmetric KMS/Sigstore evidence is on the roadmap.

Run history is stored locally in `.containmentci/runs.db`. The signed JSON is the verifiable
evidence artifact; HTML and JUnit are human- and CI-readable summaries.

## Safety

- Use only synthetic identities and disposable resources with no production data.
- Live providers require `--approve-live` and a signing key of at least 32 bytes.
- API live execution additionally requires a server gate, per-request approval, and a Bearer
  token that is distinct from the evidence signing key.
- Live runs sharing one state directory are protected by cross-process identity/resource leases;
  runners on different machines require a CI concurrency group or external global lock.
- A live scenario may contain only one state-changing target. Use an isolated identity per
  control and do not reuse it until restoration and propagation have stabilized.
- The generic HTTP provider accepts HTTPS or exact loopback hostnames; evidence strips URL query
  strings to avoid retaining secrets. It accepts explicit `401`, endpoint-contract `403`, and
  same-resource-controlled `404` denial semantics. Subject and containment credentials are
  required; any configured control credential must be distinct. Configure only responses the
  endpoint documents as unambiguous authorization decisions; common throttling headers override
  a configured denial.
- Every live provider requires `safety_acknowledgement: dedicated-synthetic-identity`.
- Restore the synthetic fixture after each live test using the provider runbook.

Read [SECURITY.md](https://github.com/sonu07-star/containmentci/blob/main/SECURITY.md) before operating or extending a live provider.

## Development

```bash
git clone https://github.com/sonu07-star/containmentci.git
cd containmentci
python -m venv .venv
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
```

ContainmentCI is Apache-2.0 licensed and early-stage. Focused provider adapters, safety tests,
real-world revocation measurements, and documentation improvements are welcome.

See the [public roadmap](https://github.com/sonu07-star/containmentci/blob/main/ROADMAP.md) for safe restoration, Entra/AWS/CAEP providers, asymmetric
attestations, and the proposed Open Revocation Latency Index.
