# CI Integration

ContainmentCI exits `0` only when every target produces enough explicit denial samples within
its containment SLO. Provider-classified outages or rate limits and unhealthy control
credentials never become passing results.

## GitHub Action

Pin a released major version in a consuming repository:

```yaml
name: Containment proof

on:
  workflow_dispatch:
  schedule:
    - cron: "17 3 * * 1"

concurrency:
  group: containmentci-github-synthetic-fixture
  cancel-in-progress: false

jobs:
  containment:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: sonu07-star/containmentci@v0
        id: containment
        with:
          scenario: security/containment/github.yaml
          report: artifacts/containment-report.html
          junit: artifacts/containment-junit.xml
          evidence: artifacts/containment-evidence.json
          approve-live: "true"
        env:
          CONTAINMENTCI_SIGNING_KEY: ${{ secrets.CONTAINMENTCI_SIGNING_KEY }}
          CONTAINMENTCI_GITHUB_PROBE_TOKEN: ${{ secrets.CONTAINMENTCI_GITHUB_PROBE_TOKEN }}
          CONTAINMENTCI_GITHUB_ADMIN_TOKEN: ${{ secrets.CONTAINMENTCI_GITHUB_ADMIN_TOKEN }}
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: containment-evidence
          path: |
            ${{ steps.containment.outputs.report }}
            ${{ steps.containment.outputs.junit }}
            ${{ steps.containment.outputs.evidence }}
```

Live providers change state. Use dedicated synthetic identities and disposable resources,
store every secret in the CI secret store, and keep `approve-live` disabled for simulations.
The fixed concurrency group is part of the safety boundary: choose one unique group per shared
fixture. ContainmentCI's SQLite lease coordinates processes sharing a state directory, but
cross-repository or cross-platform runners need an external/global fixture lock as well.

## Any CI System

Install the package, then use the CLI's exit status and JUnit output:

```bash
containmentci run scenario.yaml \
  --report artifacts/containment-report.html \
  --junit artifacts/containment-junit.xml \
  --evidence artifacts/containment-evidence.json
containmentci verify artifacts/containment-evidence.json
```

The JUnit file represents each target as a test case, records failures and provider errors
separately, and includes the proof mode, first-denial time, proof-completion time, SLO, and
denial-confirmation count. The JSON bundle contains the complete signed run and hash-chained
event transcript; archive it when the proof succeeds or fails. Use a secret signing key of at
least 32 bytes for evidence that must be independently trusted.

The Action exposes `report`, `junit`, and `evidence` outputs containing the paths supplied in its
matching inputs. This makes artifact upload steps independent of the chosen filenames.
