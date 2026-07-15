# GitHub Real-World Containment Test

This test removes a dedicated synthetic GitHub user from a dedicated private repository,
then proves that the same synthetic user's token can no longer read that repository.
The administrative token remains able to read the repository as a control witness, so a GitHub
outage or rate limit cannot be counted as successful containment.

## Safety Boundary

Use a new repository containing no production code or data. Use a synthetic GitHub account
that has no access outside this repository.

The scenario identity and configured GitHub username must match. ContainmentCI rejects a
mismatch to reduce the risk of removing the wrong collaborator. Before probing or removal, it
also calls GitHub's authenticated-user endpoint to bind each token to its actual account.

The scenario must also include:

```yaml
safety_acknowledgement: dedicated-synthetic-identity
```

This is a deliberate operator acknowledgement, not proof that an account is synthetic.

## Prepare GitHub

1. Create a private repository named `containmentci-test-resource`.
2. Create or select a dedicated synthetic GitHub user, such as `containmentci-synthetic`.
3. Add the synthetic user as a direct read-only collaborator.
4. Create a fine-grained token for the synthetic user scoped only to the test repository.
5. Create an admin token that can remove collaborators from only the test repository.

The admin token requires repository Administration write permission. The probe token should
have only the minimum repository read access required for `GET /repos/{owner}/{repo}`.

## Configure

Edit `examples/github-repository-access.yaml` and replace `YOUR_OWNER`.

Set secrets only in the current shell:

```powershell
$env:CONTAINMENTCI_GITHUB_PROBE_TOKEN = "replace-with-probe-token"
$env:CONTAINMENTCI_GITHUB_ADMIN_TOKEN = "replace-with-admin-token"
$env:CONTAINMENTCI_SIGNING_KEY = "replace-with-at-least-32-random-bytes"
```

Validate configuration without making network requests:

```powershell
python -m containmentci.cli check examples/github-repository-access.yaml
```

## Execute

The live approval flag is mandatory:

```powershell
python -m containmentci.cli run examples/github-repository-access.yaml `
  --approve-live `
  --report .containmentci/github-report.html `
  --evidence .containmentci/github-evidence.json
```

ContainmentCI first proves the probe token can read the private repository, removes the
synthetic collaborator, and repeatedly retries the same probe until GitHub returns two explicit
denials while the admin control token still reads the repository. The test fails if that causal
sequence is not complete within `max_containment_seconds`. This is strong controlled evidence;
it cannot exclude every outside administrative action or independent token-lifecycle event.

ContainmentCI prevents overlapping processes that share `.containmentci`, but scheduled jobs on
separate runners must use a fixture-specific CI concurrency group or external global lock.

## Restore

Re-add `containmentci-synthetic` as a read-only collaborator before the next scheduled test.
Confirm that the probe token can read the repository again by running the preflight and test
from the beginning.

Do not automate restoration until a separate administrative identity, approval policy, and
audit trail are implemented.

GitHub API references:

- [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)
- [Remove a repository collaborator](https://docs.github.com/en/rest/collaborators/collaborators#remove-a-repository-collaborator)
