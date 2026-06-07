# GitHub Real-World Containment Test

This test removes a dedicated synthetic GitHub user from a dedicated private repository,
then proves that the same synthetic user's token can no longer read that repository.

## Safety Boundary

Use a new repository containing no production code or data. Use a synthetic GitHub account
that has no access outside this repository.

The scenario identity and configured GitHub username must match. ContainmentCI rejects a
mismatch to reduce the risk of removing the wrong collaborator.

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
$env:CONTAINMENTCI_GITHUB_PROBE_TOKEN = "github_pat_probe"
$env:CONTAINMENTCI_GITHUB_ADMIN_TOKEN = "github_pat_admin"
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
  --report .containmentci/github-report.html
```

ContainmentCI first proves the probe token can read the private repository, removes the
synthetic collaborator, and repeatedly retries the same probe until GitHub returns denial.

## Restore

Re-add `containmentci-synthetic` as a read-only collaborator before the next scheduled test.
Confirm that the probe token can read the repository again by running the preflight and test
from the beginning.

Do not automate restoration until a separate administrative identity, approval policy, and
audit trail are implemented.

GitHub API references:

- [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)
- [Remove a repository collaborator](https://docs.github.com/en/rest/collaborators/collaborators#remove-a-repository-collaborator)
