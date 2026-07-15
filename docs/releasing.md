# Releasing ContainmentCI

The release workflow builds a wheel and source distribution, checks their package metadata,
installs each artifact into its own clean virtual environment, and runs a signed-evidence demo
from both installations before publishing through PyPI Trusted Publishing. It does not use a
long-lived PyPI API token.

## One-Time Setup

1. Create or sign in to the maintainer's PyPI account.
2. Register a pending Trusted Publisher for project `containmentci` with:
   - Owner: `sonu07-star`
   - Repository: `containmentci`
   - Workflow: `release.yml`
   - Environment: `pypi`
3. Create a protected GitHub environment named `pypi` and require manual approval.
4. Protect `main` and require the CI workflow before merge.

Use the official [PyPI Trusted Publishing setup](https://docs.pypi.org/trusted-publishers/)
for the current account screens and security guidance.

## Release Checklist

1. Update `containmentci.__version__`, `project.version`, and `CHANGELOG.md` together.
2. Run `ruff check .`, `pytest -q`, and `python -m build` locally.
3. Install both `dist/*.whl` and `dist/*.tar.gz` into separate clean virtual environments, then
   run `containmentci --version`, `containmentci demo --evidence evidence.json`, and
   `containmentci verify evidence.json` from each one.
4. Merge the release commit to `main`.
5. Create a GitHub release whose tag exactly matches the package version, such as `v0.3.0`.
6. Approve the protected `pypi` deployment after reviewing the built and smoke-tested artifacts.
7. Verify the PyPI provenance and install the released package in a clean environment.
8. Move the floating `v0` tag to the same reviewed commit so GitHub Action consumers receive the
   compatible release.

The official PyPA publishing action creates PyPI attestations by default when Trusted Publishing
is used.
