# Contributing

ContainmentCI accepts focused bug fixes, provider adapters, tests, and documentation
improvements.

## Before Opening A Pull Request

Open an issue before making broad architectural changes or adding a live provider. Describe
the containment action, the access path used to verify it, required permissions, and how the
test is safely restored.

Live providers must:

- Operate only on explicitly configured resources.
- Validate that the target identity is synthetic.
- Keep credentials outside scenario files and evidence.
- Treat provider API acknowledgement as evidence, not proof of containment.
- Include mocked tests covering successful containment and persistent access.
- Document minimum permissions and restoration steps.

## Local Checks

```powershell
pip install -e ".[dev]"
ruff check .
pytest -q
```

Keep changes scoped. Do not include local databases, evidence bundles, reports, credentials,
or generated build artifacts.

