## Summary

Describe what changed and the user or operator outcome it improves.

## Related issue

Link the issue or explain why one is not needed.

## Validation

List the commands, scenarios, or manual checks used to validate the change.

## Safety and operational impact

Describe any credential, permission, network, state-changing, restoration, or
backward-compatibility considerations. Write `Not applicable` when none exist.

## Checklist

- [ ] I kept this pull request focused and explained any non-obvious design choices.
- [ ] I ran `ruff check .` and `pytest -q`, or explained why a check was not run.
- [ ] I added or updated tests for behavior changed by this pull request.
- [ ] I updated user-facing documentation and `CHANGELOG.md` when appropriate.
- [ ] I did not include credentials, private resource names, evidence bundles,
      local databases, or generated reports.
- [ ] Live-provider changes use dedicated synthetic identities and disposable test
      resources, enforce explicit approval, and document minimum permissions and
      restoration steps, or are marked `Not applicable` above.
