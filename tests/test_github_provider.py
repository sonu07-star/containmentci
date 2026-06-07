import asyncio

import httpx

from containmentci.models import TargetConfig
from containmentci.providers.github import GitHubRepositoryAccessProvider


def target() -> TargetConfig:
    return TargetConfig(
        name="GitHub synthetic collaborator",
        provider="github-repository-access",
        resource="github://acme/containmentci-test",
        metadata={
            "owner": "acme",
            "repo": "containmentci-test",
            "username": "containmentci-synthetic",
            "safety_acknowledgement": "dedicated-synthetic-identity",
            "probe_token_env": "TEST_GITHUB_PROBE_TOKEN",
            "admin_token_env": "TEST_GITHUB_ADMIN_TOKEN",
        },
    )


def test_github_provider_probes_and_contains(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")
    contained = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal contained
        assert "secret" in request.headers["authorization"]
        if request.method == "DELETE":
            contained = True
            return httpx.Response(204, headers={"x-github-request-id": "delete-id"})
        return httpx.Response(404 if contained else 200, headers={"x-github-request-id": "probe-id"})

    provider = GitHubRepositoryAccessProvider(httpx.MockTransport(handler))
    before = asyncio.run(provider.verify_access("containmentci-synthetic", target()))
    removal = asyncio.run(provider.contain("containmentci-synthetic", target()))
    after = asyncio.run(provider.verify_access("containmentci-synthetic", target()))

    assert before.success
    assert removal.success
    assert not after.success
    assert after.evidence["status_code"] == 404


def test_github_provider_rejects_identity_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")
    configured = target()
    configured.metadata["username"] = "real-employee"

    problems = GitHubRepositoryAccessProvider().validate("containmentci-synthetic", configured)
    assert any("must match scenario identity" in problem for problem in problems)
