import asyncio

import httpx

from containmentci.models import AccessState, TargetConfig
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
        if request.url.path == "/user":
            login = (
                "containmentci-synthetic"
                if "probe-secret" in request.headers["authorization"]
                else "acme-admin"
            )
            return httpx.Response(200, json={"login": login})
        if request.method == "DELETE":
            contained = True
            return httpx.Response(204, headers={"x-github-request-id": "delete-id"})
        return httpx.Response(
            404 if contained else 200, headers={"x-github-request-id": "probe-id"}
        )

    provider = GitHubRepositoryAccessProvider(httpx.MockTransport(handler))
    before = asyncio.run(provider.verify_access("containmentci-synthetic", target()))
    removal = asyncio.run(provider.contain("containmentci-synthetic", target()))
    after = asyncio.run(provider.verify_access("containmentci-synthetic", target()))

    assert before.success
    assert removal.success
    assert not after.success
    assert after.evidence["status_code"] == 404


def test_github_provider_binds_probe_token_to_synthetic_identity(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "wrong-collaborator"})
        raise AssertionError("Repository must not be probed with a mismatched credential")

    provider = GitHubRepositoryAccessProvider(httpx.MockTransport(handler))
    response = asyncio.run(provider.verify_access("containmentci-synthetic", target()))

    assert response.state == AccessState.INDETERMINATE
    assert response.evidence["authenticated_login"] == "wrong-collaborator"


def test_github_provider_rejects_identity_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")
    configured = target()
    configured.metadata["username"] = "real-employee"

    problems = GitHubRepositoryAccessProvider().validate("containmentci-synthetic", configured)
    assert any("must match scenario identity" in problem for problem in problems)


def test_github_provider_does_not_treat_rate_limit_as_denial(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "containmentci-synthetic"})
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0"})

    provider = GitHubRepositoryAccessProvider(httpx.MockTransport(handler))
    response = asyncio.run(provider.verify_access("containmentci-synthetic", target()))

    assert response.state == AccessState.INDETERMINATE


def test_github_provider_keeps_unauthorized_response_indeterminate(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "containmentci-synthetic"})
        return httpx.Response(401)

    provider = GitHubRepositoryAccessProvider(httpx.MockTransport(handler))
    response = asyncio.run(provider.verify_access("containmentci-synthetic", target()))

    assert response.state == AccessState.INDETERMINATE


def test_github_provider_rejects_non_github_api_host(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "probe-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "admin-secret")
    configured = target()
    configured.metadata["api_url"] = "https://credential-capture.example"

    problems = GitHubRepositoryAccessProvider().validate("containmentci-synthetic", configured)

    assert any("exactly https://api.github.com" in problem for problem in problems)


def test_github_provider_rejects_probe_admin_secret_overlap(monkeypatch) -> None:
    monkeypatch.setenv("TEST_GITHUB_PROBE_TOKEN", "same-secret")
    monkeypatch.setenv("TEST_GITHUB_ADMIN_TOKEN", "same-secret")

    problems = GitHubRepositoryAccessProvider().validate("containmentci-synthetic", target())

    assert any("credential values must be distinct" in problem for problem in problems)
