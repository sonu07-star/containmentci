import asyncio
import os

import httpx

from containmentci.models import AccessState, TargetConfig
from containmentci.providers.http import HttpProvider


def test_http_provider_rejects_insecure_remote_url() -> None:
    target = TargetConfig(
        name="unsafe",
        provider="http",
        resource="test://unsafe",
        metadata={
            "probe_url": "http://example.com/probe",
            "containment_url": "https://example.com/contain",
        },
    )
    try:
        asyncio.run(HttpProvider().verify_access("synthetic@example.com", target))
    except ValueError as exc:
        assert "must use HTTPS" in str(exc)
    else:
        raise AssertionError("Insecure URL should be rejected")


def test_http_provider_rejects_deceptive_loopback_hostname() -> None:
    target = TargetConfig(
        name="deceptive-loopback",
        provider="http",
        resource="test://unsafe",
        metadata={
            "probe_url": "http://localhost.evil.example/probe",
            "containment_url": "https://example.com/contain",
        },
    )

    problems = HttpProvider().validate("synthetic@example.com", target)

    assert any("exact loopback hostname" in problem for problem in problems)


def test_http_provider_requires_header_environment_variable(monkeypatch) -> None:
    os.environ.pop("MISSING_TEST_TOKEN", None)
    target = TargetConfig(
        name="missing-secret",
        provider="http",
        resource="test://missing",
        metadata={
            "probe_url": "https://example.com/probe",
            "headers_from_env": {"Authorization": "MISSING_TEST_TOKEN"},
            "denied_statuses": [401, 403],
        },
    )

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("Network must not be called without required secrets")

    monkeypatch.setattr(httpx.AsyncClient, "request", fail_if_called)
    try:
        asyncio.run(HttpProvider().verify_access("synthetic@example.com", target))
    except ValueError as exc:
        assert "MISSING_TEST_TOKEN" in str(exc)
    else:
        raise AssertionError("Missing environment variable should fail")


def test_http_provider_keeps_server_errors_indeterminate(monkeypatch) -> None:
    target = TargetConfig(
        name="outage",
        provider="http",
        resource="test://outage",
        metadata={
            "probe_url": "https://example.com/probe?secret=redacted",
            "containment_url": "https://example.com/contain",
            "denied_statuses": [401, 403],
        },
    )

    async def server_error(*args, **kwargs):
        return httpx.Response(503)

    monkeypatch.setattr(httpx.AsyncClient, "request", server_error)
    response = asyncio.run(HttpProvider().verify_access("synthetic@example.com", target))

    assert response.state == AccessState.INDETERMINATE
    assert response.evidence["probe_url"] == "https://example.com/probe"


def test_http_provider_rate_limit_headers_override_configured_403(monkeypatch) -> None:
    target = TargetConfig(
        name="throttled",
        provider="http",
        resource="test://throttled",
        metadata={
            "probe_url": "https://example.com/probe",
            "containment_url": "https://example.com/contain",
            "denied_statuses": [403],
        },
    )

    async def throttled(*args, **kwargs):
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0"})

    monkeypatch.setattr(httpx.AsyncClient, "request", throttled)
    response = asyncio.run(HttpProvider().verify_access("synthetic@example.com", target))

    assert response.state == AccessState.INDETERMINATE


def test_http_provider_never_forwards_probe_credential_to_containment(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SUBJECT_TOKEN", "subject-secret")
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")
    target = TargetConfig(
        name="separate-credentials",
        provider="http",
        resource="test://separate",
        metadata={
            "probe_url": "https://resource.example/probe",
            "containment_url": "https://admin.example/contain",
            "denied_statuses": [401, 403],
            "headers_from_env": {"Authorization": "SUBJECT_TOKEN"},
            "containment_headers_from_env": {"Authorization": "ADMIN_TOKEN"},
        },
    )

    async def accepted(request_self, method, url, **kwargs):
        assert kwargs["headers"]["Authorization"] == "admin-secret"
        assert "subject-secret" not in kwargs["headers"].values()
        return httpx.Response(204)

    monkeypatch.setattr(httpx.AsyncClient, "request", accepted)
    response = asyncio.run(HttpProvider().contain("synthetic@example.com", target))

    assert response.success


def test_http_provider_rejects_outage_status_as_denial() -> None:
    configured = TargetConfig(
        name="unsafe-status",
        provider="http",
        resource="test://unsafe-status",
        metadata={
            "safety_acknowledgement": "dedicated-synthetic-identity",
            "probe_url": "https://example.com/probe",
            "containment_url": "https://example.com/contain",
            "denied_statuses": [503],
        },
    )

    problems = HttpProvider().validate("synthetic@example.com", configured)

    assert any("unsupported: 503" in problem for problem in problems)


def test_http_provider_requires_control_before_404_can_prove_denial() -> None:
    configured = TargetConfig(
        name="hidden-resource",
        provider="http",
        resource="test://hidden-resource",
        metadata={
            "safety_acknowledgement": "dedicated-synthetic-identity",
            "probe_url": "https://example.com/probe",
            "containment_url": "https://example.com/contain",
            "denied_statuses": [404],
        },
    )

    problems = HttpProvider().validate("synthetic@example.com", configured)

    assert any(
        "requires a distinct same-resource control credential" in problem for problem in problems
    )


def test_http_provider_does_not_treat_different_query_resource_as_same_control(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SUBJECT_TOKEN", "subject-secret")
    monkeypatch.setenv("CONTROL_TOKEN", "control-secret")
    configured = TargetConfig(
        name="query-resource",
        provider="http",
        resource="test://query-resource",
        metadata={
            "safety_acknowledgement": "dedicated-synthetic-identity",
            "probe_url": "https://example.com/probe?resource=subject",
            "control_probe_url": "https://example.com/probe?resource=control",
            "containment_url": "https://example.com/contain",
            "denied_statuses": [404],
            "headers_from_env": {"Authorization": "SUBJECT_TOKEN"},
            "control_headers_from_env": {"Authorization": "CONTROL_TOKEN"},
        },
    )

    problems = HttpProvider().validate("synthetic@example.com", configured)

    assert any(
        "requires a distinct same-resource control credential" in problem for problem in problems
    )


def test_http_provider_404_control_must_use_the_same_safe_method(monkeypatch) -> None:
    monkeypatch.setenv("SUBJECT_TOKEN", "subject-secret")
    monkeypatch.setenv("CONTROL_TOKEN", "control-secret")
    configured = TargetConfig(
        name="method-mismatch",
        provider="http",
        resource="test://method-mismatch",
        metadata={
            "safety_acknowledgement": "dedicated-synthetic-identity",
            "probe_url": "https://example.com/probe",
            "probe_method": "GET",
            "control_probe_method": "HEAD",
            "containment_url": "https://example.com/contain",
            "denied_statuses": [404],
            "headers_from_env": {"Authorization": "SUBJECT_TOKEN"},
            "control_headers_from_env": {"Authorization": "CONTROL_TOKEN"},
        },
    )

    problems = HttpProvider().validate("synthetic@example.com", configured)

    assert any(
        "requires a distinct same-resource control credential" in problem for problem in problems
    )


def test_http_provider_rejects_equal_subject_and_admin_secret_values(monkeypatch) -> None:
    monkeypatch.setenv("SUBJECT_SECRET", "same-loaded-secret")
    monkeypatch.setenv("ADMIN_SECRET", "same-loaded-secret")
    configured = TargetConfig(
        name="secret-overlap",
        provider="http",
        resource="test://secret-overlap",
        metadata={
            "safety_acknowledgement": "dedicated-synthetic-identity",
            "probe_url": "https://resource.example/probe",
            "containment_url": "https://admin.example/contain",
            "denied_statuses": [401, 403],
            "headers_from_env": {"Authorization": "SUBJECT_SECRET"},
            "containment_headers_from_env": {"Authorization": "ADMIN_SECRET"},
        },
    )

    problems = HttpProvider().validate("synthetic@example.com", configured)

    assert any("credential values must be distinct" in problem for problem in problems)


def test_http_provider_rejects_mutating_probe_methods() -> None:
    for method_key in ("probe_method", "control_probe_method"):
        configured = TargetConfig(
            name="mutating-probe",
            provider="http",
            resource="test://mutating-probe",
            metadata={
                "safety_acknowledgement": "dedicated-synthetic-identity",
                "probe_url": "https://example.com/probe",
                method_key: "DELETE",
                "containment_url": "https://example.com/contain",
                "denied_statuses": [401],
            },
        )

        problems = HttpProvider().validate("synthetic@example.com", configured)

        assert any(f"{method_key} must be GET or HEAD" in problem for problem in problems)
