import asyncio
import os

import httpx

from containmentci.models import TargetConfig
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


def test_http_provider_requires_header_environment_variable(monkeypatch) -> None:
    os.environ.pop("MISSING_TEST_TOKEN", None)
    target = TargetConfig(
        name="missing-secret",
        provider="http",
        resource="test://missing",
        metadata={
            "probe_url": "https://example.com/probe",
            "headers_from_env": {"Authorization": "MISSING_TEST_TOKEN"},
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

