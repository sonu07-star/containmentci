import asyncio

import httpx
import pytest

from containmentci.engine import ExecutionEngine
from containmentci.models import CheckStatus, ScenarioConfig


def test_live_provider_requires_explicit_approval(monkeypatch) -> None:
    monkeypatch.setenv("TEST_HTTP_SUBJECT_TOKEN", "subject-secret")
    monkeypatch.setenv("TEST_HTTP_ADMIN_TOKEN", "admin-secret")
    scenario = ScenarioConfig.model_validate(
        {
            "name": "live",
            "identity": "synthetic@example.com",
            "targets": [
                {
                    "name": "live-http",
                    "provider": "http",
                    "resource": "test://live",
                    "metadata": {
                        "safety_acknowledgement": "dedicated-synthetic-identity",
                        "probe_url": "https://example.com/probe",
                        "containment_url": "https://example.com/contain",
                        "denied_statuses": [401, 403],
                        "headers_from_env": {"Authorization": "TEST_HTTP_SUBJECT_TOKEN"},
                        "containment_headers_from_env": {"Authorization": "TEST_HTTP_ADMIN_TOKEN"},
                    },
                }
            ],
        }
    )
    run = asyncio.run(ExecutionEngine().run(scenario))
    assert run.checks[0].status == CheckStatus.ERROR
    assert "--approve-live" in run.checks[0].message


def test_direct_engine_live_run_enforces_preflight_before_network(monkeypatch) -> None:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "unsafe-direct-sdk",
            "identity": "synthetic@example.com",
            "targets": [
                {
                    "name": "live-http",
                    "provider": "http",
                    "resource": "test://live",
                    "metadata": {
                        "probe_url": "https://example.com/probe",
                        "containment_url": "https://example.com/contain",
                        "denied_statuses": [401],
                    },
                }
            ],
        }
    )

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("Invalid live configuration must fail before network access")

    monkeypatch.setattr(httpx.AsyncClient, "request", fail_if_called)

    with pytest.raises(ValueError, match="safety_acknowledgement"):
        asyncio.run(ExecutionEngine(allow_live=True).run(scenario))


def test_direct_engine_live_run_requires_strong_signing_key(monkeypatch) -> None:
    monkeypatch.delenv("CONTAINMENTCI_SIGNING_KEY", raising=False)
    monkeypatch.setenv("TEST_HTTP_SUBJECT_TOKEN", "subject-secret")
    monkeypatch.setenv("TEST_HTTP_ADMIN_TOKEN", "admin-secret")
    scenario = ScenarioConfig.model_validate(
        {
            "name": "unsigned-live-sdk",
            "identity": "synthetic@example.com",
            "targets": [
                {
                    "name": "live-http",
                    "provider": "http",
                    "resource": "test://live",
                    "metadata": {
                        "safety_acknowledgement": "dedicated-synthetic-identity",
                        "probe_url": "https://example.com/probe",
                        "containment_url": "https://example.com/contain",
                        "denied_statuses": [401],
                        "headers_from_env": {"Authorization": "TEST_HTTP_SUBJECT_TOKEN"},
                        "containment_headers_from_env": {"Authorization": "TEST_HTTP_ADMIN_TOKEN"},
                    },
                }
            ],
        }
    )

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("Unsigned live execution must fail before network access")

    monkeypatch.setattr(httpx.AsyncClient, "request", fail_if_called)

    with pytest.raises(PermissionError, match="at least 32 bytes"):
        asyncio.run(ExecutionEngine(allow_live=True).run(scenario))
