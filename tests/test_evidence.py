import asyncio

import pytest
from pydantic import ValidationError

from containmentci.engine import ExecutionEngine
from containmentci.evidence import sign_run, signing_key_is_configured, verify_run
from containmentci.models import RunResult, ScenarioConfig


def completed_run() -> RunResult:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "evidence-integrity",
            "identity": "synthetic@example.com",
            "targets": [{"name": "token", "resource": "test://token"}],
        }
    )
    return asyncio.run(ExecutionEngine().run(scenario))


def test_configured_mode_cannot_be_forged_with_development_key(monkeypatch) -> None:
    monkeypatch.delenv("CONTAINMENTCI_SIGNING_KEY", raising=False)
    run = completed_run()
    run.evidence_key_mode = "configured-hmac"
    run.signature = sign_run(run, "development-key")

    assert not verify_run(run)


def test_short_signing_key_is_not_trusted(monkeypatch) -> None:
    monkeypatch.setenv("CONTAINMENTCI_SIGNING_KEY", "too-short")

    assert not signing_key_is_configured()
    run = completed_run()
    assert run.evidence_key_mode == "development-hmac"
    assert verify_run(run)


def test_unknown_evidence_fields_are_rejected() -> None:
    payload = completed_run().model_dump(mode="json")
    payload["unsigned_annotation"] = "must-not-be-ignored"

    with pytest.raises(ValidationError):
        RunResult.model_validate(payload)
