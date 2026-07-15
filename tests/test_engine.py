import asyncio
import time

import pytest
from pydantic import ValidationError

from containmentci.engine import ExecutionEngine
from containmentci.evidence import sign_run, verify_run
from containmentci.models import AccessState, CheckStatus, RunStatus, ScenarioConfig
from containmentci.providers.base import (
    AccessResponse,
    ContainmentProvider,
    ProviderRegistry,
    ProviderResponse,
)


def test_engine_proves_revocation_and_detects_persistence() -> None:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "test",
            "identity": "synthetic@example.com",
            "timeout_seconds": 0.05,
            "poll_interval_seconds": 0.005,
            "targets": [
                {"name": "revoked", "resource": "test://revoked"},
                {
                    "name": "persistent",
                    "resource": "test://persistent",
                    "containment_supported": False,
                },
            ],
        }
    )

    run = asyncio.run(ExecutionEngine().run(scenario))

    assert run.status == RunStatus.FAIL
    assert run.checks[0].status == CheckStatus.PASS
    assert run.checks[1].status == CheckStatus.FAIL
    assert run.coverage_percent == 50
    assert verify_run(run)


def test_baseline_failure_is_an_error() -> None:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "test",
            "identity": "synthetic@example.com",
            "targets": [
                {
                    "name": "bad-fixture",
                    "resource": "test://bad",
                    "baseline_accessible": False,
                }
            ],
        }
    )
    run = asyncio.run(ExecutionEngine().run(scenario))
    assert run.checks[0].status == CheckStatus.ERROR
    assert run.status == RunStatus.ERROR


class BrokenControlProvider(ContainmentProvider):
    def __init__(self) -> None:
        self.contained = False

    def has_control_probe(self, target) -> bool:
        return True

    async def verify_access(self, identity, target) -> AccessResponse:
        return AccessResponse(
            state=AccessState.DENIED if self.contained else AccessState.ALLOWED,
            message="subject decision",
        )

    async def verify_control_access(self, identity, target) -> AccessResponse:
        return AccessResponse(
            state=AccessState.DENIED if self.contained else AccessState.ALLOWED,
            message="control decision",
        )

    async def contain(self, identity, target) -> ProviderResponse:
        self.contained = True
        return ProviderResponse(success=True, message="accepted")


def test_control_outage_can_never_be_a_false_pass(monkeypatch) -> None:
    monkeypatch.setenv(
        "CONTAINMENTCI_SIGNING_KEY", "test-control-signing-key-with-at-least-32-bytes"
    )
    provider = BrokenControlProvider()
    registry = ProviderRegistry()
    registry.register("broken-control", lambda: provider)
    scenario = ScenarioConfig.model_validate(
        {
            "name": "causal-proof",
            "identity": "synthetic@example.com",
            "timeout_seconds": 0.02,
            "poll_interval_seconds": 0.002,
            "targets": [
                {
                    "name": "subject-and-control",
                    "provider": "broken-control",
                    "resource": "test://causal",
                    "control_required": True,
                    "denial_confirmation_attempts": 1,
                }
            ],
        }
    )

    run = asyncio.run(ExecutionEngine(registry=registry, allow_live=True).run(scenario))

    assert run.status == RunStatus.FAIL
    assert run.checks[0].status == CheckStatus.FAIL
    assert not run.checks[0].access_revoked
    assert run.checks[0].indeterminate_attempts > 0


def test_simulation_records_causal_proof_and_containment_slo() -> None:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "causal-proof",
            "identity": "synthetic@example.com",
            "timeout_seconds": 0.1,
            "poll_interval_seconds": 0.002,
            "targets": [
                {
                    "name": "fast-revocation",
                    "resource": "test://causal",
                    "control_required": True,
                    "max_containment_seconds": 0.05,
                    "denial_confirmation_attempts": 2,
                }
            ],
        }
    )

    run = asyncio.run(ExecutionEngine().run(scenario))
    check = run.checks[0]

    assert run.status == RunStatus.PASS
    assert check.proof_mode == "subject-and-control"
    assert check.control_accessible is True
    assert check.denial_confirmations == 2
    assert check.first_denial_seconds is not None
    assert check.proof_seconds is not None
    assert check.first_denial_seconds <= check.proof_seconds
    assert check.proof_seconds <= check.containment_slo_seconds
    event_kinds = [event.kind for event in run.events]
    assert event_kinds.index("access.control_baseline") < event_kinds.index("containment.requested")


def test_provider_responses_reject_invalid_runtime_types() -> None:
    with pytest.raises(ValueError, match="AccessState"):
        AccessResponse(state="provider-error", message="invalid")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="boolean"):
        ProviderResponse(success="yes", message="invalid")  # type: ignore[arg-type]


class ConflictingEvidenceProvider(ContainmentProvider):
    requires_live_approval = False

    def __init__(self) -> None:
        self.contained = False

    async def verify_access(self, identity, target) -> AccessResponse:
        state = AccessState.DENIED if self.contained else AccessState.ALLOWED
        return AccessResponse(
            state=state,
            message="decision",
            evidence={"state": "forged", "attempt": 999},
        )

    async def contain(self, identity, target) -> ProviderResponse:
        self.contained = True
        return ProviderResponse(
            success=True,
            message="accepted",
            evidence={"accepted": False},
        )


def test_provider_evidence_cannot_override_authoritative_event_fields() -> None:
    registry = ProviderRegistry()
    registry.register("simulation", ConflictingEvidenceProvider)
    scenario = ScenarioConfig.model_validate(
        {
            "name": "reserved-evidence",
            "identity": "synthetic@example.com",
            "targets": [
                {
                    "name": "token",
                    "resource": "test://token",
                    "denial_confirmation_attempts": 1,
                }
            ],
        }
    )

    run = asyncio.run(ExecutionEngine(registry=registry).run(scenario))
    baseline = next(event for event in run.events if event.kind == "access.baseline")
    containment = next(event for event in run.events if event.kind == "containment.requested")
    probe = next(event for event in run.events if event.kind == "access.probe")

    assert baseline.data["state"] == AccessState.ALLOWED
    assert containment.data["accepted"] is True
    assert probe.data["state"] == AccessState.DENIED
    assert probe.data["attempt"] == 1


def test_preflight_rejects_multiple_live_targets_per_scenario() -> None:
    registry = ProviderRegistry()
    registry.register("live-test", BrokenControlProvider)
    scenario = ScenarioConfig.model_validate(
        {
            "name": "cross-credit-risk",
            "identity": "synthetic@example.com",
            "targets": [
                {
                    "name": "first-control",
                    "provider": "live-test",
                    "resource": "test://first",
                },
                {
                    "name": "second-control",
                    "provider": "live-test",
                    "resource": "test://second",
                },
            ],
        }
    )

    problems = ExecutionEngine(registry=registry, allow_live=True).preflight(scenario)

    assert any("exactly one state-changing target" in problem for problem in problems)


def test_evidence_verification_rejects_a_rehashed_broken_event_chain() -> None:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "evidence-chain",
            "identity": "synthetic@example.com",
            "targets": [{"name": "target", "resource": "test://evidence"}],
        }
    )
    run = asyncio.run(ExecutionEngine().run(scenario))
    run.events[1].previous_hash = "tampered"
    run.signature = sign_run(run)

    assert not verify_run(run)


def test_scenario_typos_fail_closed() -> None:
    with pytest.raises(ValidationError, match="control_requred"):
        ScenarioConfig.model_validate(
            {
                "name": "typo",
                "identity": "synthetic@example.com",
                "targets": [
                    {
                        "name": "token",
                        "resource": "test://token",
                        "control_requred": True,
                    }
                ],
            }
        )


def test_scenario_rejects_blank_live_fixture_identifiers() -> None:
    with pytest.raises(ValidationError, match="must not be empty or whitespace"):
        ScenarioConfig.model_validate(
            {
                "name": "blank-fixture",
                "identity": "   ",
                "targets": [{"name": "token", "resource": "   "}],
            }
        )


class HangingProvider(ContainmentProvider):
    requires_live_approval = False

    async def verify_access(self, identity, target) -> AccessResponse:
        await asyncio.sleep(1)
        return AccessResponse(state=AccessState.ALLOWED, message="late")

    async def contain(self, identity, target) -> ProviderResponse:
        return ProviderResponse(success=True, message="accepted")


def test_provider_calls_are_bounded_by_request_timeout() -> None:
    registry = ProviderRegistry()
    registry.register("simulation", HangingProvider)
    scenario = ScenarioConfig.model_validate(
        {
            "name": "bounded-provider",
            "identity": "synthetic@example.com",
            "provider_timeout_seconds": 0.01,
            "targets": [{"name": "hung", "resource": "test://hung"}],
        }
    )

    started = time.monotonic()
    run = asyncio.run(ExecutionEngine(registry=registry).run(scenario))

    assert time.monotonic() - started < 0.2
    assert run.status == RunStatus.ERROR
    assert run.checks[0].status == CheckStatus.ERROR
    assert "TimeoutError" in run.checks[0].message


class SequencedDenialProvider(ContainmentProvider):
    requires_live_approval = False

    def __init__(self) -> None:
        self.contained = False
        self.samples = iter(
            [AccessState.DENIED, AccessState.ALLOWED, AccessState.DENIED, AccessState.DENIED]
        )

    async def verify_access(self, identity, target) -> AccessResponse:
        if not self.contained:
            return AccessResponse(state=AccessState.ALLOWED, message="baseline")
        await asyncio.sleep(0.008)
        return AccessResponse(state=next(self.samples), message="sample")

    async def contain(self, identity, target) -> ProviderResponse:
        self.contained = True
        return ProviderResponse(success=True, message="accepted")


def test_first_denial_is_from_the_final_confirmed_sequence() -> None:
    provider = SequencedDenialProvider()
    registry = ProviderRegistry()
    registry.register("simulation", lambda: provider)
    scenario = ScenarioConfig.model_validate(
        {
            "name": "confirmed-sequence",
            "identity": "synthetic@example.com",
            "timeout_seconds": 0.2,
            "poll_interval_seconds": 0.002,
            "targets": [
                {
                    "name": "token",
                    "resource": "test://token",
                    "denial_confirmation_attempts": 2,
                }
            ],
        }
    )

    check = asyncio.run(ExecutionEngine(registry=registry).run(scenario)).checks[0]

    assert check.status == CheckStatus.PASS
    assert check.first_denial_seconds is not None
    assert check.first_denial_seconds >= 0.025
    assert check.proof_seconds is not None
    assert check.first_denial_seconds < check.proof_seconds
