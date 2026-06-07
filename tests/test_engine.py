import asyncio

from containmentci.engine import ExecutionEngine
from containmentci.evidence import verify_run
from containmentci.models import CheckStatus, RunStatus, ScenarioConfig


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

