import asyncio

from containmentci.engine import ExecutionEngine
from containmentci.models import CheckStatus, ScenarioConfig


def test_live_provider_requires_explicit_approval() -> None:
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
                        "probe_url": "https://example.com/probe",
                        "containment_url": "https://example.com/contain",
                    },
                }
            ],
        }
    )
    run = asyncio.run(ExecutionEngine().run(scenario))
    assert run.checks[0].status == CheckStatus.ERROR
    assert "--approve-live" in run.checks[0].message
