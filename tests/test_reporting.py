import asyncio
from xml.etree import ElementTree

from containmentci.engine import ExecutionEngine
from containmentci.evidence import verify_run
from containmentci.models import CheckResult, CheckStatus, RunResult, RunStatus, ScenarioConfig
from containmentci.reporting import render_junit, write_json_evidence


def test_junit_report_exposes_ci_failures_and_slo_metadata() -> None:
    run = RunResult(
        scenario="ci-gate",
        identity="synthetic@example.com",
        status=RunStatus.FAIL,
        checks=[
            CheckResult(
                target="stale-session",
                provider="simulation",
                resource="test://session",
                status=CheckStatus.FAIL,
                containment_slo_seconds=1,
                message="Access remained active",
            )
        ],
    )

    root = ElementTree.fromstring(render_junit(run))

    assert root.attrib["failures"] == "1"
    assert root.find("./testcase/failure") is not None
    output = root.findtext("./testcase/system-out") or ""
    assert "proof_seconds=None" in output
    assert "slo_seconds=1.0" in output


def test_json_evidence_round_trips_a_signed_run(tmp_path) -> None:
    scenario = ScenarioConfig.model_validate(
        {
            "name": "evidence",
            "identity": "synthetic@example.com",
            "targets": [{"name": "credential", "resource": "test://credential"}],
        }
    )
    run = asyncio.run(ExecutionEngine().run(scenario))
    evidence = tmp_path / "nested" / "evidence.json"

    write_json_evidence(run, evidence)

    restored = RunResult.model_validate_json(evidence.read_text(encoding="utf-8"))
    assert restored.signature == run.signature
    assert verify_run(restored)
