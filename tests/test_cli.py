from pathlib import Path
from xml.etree import ElementTree

from typer.testing import CliRunner

from containmentci import __version__
from containmentci.cli import app
from containmentci.evidence import verify_run
from containmentci.models import RunResult


runner = CliRunner()


def test_cli_reports_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"ContainmentCI {__version__}"


def test_demo_is_an_all_pass_first_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = tmp_path / "demo.html"
    junit = tmp_path / "demo-junit.xml"
    evidence = tmp_path / "demo-evidence.json"
    monkeypatch.setenv("CONTAINMENTCI_SIGNING_KEY", "test-only-signing-key-with-at-least-32-bytes")

    result = runner.invoke(
        app,
        [
            "demo",
            "--report",
            str(report),
            "--junit",
            str(junit),
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 0
    assert "Containment coverage: 100.0%" in result.stdout
    assert "control access stayed healthy" in result.stdout
    assert "Evidence mode: configured-hmac" in result.stdout
    assert "ContainmentCI Summary Report" in report.read_text(encoding="utf-8")
    assert ElementTree.parse(junit).getroot().attrib["failures"] == "0"
    signed_run = RunResult.model_validate_json(evidence.read_text(encoding="utf-8"))
    assert signed_run.signature
    assert verify_run(signed_run)


def test_run_writes_signed_json_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CONTAINMENTCI_SIGNING_KEY", "test-only-signing-key-with-at-least-32-bytes")
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        """\
name: cli-run
identity: synthetic-cli@containmentci.local
timeout_seconds: 1
poll_interval_seconds: 0.025
targets:
  - name: Synthetic token
    provider: simulation
    resource: cli://token
    containment_delay_seconds: 0.025
    max_containment_seconds: 0.4
    control_required: true
""",
        encoding="utf-8",
    )
    evidence = tmp_path / "run-evidence.json"

    result = runner.invoke(app, ["run", str(scenario), "--evidence", str(evidence)])

    assert result.exit_code == 0
    signed_run = RunResult.model_validate_json(evidence.read_text(encoding="utf-8"))
    assert signed_run.scenario == "cli-run"
    assert verify_run(signed_run)
