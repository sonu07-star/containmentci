from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import uvicorn

from containmentci import __version__
from containmentci.config import load_scenario
from containmentci.engine import ExecutionEngine
from containmentci.evidence import signing_key_is_configured, verify_run
from containmentci.lease import FixtureLeaseConflict
from containmentci.models import RunResult, RunStatus, ScenarioConfig
from containmentci.reporting import (
    render_terminal,
    write_html_report,
    write_json_evidence,
    write_junit_report,
)
from containmentci.store import RunStore

app = typer.Typer(help="Prove identity containment controls revoke real access within an SLO.")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"ContainmentCI {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
) -> None:
    """Prove identity containment outcomes instead of trusting revoke responses."""


def _execute(
    loaded: ScenarioConfig,
    *,
    report: Path | None,
    junit: Path | None,
    evidence: Path | None,
    json_output: bool,
    approve_live: bool,
) -> None:
    if approve_live and not signing_key_is_configured():
        typer.echo(
            "ERROR: live runs require a non-default CONTAINMENTCI_SIGNING_KEY",
            err=True,
        )
        raise typer.Exit(code=2)
    engine = ExecutionEngine(allow_live=approve_live)
    problems = engine.preflight(loaded)
    if problems:
        for problem in problems:
            typer.echo(f"ERROR: {problem}", err=True)
        raise typer.Exit(code=2)
    try:
        result = asyncio.run(engine.run(loaded))
    except FixtureLeaseConflict as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    RunStore().save(result)
    if report:
        write_html_report(result, report)
    if junit:
        write_junit_report(result, junit)
    if evidence:
        write_json_evidence(result, evidence)
    typer.echo(result.model_dump_json(indent=2) if json_output else render_terminal(result))
    if result.status != RunStatus.PASS:
        raise typer.Exit(code=1)


@app.command()
def run(
    scenario: Path = typer.Argument(..., exists=True, readable=True),
    report: Path | None = typer.Option(None, help="Write an HTML summary report."),
    junit: Path | None = typer.Option(None, help="Write a JUnit XML report for CI systems."),
    evidence: Path | None = typer.Option(
        None, help="Write the signed run and event chain as JSON evidence."
    ),
    json_output: bool = typer.Option(False, "--json", help="Print JSON instead of a table."),
    approve_live: bool = typer.Option(
        False,
        "--approve-live",
        help="Authorize state-changing execution against non-simulation providers.",
    ),
) -> None:
    """Execute a containment scenario."""
    _execute(
        load_scenario(scenario),
        report=report,
        junit=junit,
        evidence=evidence,
        json_output=json_output,
        approve_live=approve_live,
    )


@app.command()
def demo(
    report: Path | None = typer.Option(None, help="Write an HTML summary report."),
    junit: Path | None = typer.Option(None, help="Write a JUnit XML report for CI systems."),
    evidence: Path | None = typer.Option(
        None, help="Write the signed run and event chain as JSON evidence."
    ),
) -> None:
    """Run a safe, all-pass controlled containment proof in under a second."""
    scenario = ScenarioConfig.model_validate(
        {
            "name": "controlled-containment-demo",
            "description": "Safe local proof with an untouched control witness.",
            "identity": "synthetic-demo@containmentci.local",
            "timeout_seconds": 1,
            "poll_interval_seconds": 0.025,
            "targets": [
                {
                    "name": "Revoked API token",
                    "resource": "demo://api/token",
                    "containment_delay_seconds": 0.05,
                    "max_containment_seconds": 0.25,
                    "control_required": True,
                },
                {
                    "name": "Terminated web session",
                    "resource": "demo://app/session",
                    "containment_delay_seconds": 0.1,
                    "max_containment_seconds": 0.4,
                    "control_required": True,
                },
            ],
        }
    )
    _execute(
        scenario,
        report=report,
        junit=junit,
        evidence=evidence,
        json_output=False,
        approve_live=False,
    )


@app.command()
def check(scenario: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Validate a scenario and required environment variables without making requests."""
    loaded = load_scenario(scenario)
    engine = ExecutionEngine()
    problems = engine.preflight(loaded)
    if problems:
        for problem in problems:
            typer.echo(f"ERROR: {problem}")
        raise typer.Exit(code=2)
    providers = ", ".join(sorted({target.provider for target in loaded.targets}))
    typer.echo(f"Scenario '{loaded.name}' is valid. Providers: {providers}")


@app.command()
def verify(evidence_file: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Verify the HMAC signature and event chain of an exported evidence bundle."""
    result = RunResult.model_validate_json(evidence_file.read_text(encoding="utf-8"))
    if result.evidence_key_mode == "development-hmac":
        typer.echo(
            "WARNING: this bundle uses the public development HMAC key and is not "
            "trustworthy evidence.",
            err=True,
        )
    if not verify_run(result):
        typer.echo("Evidence signature or event chain is invalid.")
        raise typer.Exit(code=1)
    typer.echo(f"Evidence integrity is valid for run {result.id}.")


@app.command()
def export(run_id: str, output: Path) -> None:
    """Export a stored run as a signed JSON evidence bundle."""
    result = RunStore().get(run_id)
    if not result:
        raise typer.BadParameter(f"Run {run_id} was not found")
    write_json_evidence(result, output)
    typer.echo(f"Exported {run_id} to {output}")


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    """Start the dashboard and API."""
    uvicorn.run("containmentci.api:app", host=host, port=port)


if __name__ == "__main__":
    app()
