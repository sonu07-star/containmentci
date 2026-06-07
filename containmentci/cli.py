from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
import uvicorn

from containmentci.config import load_scenario
from containmentci.engine import ExecutionEngine
from containmentci.evidence import verify_run
from containmentci.models import RunResult, RunStatus
from containmentci.reporting import render_terminal, write_html_report
from containmentci.store import RunStore

app = typer.Typer(help="Continuously prove that identity containment controls actually work.")


@app.command()
def run(
    scenario: Path = typer.Argument(..., exists=True, readable=True),
    report: Path | None = typer.Option(None, help="Write a standalone HTML evidence report."),
    json_output: bool = typer.Option(False, "--json", help="Print JSON instead of a table."),
    approve_live: bool = typer.Option(
        False,
        "--approve-live",
        help="Authorize state-changing execution against non-simulation providers.",
    ),
) -> None:
    """Execute a containment scenario."""
    loaded = load_scenario(scenario)
    engine = ExecutionEngine(allow_live=approve_live)
    problems = engine.preflight(loaded)
    if problems:
        for problem in problems:
            typer.echo(f"ERROR: {problem}", err=True)
        raise typer.Exit(code=2)
    result = asyncio.run(engine.run(loaded))
    RunStore().save(result)
    if report:
        write_html_report(result, report)
    typer.echo(result.model_dump_json(indent=2) if json_output else render_terminal(result))
    if result.status != RunStatus.PASS:
        raise typer.Exit(code=1)


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
    """Verify the HMAC signature of an exported JSON evidence bundle."""
    result = RunResult.model_validate_json(evidence_file.read_text(encoding="utf-8"))
    if not verify_run(result):
        typer.echo("Evidence signature is invalid.")
        raise typer.Exit(code=1)
    typer.echo(f"Evidence signature is valid for run {result.id}.")


@app.command()
def export(run_id: str, output: Path) -> None:
    """Export a stored run as a signed JSON evidence bundle."""
    result = RunStore().get(run_id)
    if not result:
        raise typer.BadParameter(f"Run {run_id} was not found")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
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
