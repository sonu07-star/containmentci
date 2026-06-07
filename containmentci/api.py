from __future__ import annotations

import asyncio
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from containmentci.config import load_scenario
from containmentci.engine import ExecutionEngine
from containmentci.models import RunResult
from containmentci.reporting import render_html
from containmentci.store import RunStore

app = FastAPI(title="ContainmentCI", version="0.2.0")
store = RunStore()


def scenario_root() -> Path:
    return Path(os.getenv("CONTAINMENTCI_SCENARIO_ROOT", "examples")).resolve()


def resolve_scenario(name: str) -> Path:
    root = scenario_root()
    path = (root / name).resolve()
    if root not in path.parents or not path.is_file():
        raise HTTPException(status_code=400, detail="Scenario file not found in scenario root")
    return path


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/runs", response_model=list[RunResult])
def list_runs() -> list[RunResult]:
    return store.list()


@app.get("/api/runs/{run_id}", response_model=RunResult)
def get_run(run_id: str) -> RunResult:
    run = store.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@app.post("/api/runs", response_model=RunResult)
def create_run(scenario: str = "compromised-user.yaml") -> RunResult:
    allow_live = os.getenv("CONTAINMENTCI_API_ALLOW_LIVE", "").lower() == "true"
    run = asyncio.run(
        ExecutionEngine(allow_live=allow_live).run(load_scenario(resolve_scenario(scenario)))
    )
    store.save(run)
    return run


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_report(run_id: str) -> str:
    run = store.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return render_html(run)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    runs = store.list()
    rows = "".join(
        f'<li><a href="/runs/{run.id}">{run.scenario}</a> — {run.status.upper()} '
        f"({run.coverage_percent}%)</li>"
        for run in runs
    )
    return f"""<!doctype html><html><head><title>ContainmentCI</title>
    <style>body{{font:16px system-ui;max-width:900px;margin:50px auto;padding:20px}}
    li{{padding:10px 0}}</style></head><body>
    <h1>ContainmentCI</h1><p>Continuously prove that your kill switches actually work.</p>
    <h2>Recent runs</h2><ul>{rows or '<li>No runs yet.</li>'}</ul>
    <p><a href="/docs">API documentation</a></p></body></html>"""
