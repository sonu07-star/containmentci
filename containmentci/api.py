from __future__ import annotations

import asyncio
import html
import hmac
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from containmentci import __version__
from containmentci.config import load_scenario
from containmentci.engine import ExecutionEngine
from containmentci.evidence import signing_key_is_configured
from containmentci.lease import FixtureLeaseConflict
from containmentci.models import RunResult
from containmentci.reporting import render_html
from containmentci.store import RunStore

app = FastAPI(title="ContainmentCI", version=__version__)
store = RunStore()
_active_live_runs: set[tuple[str, frozenset[str]]] = set()
_live_run_guard = threading.Lock()
_MIN_API_TOKEN_BYTES = 32


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
def list_runs(authorization: str | None = Header(default=None)) -> list[RunResult]:
    _authorize_api_access(authorization)
    return store.list()


@app.get("/api/runs/{run_id}", response_model=RunResult)
def get_run(run_id: str, authorization: str | None = Header(default=None)) -> RunResult:
    _authorize_api_access(authorization)
    run = store.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@app.post("/api/runs", response_model=RunResult)
def create_run(
    scenario: str = "compromised-user.yaml",
    approve_live: bool = False,
    authorization: str | None = Header(default=None),
) -> RunResult:
    loaded = load_scenario(resolve_scenario(scenario))
    engine = ExecutionEngine(allow_live=False)
    registered = set(engine.registry.names)
    has_live_targets = any(
        target.provider in registered
        and engine.registry.create(target.provider).requires_live_approval
        for target in loaded.targets
    )
    if has_live_targets:
        _authorize_live_run(approve_live, authorization)
        engine = ExecutionEngine(allow_live=True)
    else:
        _authorize_api_access(authorization)

    problems = engine.preflight(loaded)
    if problems:
        raise HTTPException(
            status_code=422,
            detail={"message": "Scenario preflight failed", "problems": problems},
        )

    try:
        if has_live_targets:
            with _claim_live_fixture(
                loaded.identity,
                frozenset(target.resource for target in loaded.targets),
            ):
                run = asyncio.run(engine.run(loaded))
        else:
            run = asyncio.run(engine.run(loaded))
    except FixtureLeaseConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    store.save(run)
    return run


def _token_is_valid(authorization: str | None, expected_token: str) -> bool:
    scheme, separator, supplied_token = (authorization or "").partition(" ")
    return (
        bool(separator)
        and scheme.lower() == "bearer"
        and bool(supplied_token)
        and hmac.compare_digest(supplied_token.encode(), expected_token.encode())
    )


def _require_independent_signing_secret(api_token: str) -> None:
    signing_key = os.getenv("CONTAINMENTCI_SIGNING_KEY", "")
    if signing_key and hmac.compare_digest(api_token.encode(), signing_key.encode()):
        raise HTTPException(
            status_code=503,
            detail="API authentication and evidence signing must use independent secrets",
        )


def _authorize_api_access(authorization: str | None) -> None:
    expected_token = os.getenv("CONTAINMENTCI_API_TOKEN", "")
    if not expected_token:
        return
    if len(expected_token.encode("utf-8")) < _MIN_API_TOKEN_BYTES:
        raise HTTPException(
            status_code=503,
            detail="CONTAINMENTCI_API_TOKEN must contain at least 32 bytes",
        )
    if not _token_is_valid(authorization, expected_token):
        raise HTTPException(
            status_code=401,
            detail="A valid Bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _require_independent_signing_secret(expected_token)


def _authorize_live_run(approve_live: bool, authorization: str | None) -> None:
    if not approve_live:
        raise HTTPException(
            status_code=403,
            detail="Live scenarios require the explicit approve_live=true request flag",
        )
    if os.getenv("CONTAINMENTCI_API_ALLOW_LIVE", "").strip().lower() != "true":
        raise HTTPException(
            status_code=503,
            detail="Live API execution is disabled by server configuration",
        )

    expected_token = os.getenv("CONTAINMENTCI_API_TOKEN", "")
    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="Live API execution requires CONTAINMENTCI_API_TOKEN to be configured",
        )
    if len(expected_token.encode("utf-8")) < _MIN_API_TOKEN_BYTES:
        raise HTTPException(
            status_code=503,
            detail="CONTAINMENTCI_API_TOKEN must contain at least 32 bytes",
        )
    if not _token_is_valid(authorization, expected_token):
        raise HTTPException(
            status_code=403,
            detail="Live API execution requires a valid Bearer token",
        )
    _require_independent_signing_secret(expected_token)
    if not signing_key_is_configured():
        raise HTTPException(
            status_code=503,
            detail="Live API execution requires a non-default CONTAINMENTCI_SIGNING_KEY",
        )


@contextmanager
def _claim_live_fixture(identity: str, resources: frozenset[str]) -> Iterator[None]:
    normalized_identity = identity.strip().casefold()
    normalized_resources = frozenset(resource.strip().casefold() for resource in resources)
    claim = (normalized_identity, normalized_resources)
    with _live_run_guard:
        collision = any(
            active_identity == normalized_identity or bool(active_resources & normalized_resources)
            for active_identity, active_resources in _active_live_runs
        )
        if collision:
            raise HTTPException(
                status_code=409,
                detail="A live run already holds this synthetic identity or resource",
            )
        _active_live_runs.add(claim)
    try:
        yield
    finally:
        with _live_run_guard:
            _active_live_runs.discard(claim)


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_report(run_id: str, authorization: str | None = Header(default=None)) -> str:
    _authorize_api_access(authorization)
    run = store.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return render_html(run)


@app.get("/", response_class=HTMLResponse)
def dashboard(authorization: str | None = Header(default=None)) -> str:
    _authorize_api_access(authorization)
    runs = store.list()
    rows = "".join(
        f'<li><a href="/runs/{run.id}">{html.escape(run.scenario)}</a> — {run.status.upper()} '
        f"({run.coverage_percent}%)</li>"
        for run in runs
    )
    return f"""<!doctype html><html><head><title>ContainmentCI</title>
    <style>body{{font:16px system-ui;max-width:900px;margin:50px auto;padding:20px}}
    li{{padding:10px 0}}</style></head><body>
    <h1>ContainmentCI</h1><p>Prove access is gone, not just that revocation was accepted.</p>
    <h2>Recent runs</h2><ul>{rows or "<li>No runs yet.</li>"}</ul>
    <p><a href="/docs">API documentation</a></p></body></html>"""
