from pathlib import Path

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from containmentci.models import CheckResult, RunResult
from containmentci.store import RunStore


def test_store_closes_connections(tmp_path, monkeypatch) -> None:
    connections = []
    original_connect = sqlite3.connect

    def tracked_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    store = RunStore(tmp_path / "runs.db")
    run = RunResult(scenario="demo", identity="synthetic@example.com")
    store.save(run)
    store.get(run.id)
    store.list()
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_store_lists_latest_runs_with_limit(tmp_path) -> None:
    store = RunStore(tmp_path / "runs.db")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for offset in (2, 0, 1):
        store.save(RunResult(
            scenario=f"run-{offset}",
            identity="synthetic@example.com",
            started_at=start + timedelta(seconds=offset),
        ))

    assert [run.scenario for run in store.list(limit=2)] == ["run-2", "run-1"]
    assert store.list(limit=0) == []


def test_store_round_trip(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs.db")
    run = RunResult(scenario="demo", identity="synthetic@example.com")
    store.save(run)
    restored = store.get(run.id)
    assert restored is not None
    assert restored.id == run.id


def test_store_migrates_legacy_containment_timing(tmp_path) -> None:
    path = tmp_path / "runs.db"
    store = RunStore(path)
    run = RunResult(
        scenario="legacy",
        identity="synthetic@example.com",
        checks=[
            CheckResult(
                target="token",
                provider="simulation",
                resource="test://token",
                proof_seconds=1.25,
            )
        ],
    )
    payload = run.model_dump(mode="json")
    payload.pop("evidence_key_mode")
    legacy_check = payload["checks"][0]
    legacy_check["containment_seconds"] = legacy_check.pop("proof_seconds")
    legacy_check.pop("first_denial_seconds")
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO runs (id, scenario, identity, status, started_at, finished_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.id,
                run.scenario,
                run.identity,
                run.status,
                run.started_at.isoformat(),
                None,
                json.dumps(payload),
            ),
        )

    restored = store.get(run.id)

    assert restored is not None
    assert restored.evidence_key_mode == "development-hmac"
    assert restored.checks[0].proof_seconds == 1.25
    assert restored.checks[0].first_denial_seconds is None
