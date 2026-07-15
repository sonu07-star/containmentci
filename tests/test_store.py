from pathlib import Path

import json
import sqlite3

from containmentci.models import CheckResult, RunResult
from containmentci.store import RunStore


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
