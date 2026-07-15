from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from containmentci.models import RunResult


class RunStore:
    def __init__(self, path: Path = Path(".containmentci/runs.db")) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    scenario TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    payload TEXT NOT NULL
                )
                """
            )

    def save(self, run: RunResult) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO runs
                (id, scenario, identity, status, started_at, finished_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.scenario,
                    run.identity,
                    run.status,
                    run.started_at.isoformat(),
                    run.finished_at.isoformat() if run.finished_at else None,
                    run.model_dump_json(),
                ),
            )

    def get(self, run_id: str) -> RunResult | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._load_run(row["payload"]) if row else None

    def list(self, limit: int = 50) -> list[RunResult]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._load_run(row["payload"]) for row in rows]

    def _load_run(self, payload: str) -> RunResult:
        """Load stored runs while migrating only known pre-0.3 fields.

        External evidence verification stays strict. Compatibility is intentionally scoped to
        the local database so upgrades do not destroy a user's historical run records.
        """
        raw = json.loads(payload)
        raw.setdefault("evidence_key_mode", "development-hmac")
        for check in raw.get("checks", []):
            legacy_seconds = check.pop("containment_seconds", None)
            if "proof_seconds" not in check:
                check["proof_seconds"] = legacy_seconds
            check.setdefault("first_denial_seconds", None)
        return RunResult.model_validate(raw)
