from __future__ import annotations

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
        return RunResult.model_validate_json(row["payload"]) if row else None

    def list(self, limit: int = 50) -> list[RunResult]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [RunResult.model_validate_json(row["payload"]) for row in rows]

