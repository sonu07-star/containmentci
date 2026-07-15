from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from uuid import uuid4


class FixtureLeaseConflict(RuntimeError):
    """Raised when another live run already owns the identity or resource fixture."""


class FixtureLease:
    """Cross-process lease for a live synthetic identity and its resources.

    SQLite makes acquisition atomic for processes sharing the same state directory. CI systems
    running on separate machines must additionally use their platform's concurrency controls.
    """

    def __init__(
        self,
        identity: str,
        resources: set[str],
        *,
        ttl_seconds: float,
        path: Path | None = None,
    ) -> None:
        configured_path = os.getenv("CONTAINMENTCI_LEASE_DB", ".containmentci/leases.db")
        self.path = path or Path(configured_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.identity = identity.strip().casefold()
        self.resources = {resource.strip().casefold() for resource in resources}
        self.ttl_seconds = ttl_seconds
        self.lease_id = str(uuid4())
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fixture_leases (
                    lease_id TEXT PRIMARY KEY,
                    identity TEXT UNIQUE NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(fixture_leases)")}
            if "expires_at" not in columns:
                connection.execute("ALTER TABLE fixture_leases ADD COLUMN expires_at REAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fixture_resources (
                    resource TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    FOREIGN KEY (lease_id) REFERENCES fixture_leases(lease_id)
                        ON DELETE CASCADE
                )
                """
            )

    def _acquire(self) -> None:
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                now = time.time()
                connection.execute(
                    "DELETE FROM fixture_leases WHERE expires_at IS NULL OR expires_at < ?",
                    (now,),
                )
                identity_conflict = connection.execute(
                    "SELECT 1 FROM fixture_leases WHERE identity = ?", (self.identity,)
                ).fetchone()
                resource_conflict = None
                if self.resources:
                    placeholders = ",".join("?" for _ in self.resources)
                    resource_conflict = connection.execute(
                        f"SELECT resource FROM fixture_resources "
                        f"WHERE resource IN ({placeholders}) LIMIT 1",
                        tuple(sorted(self.resources)),
                    ).fetchone()
                if identity_conflict or resource_conflict:
                    connection.execute("ROLLBACK")
                    overlap = (
                        f"resource '{resource_conflict[0]}'"
                        if resource_conflict
                        else f"identity '{self.identity}'"
                    )
                    raise FixtureLeaseConflict(
                        f"Another live containment run already owns {overlap}. "
                        "Wait for it to finish; do not run shared fixtures concurrently."
                    )
                connection.execute(
                    """
                    INSERT INTO fixture_leases (lease_id, identity, acquired_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (self.lease_id, self.identity, now, now + self.ttl_seconds),
                )
                connection.executemany(
                    "INSERT INTO fixture_resources (resource, lease_id) VALUES (?, ?)",
                    ((resource, self.lease_id) for resource in sorted(self.resources)),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise FixtureLeaseConflict(
                    "Another live containment run acquired this identity or resource. "
                    "Wait for it to finish; do not run shared fixtures concurrently."
                ) from exc

    def _release(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM fixture_leases WHERE lease_id = ?", (self.lease_id,))

    def _renew(self, stop: threading.Event) -> None:
        interval = max(0.01, min(30.0, self.ttl_seconds / 3))
        while not stop.wait(interval):
            now = time.time()
            try:
                with self._connect() as connection:
                    connection.execute(
                        """
                        UPDATE fixture_leases
                        SET acquired_at = ?, expires_at = ?
                        WHERE lease_id = ?
                        """,
                        (now, now + self.ttl_seconds, self.lease_id),
                    )
            except sqlite3.Error:
                # A transient lock is safe: the existing expiry still provides multiple
                # renewal intervals before another process may reclaim the lease.
                continue

    @contextmanager
    def hold(self) -> Iterator[None]:
        self._acquire()
        stop = threading.Event()
        heartbeat = threading.Thread(target=self._renew, args=(stop,), daemon=True)
        heartbeat.start()
        try:
            yield
        finally:
            stop.set()
            heartbeat.join(timeout=min(5, self.ttl_seconds))
            self._release()
