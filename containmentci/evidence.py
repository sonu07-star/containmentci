from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from containmentci.models import Event, RunResult


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def append_event(
    events: list[Event], kind: str, target: str | None = None, data: dict[str, Any] | None = None
) -> Event:
    previous_hash = events[-1].hash if events else ""
    event = Event(
        sequence=len(events) + 1,
        kind=kind,
        target=target,
        data=data or {},
        previous_hash=previous_hash,
    )
    payload = event.model_dump(mode="json", exclude={"hash"})
    event.hash = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    events.append(event)
    return event


def sign_run(run: RunResult, key: str | None = None) -> str:
    signing_key = (key or os.getenv("CONTAINMENTCI_SIGNING_KEY", "development-key")).encode()
    payload = run.model_dump(mode="json", exclude={"signature"})
    return hmac.new(signing_key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()


def verify_run(run: RunResult, key: str | None = None) -> bool:
    return hmac.compare_digest(run.signature, sign_run(run, key))

