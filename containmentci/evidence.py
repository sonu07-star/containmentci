from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from containmentci.models import Event, RunResult


INSECURE_SIGNING_KEYS = {"", "development-key", "change-me"}
MIN_SIGNING_KEY_BYTES = 32


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
    if key is None:
        configured_key = os.getenv("CONTAINMENTCI_SIGNING_KEY", "")
        key = (
            configured_key if signing_key_value_is_configured(configured_key) else "development-key"
        )
    signing_key = key.encode()
    payload = run.model_dump(mode="json", exclude={"signature"})
    return hmac.new(signing_key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()


def signing_key_is_configured() -> bool:
    return signing_key_value_is_configured(os.getenv("CONTAINMENTCI_SIGNING_KEY", ""))


def signing_key_value_is_configured(key: str) -> bool:
    return key not in INSECURE_SIGNING_KEYS and len(key.encode("utf-8")) >= MIN_SIGNING_KEY_BYTES


def verify_event_chain(run: RunResult) -> bool:
    if (
        len(run.events) < 2
        or run.events[0].kind != "run.started"
        or run.events[-1].kind != "run.finished"
        or run.events[0].data.get("scenario") != run.scenario
        or run.events[-1].data.get("status") != run.status
        or run.finished_at is None
    ):
        return False
    previous_hash = ""
    for expected_sequence, event in enumerate(run.events, start=1):
        if event.sequence != expected_sequence or event.previous_hash != previous_hash:
            return False
        payload = event.model_dump(mode="json", exclude={"hash"})
        expected_hash = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        if not hmac.compare_digest(event.hash, expected_hash):
            return False
        previous_hash = event.hash
    return True


def verify_run(run: RunResult, key: str | None = None) -> bool:
    if run.evidence_key_mode == "configured-hmac":
        verification_key = key if key is not None else os.getenv("CONTAINMENTCI_SIGNING_KEY", "")
        if not signing_key_value_is_configured(verification_key):
            return False
    elif run.evidence_key_mode == "development-hmac":
        if key is not None and key != "development-key":
            return False
        verification_key = "development-key"
    else:
        return False
    return verify_event_chain(run) and hmac.compare_digest(
        run.signature, sign_run(run, verification_key)
    )
