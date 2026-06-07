from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CheckStatus(StrEnum):
    PENDING = "pending"
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class RunStatus(StrEnum):
    RUNNING = "running"
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class TargetConfig(BaseModel):
    name: str
    provider: str = "simulation"
    resource: str
    containment_delay_seconds: float = Field(default=0, ge=0)
    containment_supported: bool = True
    baseline_accessible: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScenarioConfig(BaseModel):
    name: str
    description: str = ""
    identity: str
    timeout_seconds: float = Field(default=10, gt=0)
    poll_interval_seconds: float = Field(default=0.25, gt=0)
    targets: list[TargetConfig]


class CheckResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    provider: str
    resource: str
    status: CheckStatus = CheckStatus.PENDING
    baseline_access: bool | None = None
    containment_requested: bool = False
    access_revoked: bool = False
    elapsed_seconds: float = 0
    attempts: int = 0
    message: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class Event(BaseModel):
    sequence: int
    timestamp: datetime = Field(default_factory=utc_now)
    kind: str
    target: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    hash: str = ""


class RunResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    scenario: str
    identity: str
    status: RunStatus = RunStatus.RUNNING
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    checks: list[CheckResult] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    signature: str = ""

    @property
    def coverage_percent(self) -> float:
        if not self.checks:
            return 0
        passed = sum(check.status == CheckStatus.PASS for check in self.checks)
        return round((passed / len(self.checks)) * 100, 1)

