from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class AccessState(StrEnum):
    """A semantic access decision returned by a provider probe."""

    ALLOWED = "allowed"
    DENIED = "denied"
    INDETERMINATE = "indeterminate"


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    provider: str = "simulation"
    resource: str
    containment_delay_seconds: float = Field(default=0, ge=0)
    containment_supported: bool = True
    baseline_accessible: bool = True
    max_containment_seconds: float | None = Field(default=None, gt=0)
    denial_confirmation_attempts: int = Field(default=2, ge=1, le=10)
    control_required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name", "provider", "resource")
    @classmethod
    def require_nonblank_target_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be empty or whitespace")
        return normalized


class ScenarioConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    identity: str
    timeout_seconds: float = Field(default=10, gt=0)
    poll_interval_seconds: float = Field(default=0.25, gt=0)
    provider_timeout_seconds: float = Field(default=10, gt=0)
    targets: list[TargetConfig] = Field(min_length=1)

    @field_validator("name", "identity")
    @classmethod
    def require_nonblank_scenario_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be empty or whitespace")
        return normalized


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    provider: str
    resource: str
    status: CheckStatus = CheckStatus.PENDING
    baseline_access: bool | None = None
    containment_requested: bool = False
    access_revoked: bool = False
    elapsed_seconds: float = 0
    first_denial_seconds: float | None = None
    proof_seconds: float | None = None
    containment_slo_seconds: float = 0
    attempts: int = 0
    denial_confirmations: int = 0
    indeterminate_attempts: int = 0
    proof_mode: str = "subject-only"
    control_accessible: bool | None = None
    message: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int
    timestamp: datetime = Field(default_factory=utc_now)
    kind: str
    target: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    hash: str = ""


class RunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()))
    scenario: str
    identity: str
    status: RunStatus = RunStatus.RUNNING
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    checks: list[CheckResult] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    evidence_key_mode: str = "development-hmac"
    signature: str = ""

    @property
    def coverage_percent(self) -> float:
        if not self.checks:
            return 0
        passed = sum(check.status == CheckStatus.PASS for check in self.checks)
        return round((passed / len(self.checks)) * 100, 1)
