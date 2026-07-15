from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from containmentci.models import AccessState, TargetConfig


@dataclass
class AccessResponse:
    """Semantic result of replaying an access path.

    Providers must use ``INDETERMINATE`` for outages, throttling, unexpected
    redirects, and any response that is not an explicit authorization decision.
    """

    state: AccessState
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.state, AccessState):
            raise ValueError("Provider access state must be an AccessState value")
        if not isinstance(self.evidence, dict):
            raise ValueError("Provider access evidence must be a mapping")

    @property
    def success(self) -> bool:
        """Compatibility shorthand for callers that only need allowed/not-allowed."""
        return self.state == AccessState.ALLOWED


@dataclass
class ProviderResponse:
    success: bool
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise ValueError("Provider containment success must be a boolean")
        if not isinstance(self.evidence, dict):
            raise ValueError("Provider containment evidence must be a mapping")


class ContainmentProvider(ABC):
    """Provider contract.

    A provider must test access using the same credential/session before and after
    containment. Merely checking whether a revoke API returned 200 is insufficient.
    """

    requires_live_approval = True

    def validate(self, identity: str, target: TargetConfig) -> list[str]:
        """Return configuration problems without making network requests."""
        return []

    @abstractmethod
    async def verify_access(self, identity: str, target: TargetConfig) -> AccessResponse:
        raise NotImplementedError

    @abstractmethod
    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        raise NotImplementedError

    def has_control_probe(self, target: TargetConfig) -> bool:
        """Return whether this target has an independent healthy-access witness."""
        return False

    def control_proof_mode(self, target: TargetConfig) -> str:
        """Describe the strength of the configured witness in reports."""
        return "subject-and-control"

    async def verify_control_access(
        self, identity: str, target: TargetConfig
    ) -> AccessResponse | None:
        """Probe an untouched same-resource control or labeled availability witness."""
        return None


ProviderFactory = Callable[[], ContainmentProvider]


class ProviderRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}

    def register(self, name: str, factory: ProviderFactory) -> None:
        self._factories[name] = factory

    def create(self, name: str) -> ContainmentProvider:
        try:
            return self._factories[name]()
        except KeyError as exc:
            available = ", ".join(sorted(self._factories))
            raise ValueError(f"Unknown provider '{name}'. Available: {available}") from exc

    @property
    def names(self) -> list[str]:
        return sorted(self._factories)
