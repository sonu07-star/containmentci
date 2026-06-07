from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from containmentci.models import TargetConfig


@dataclass
class ProviderResponse:
    success: bool
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


class ContainmentProvider(ABC):
    """Provider contract.

    A provider must test access using the same credential/session before and after
    containment. Merely checking whether a revoke API returned 200 is insufficient.
    """

    def validate(self, identity: str, target: TargetConfig) -> list[str]:
        """Return configuration problems without making network requests."""
        return []

    @abstractmethod
    async def verify_access(self, identity: str, target: TargetConfig) -> ProviderResponse:
        raise NotImplementedError

    @abstractmethod
    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        raise NotImplementedError


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
