from __future__ import annotations

import time

from containmentci.models import AccessState, TargetConfig
from containmentci.providers.base import AccessResponse, ContainmentProvider, ProviderResponse


class SimulationProvider(ContainmentProvider):
    """Deterministic provider used for demos, development, and CI."""

    requires_live_approval = False

    def __init__(self) -> None:
        self._requested_at: dict[str, float] = {}

    def _key(self, identity: str, target: TargetConfig) -> str:
        return f"{identity}:{target.name}:{target.resource}"

    async def verify_access(self, identity: str, target: TargetConfig) -> AccessResponse:
        key = self._key(identity, target)
        requested_at = self._requested_at.get(key)
        accessible = target.baseline_accessible
        if requested_at is not None and target.containment_supported:
            accessible = (time.monotonic() - requested_at) < target.containment_delay_seconds

        return AccessResponse(
            state=AccessState.ALLOWED if accessible else AccessState.DENIED,
            message="Synthetic access succeeded" if accessible else "Synthetic access denied",
            evidence={
                "identity": identity,
                "resource": target.resource,
                "access_result": "allowed" if accessible else "denied",
            },
        )

    def has_control_probe(self, target: TargetConfig) -> bool:
        return True

    async def verify_control_access(self, identity: str, target: TargetConfig) -> AccessResponse:
        return AccessResponse(
            state=AccessState.ALLOWED,
            message="Synthetic control access succeeded",
            evidence={
                "identity": "untouched-control",
                "resource": target.resource,
                "access_result": "allowed",
            },
        )

    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        self._requested_at[self._key(identity, target)] = time.monotonic()
        return ProviderResponse(
            success=True,
            message="Synthetic containment request accepted",
            evidence={
                "identity": identity,
                "resource": target.resource,
                "provider_acknowledged": True,
                "containment_supported": target.containment_supported,
            },
        )
