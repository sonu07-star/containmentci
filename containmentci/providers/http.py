from __future__ import annotations

import os
from typing import Any

import httpx

from containmentci.models import TargetConfig
from containmentci.providers.base import ContainmentProvider, ProviderResponse


class HttpProvider(ContainmentProvider):
    """Integrates any containment control and access probe exposed over HTTP.

    Secrets are referenced by environment-variable name and never embedded in a
    scenario. The provider intentionally returns bounded evidence without response
    bodies, which may contain sensitive data.
    """

    def validate(self, identity: str, target: TargetConfig) -> list[str]:
        problems: list[str] = []
        for key in ("probe_url", "containment_url"):
            try:
                self._url(target, key)
            except ValueError as exc:
                problems.append(f"{target.name}: {exc}")
        for env_name in target.metadata.get("headers_from_env", {}).values():
            if not os.getenv(str(env_name)):
                problems.append(f"{target.name}: environment variable {env_name} is not set")
        return problems

    def _headers(self, metadata: dict[str, Any]) -> dict[str, str]:
        headers = {"User-Agent": "ContainmentCI/0.1"}
        for header, env_name in metadata.get("headers_from_env", {}).items():
            value = os.getenv(str(env_name))
            if not value:
                raise ValueError(f"Required environment variable '{env_name}' is not set")
            headers[str(header)] = value
        return headers

    def _url(self, target: TargetConfig, key: str) -> str:
        value = target.metadata.get(key)
        if not value or not str(value).startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError(f"{key} must use HTTPS, localhost, or 127.0.0.1")
        return str(value)

    async def verify_access(self, identity: str, target: TargetConfig) -> ProviderResponse:
        metadata = target.metadata
        url = self._url(target, "probe_url")
        method = str(metadata.get("probe_method", "GET")).upper()
        expected_status = int(metadata.get("accessible_status", 200))
        timeout = float(metadata.get("request_timeout_seconds", 10))
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.request(method, url, headers=self._headers(metadata))
        accessible = response.status_code == expected_status
        return ProviderResponse(
            success=accessible,
            message="HTTP access succeeded" if accessible else "HTTP access denied",
            evidence={
                "identity": identity,
                "resource": target.resource,
                "probe_url": url,
                "status_code": response.status_code,
                "expected_access_status": expected_status,
            },
        )

    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        metadata = target.metadata
        url = self._url(target, "containment_url")
        method = str(metadata.get("containment_method", "POST")).upper()
        expected_statuses = {
            int(status) for status in metadata.get("containment_success_statuses", [200, 202, 204])
        }
        timeout = float(metadata.get("request_timeout_seconds", 10))
        payload = {"identity": identity, "resource": target.resource}
        payload.update(metadata.get("containment_payload", {}))
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.request(
                method,
                url,
                headers=self._headers(metadata),
                json=payload,
            )
        accepted = response.status_code in expected_statuses
        return ProviderResponse(
            success=accepted,
            message="HTTP containment request accepted" if accepted else "HTTP containment failed",
            evidence={
                "identity": identity,
                "resource": target.resource,
                "containment_url": url,
                "status_code": response.status_code,
            },
        )
