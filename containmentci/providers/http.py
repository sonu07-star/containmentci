from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from containmentci import __version__
from containmentci.models import AccessState, TargetConfig
from containmentci.providers.base import AccessResponse, ContainmentProvider, ProviderResponse


class HttpProvider(ContainmentProvider):
    """Integrates any containment control and access probe exposed over HTTP.

    Secrets are referenced by environment-variable name and never embedded in a
    scenario. The provider intentionally returns bounded evidence without response
    bodies, which may contain sensitive data.
    """

    _EXPLICIT_DENIAL_STATUSES = {401, 403, 404}

    def validate(self, identity: str, target: TargetConfig) -> list[str]:
        problems: list[str] = []
        if target.metadata.get("safety_acknowledgement") != "dedicated-synthetic-identity":
            problems.append(
                f"{target.name}: metadata.safety_acknowledgement must equal "
                "'dedicated-synthetic-identity'"
            )
        for key in ("probe_url", "containment_url"):
            try:
                self._url(target, key)
            except ValueError as exc:
                problems.append(f"{target.name}: {exc}")
        if target.metadata.get("control_probe_url"):
            try:
                self._url(target, "control_probe_url")
            except ValueError as exc:
                problems.append(f"{target.name}: {exc}")
        header_references: dict[str, dict[str, str]] = {}
        for header_group in (
            "headers_from_env",
            "control_headers_from_env",
            "containment_headers_from_env",
        ):
            try:
                header_references[header_group] = self._env_references(
                    target.metadata, header_group
                )
            except ValueError as exc:
                problems.append(f"{target.name}: {exc}")
                header_references[header_group] = {}
            for env_name in header_references[header_group].values():
                if not os.getenv(str(env_name)):
                    problems.append(f"{target.name}: environment variable {env_name} is not set")
        if not header_references["headers_from_env"]:
            problems.append(
                f"{target.name}: headers_from_env must contain the synthetic subject credential"
            )
        if not header_references["containment_headers_from_env"]:
            problems.append(
                f"{target.name}: containment_headers_from_env must contain an independent "
                "administrative credential"
            )
        if (
            target.metadata.get("control_probe_url")
            and not header_references["control_headers_from_env"]
        ):
            problems.append(f"{target.name}: control_probe_url requires control_headers_from_env")
        denied: set[int] = set()
        try:
            _, denied = self._access_statuses(target.metadata)
            self._containment_statuses(target.metadata)
            self._probe_method(target.metadata)
            self._probe_method(target.metadata, control=True)
            timeout = float(target.metadata.get("request_timeout_seconds", 10))
            if timeout <= 0:
                raise ValueError("request_timeout_seconds must be greater than zero")
        except (TypeError, ValueError) as exc:
            problems.append(f"{target.name}: {exc}")
        subject_envs = set(header_references["headers_from_env"].values())
        control_envs = set(header_references["control_headers_from_env"].values())
        if subject_envs & control_envs:
            problems.append(
                f"{target.name}: control_headers_from_env must use credentials distinct from "
                "headers_from_env"
            )
        containment_envs = set(header_references["containment_headers_from_env"].values())
        if subject_envs & containment_envs:
            problems.append(
                f"{target.name}: containment_headers_from_env must not reuse credentials from "
                "headers_from_env"
            )
        subject_secrets = self._secret_values(subject_envs)
        control_secrets = self._secret_values(control_envs)
        containment_secrets = self._secret_values(containment_envs)
        if subject_secrets & control_secrets:
            problems.append(
                f"{target.name}: subject and control credential values must be distinct"
            )
        if subject_secrets & containment_secrets:
            problems.append(
                f"{target.name}: subject and containment credential values must be distinct"
            )
        if 404 in denied and (
            not self.has_control_probe(target)
            or self.control_proof_mode(target) != "subject-and-control"
        ):
            problems.append(
                f"{target.name}: treating HTTP 404 as denial requires a distinct same-resource "
                "control credential so a missing resource cannot pass"
            )
        return problems

    def _env_references(self, metadata: dict[str, Any], group: str) -> dict[str, str]:
        raw = metadata.get(group, {})
        if not isinstance(raw, dict):
            raise ValueError(f"{group} must map HTTP header names to environment variables")
        references = {
            str(header).strip(): str(env_name).strip() for header, env_name in raw.items()
        }
        if any(not header or not env_name for header, env_name in references.items()):
            raise ValueError(f"{group} must not contain blank header or environment names")
        return references

    def _secret_values(self, env_names: set[str]) -> set[str]:
        return {value for env_name in env_names if (value := os.getenv(env_name))}

    def _headers(self, metadata: dict[str, Any], group: str = "headers_from_env") -> dict[str, str]:
        headers = {"User-Agent": f"ContainmentCI/{__version__}"}
        for header, env_name in self._env_references(metadata, group).items():
            value = os.getenv(env_name)
            if not value:
                raise ValueError(f"Required environment variable '{env_name}' is not set")
            headers[str(header)] = value
        return headers

    def _url(self, target: TargetConfig, key: str) -> str:
        value = target.metadata.get(key)
        if not value:
            raise ValueError(f"{key} must use HTTPS or an exact loopback hostname")
        raw = str(value)
        parsed = urlsplit(raw)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            parsed.username
            or parsed.password
            or not parsed.hostname
            or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
        ):
            raise ValueError(f"{key} must use HTTPS or an exact loopback hostname")
        return raw

    def _safe_evidence_url(self, url: str) -> str:
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

    def _comparison_url(self, url: str) -> str:
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))

    def _status_set(self, raw: Any, name: str) -> set[int]:
        values = [raw] if isinstance(raw, (int, str)) else raw
        try:
            statuses = {int(status) for status in values}
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must contain HTTP status integers") from exc
        if not statuses:
            raise ValueError(f"{name} must not be empty")
        if any(status < 100 or status > 599 for status in statuses):
            raise ValueError(f"{name} must contain statuses between 100 and 599")
        return statuses

    def _access_statuses(self, metadata: dict[str, Any]) -> tuple[set[int], set[int]]:
        allowed_raw = metadata.get("accessible_statuses")
        if allowed_raw is None:
            allowed_raw = [metadata.get("accessible_status", 200)]
        if "denied_statuses" not in metadata:
            raise ValueError(
                "denied_statuses must explicitly list responses that prove authorization denial"
            )
        denied_raw = metadata["denied_statuses"]
        allowed = self._status_set(allowed_raw, "accessible_statuses")
        denied = self._status_set(denied_raw, "denied_statuses")
        if any(status < 200 or status > 299 for status in allowed):
            raise ValueError("accessible_statuses must contain only 2xx responses")
        unsupported_denials = denied - self._EXPLICIT_DENIAL_STATUSES
        if unsupported_denials:
            formatted = ", ".join(str(status) for status in sorted(unsupported_denials))
            raise ValueError(
                "denied_statuses supports only explicit 401, 403, and controlled 404 "
                f"authorization decisions; unsupported: {formatted}"
            )
        if allowed & denied:
            raise ValueError("accessible_statuses and denied_statuses must not overlap")
        return allowed, denied

    def _containment_statuses(self, metadata: dict[str, Any]) -> set[int]:
        statuses = self._status_set(
            metadata.get("containment_success_statuses", [200, 202, 204]),
            "containment_success_statuses",
        )
        if any(status < 200 or status > 299 for status in statuses):
            raise ValueError("containment_success_statuses must contain only 2xx responses")
        return statuses

    def _probe_method(self, metadata: dict[str, Any], *, control: bool = False) -> str:
        method = str(
            metadata.get("control_probe_method", metadata.get("probe_method", "GET"))
            if control
            else metadata.get("probe_method", "GET")
        ).upper()
        if method not in {"GET", "HEAD"}:
            label = "control_probe_method" if control else "probe_method"
            raise ValueError(f"{label} must be GET or HEAD so access probes cannot mutate state")
        return method

    async def _probe(
        self,
        identity: str,
        target: TargetConfig,
        *,
        control: bool = False,
    ) -> AccessResponse:
        metadata = target.metadata
        url_key = (
            "control_probe_url" if control and metadata.get("control_probe_url") else "probe_url"
        )
        url = self._url(target, url_key)
        method = self._probe_method(metadata, control=control)
        allowed, denied = self._access_statuses(metadata)
        timeout = float(metadata.get("request_timeout_seconds", 10))
        header_group = "control_headers_from_env" if control else "headers_from_env"
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.request(
                method, url, headers=self._headers(metadata, header_group)
            )
        rate_limited = response.status_code in {403, 429} and (
            bool(response.headers.get("retry-after"))
            or response.headers.get("x-ratelimit-remaining") == "0"
            or response.headers.get("ratelimit-remaining") == "0"
        )
        if rate_limited:
            state = AccessState.INDETERMINATE
            message = "HTTP response indicated throttling"
        elif response.status_code in allowed:
            state = AccessState.ALLOWED
            message = "HTTP access allowed"
        elif response.status_code in denied:
            state = AccessState.DENIED
            message = "HTTP access explicitly denied"
        else:
            state = AccessState.INDETERMINATE
            message = "HTTP response was not a recognized access decision"
        return AccessResponse(
            state=state,
            message=message,
            evidence={
                "identity": identity,
                "resource": target.resource,
                "probe_url": self._safe_evidence_url(url),
                "status_code": response.status_code,
                "decision": state,
                "control": control,
            },
        )

    async def verify_access(self, identity: str, target: TargetConfig) -> AccessResponse:
        return await self._probe(identity, target)

    def has_control_probe(self, target: TargetConfig) -> bool:
        metadata = target.metadata
        try:
            subject_envs = set(self._env_references(metadata, "headers_from_env").values())
            control_envs = set(self._env_references(metadata, "control_headers_from_env").values())
        except ValueError:
            return False
        subject_secrets = self._secret_values(subject_envs)
        control_secrets = self._secret_values(control_envs)
        return bool(
            control_envs
            and not (subject_envs & control_envs)
            and not (subject_secrets & control_secrets)
        )

    def control_proof_mode(self, target: TargetConfig) -> str:
        metadata = target.metadata
        subject_url = self._comparison_url(self._url(target, "probe_url"))
        control_url = self._comparison_url(
            self._url(target, "control_probe_url")
            if metadata.get("control_probe_url")
            else self._url(target, "probe_url")
        )
        same_request_target = subject_url == control_url and self._probe_method(
            metadata
        ) == self._probe_method(metadata, control=True)
        return "subject-and-control" if same_request_target else "subject-and-availability-witness"

    async def verify_control_access(
        self, identity: str, target: TargetConfig
    ) -> AccessResponse | None:
        if not self.has_control_probe(target):
            return None
        control_identity = str(target.metadata.get("control_identity", "untouched-control"))
        return await self._probe(control_identity, target, control=True)

    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        metadata = target.metadata
        url = self._url(target, "containment_url")
        method = str(metadata.get("containment_method", "POST")).upper()
        expected_statuses = self._containment_statuses(metadata)
        timeout = float(metadata.get("request_timeout_seconds", 10))
        custom_payload = metadata.get("containment_payload", {})
        if not isinstance(custom_payload, dict):
            raise ValueError("containment_payload must be a mapping")
        payload = {**custom_payload, "identity": identity, "resource": target.resource}
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.request(
                method,
                url,
                headers=self._headers(metadata, "containment_headers_from_env"),
                json=payload,
            )
        accepted = response.status_code in expected_statuses
        return ProviderResponse(
            success=accepted,
            message="HTTP containment request accepted" if accepted else "HTTP containment failed",
            evidence={
                "identity": identity,
                "resource": target.resource,
                "containment_url": self._safe_evidence_url(url),
                "status_code": response.status_code,
            },
        )
