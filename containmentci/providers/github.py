from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from containmentci import __version__
from containmentci.models import AccessState, TargetConfig
from containmentci.providers.base import AccessResponse, ContainmentProvider, ProviderResponse


class GitHubRepositoryAccessProvider(ContainmentProvider):
    """Proves repository access removal for a dedicated synthetic collaborator."""

    _LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
    _REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.transport = transport

    def validate(self, identity: str, target: TargetConfig) -> list[str]:
        metadata = target.metadata
        problems: list[str] = []
        for key in ("owner", "repo", "probe_token_env", "admin_token_env"):
            if not metadata.get(key):
                problems.append(f"{target.name}: metadata.{key} is required")
        if metadata.get("safety_acknowledgement") != "dedicated-synthetic-identity":
            problems.append(
                f"{target.name}: metadata.safety_acknowledgement must equal "
                "'dedicated-synthetic-identity'"
            )
        username = str(metadata.get("username", identity))
        if username != identity:
            problems.append(
                f"{target.name}: metadata.username must match scenario identity to prevent "
                "containing the wrong account"
            )
        if not self._LOGIN_PATTERN.fullmatch(username):
            problems.append(f"{target.name}: metadata.username is not a safe GitHub login")
        owner = str(metadata.get("owner", ""))
        repo = str(metadata.get("repo", ""))
        if owner and not self._LOGIN_PATTERN.fullmatch(owner):
            problems.append(f"{target.name}: metadata.owner is not a safe GitHub owner")
        if repo and (not self._REPOSITORY_PATTERN.fullmatch(repo) or repo in {".", ".."}):
            problems.append(f"{target.name}: metadata.repo is not a safe GitHub repository name")
        for key in ("probe_token_env", "admin_token_env", "control_token_env"):
            env_name = metadata.get(key)
            if env_name and not os.getenv(str(env_name)):
                problems.append(f"{target.name}: environment variable {env_name} is not set")
        api_url = str(metadata.get("api_url", "https://api.github.com"))
        parsed_api_url = urlsplit(api_url)
        if (
            parsed_api_url.scheme != "https"
            or parsed_api_url.hostname != "api.github.com"
            or parsed_api_url.port is not None
            or parsed_api_url.username
            or parsed_api_url.password
            or parsed_api_url.path not in {"", "/"}
            or parsed_api_url.query
            or parsed_api_url.fragment
        ):
            problems.append(
                f"{target.name}: metadata.api_url must be exactly https://api.github.com; "
                "enterprise hosts are not supported yet"
            )
        if owner and repo and target.resource != f"github://{owner}/{repo}":
            problems.append(f"{target.name}: resource must match github://{owner}/{repo}")
        probe_env = str(metadata.get("probe_token_env", ""))
        admin_env = str(metadata.get("admin_token_env", ""))
        control_env = str(metadata.get("control_token_env", admin_env))
        control_identity = metadata.get("control_identity")
        if control_identity and str(control_identity).casefold() == identity.casefold():
            problems.append(
                f"{target.name}: metadata.control_identity must differ from scenario identity"
            )
        if probe_env and probe_env in {admin_env, control_env}:
            problems.append(
                f"{target.name}: probe_token_env must differ from admin/control token variables"
            )
        probe_secret = os.getenv(probe_env) if probe_env else None
        privileged_secrets = {
            value
            for env_name in {admin_env, control_env}
            if env_name and (value := os.getenv(env_name))
        }
        if probe_secret and probe_secret in privileged_secrets:
            problems.append(
                f"{target.name}: probe and admin/control credential values must be distinct"
            )
        return problems

    def _metadata(self, identity: str, target: TargetConfig) -> tuple[str, str, str]:
        problems = self.validate(identity, target)
        if problems:
            raise ValueError("; ".join(problems))
        metadata = target.metadata
        api_url = str(metadata.get("api_url", "https://api.github.com")).rstrip("/")
        return api_url, str(metadata["owner"]), str(metadata["repo"])

    def _headers(self, token_env: Any) -> dict[str, str]:
        token = os.environ[str(token_env)]
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"ContainmentCI/{__version__}",
            "X-GitHub-Api-Version": "2026-03-10",
        }

    def _access_state(self, response: httpx.Response) -> AccessState:
        if response.status_code == 200:
            return AccessState.ALLOWED
        if response.status_code == 404:
            return AccessState.DENIED
        return AccessState.INDETERMINATE

    async def _authenticated_login(
        self, client: httpx.AsyncClient, api_url: str, headers: dict[str, str]
    ) -> tuple[str | None, httpx.Response]:
        response = await client.get(f"{api_url}/user", headers=headers)
        if response.status_code != 200:
            return None, response
        try:
            login = response.json().get("login")
        except (AttributeError, ValueError):
            return None, response
        return (login if isinstance(login, str) and login else None), response

    async def _probe(
        self,
        identity: str,
        target: TargetConfig,
        token_env: Any,
        *,
        control: bool = False,
        expected_identity: str | None = None,
    ) -> AccessResponse:
        api_url, owner, repo = self._metadata(identity, target)
        url = f"{api_url}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        headers = self._headers(token_env)
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, transport=self.transport
        ) as client:
            authenticated_login, identity_response = await self._authenticated_login(
                client, api_url, headers
            )
            expected = expected_identity or identity
            identity_matches = bool(
                authenticated_login
                and (
                    authenticated_login.casefold() == expected.casefold()
                    if not control or expected_identity
                    else authenticated_login.casefold() != identity.casefold()
                )
            )
            if not identity_matches:
                return AccessResponse(
                    state=AccessState.INDETERMINATE,
                    message="GitHub credential owner could not be bound to the expected identity",
                    evidence={
                        "identity": expected,
                        "authenticated_login": authenticated_login,
                        "identity_status_code": identity_response.status_code,
                        "repository": f"{owner}/{repo}",
                        "decision": AccessState.INDETERMINATE,
                        "control": control,
                    },
                )
            response = await client.get(url, headers=headers)
        state = self._access_state(response)
        messages = {
            AccessState.ALLOWED: "GitHub repository access allowed",
            AccessState.DENIED: "GitHub repository access explicitly denied",
            AccessState.INDETERMINATE: "GitHub response was not a conclusive access decision",
        }
        return AccessResponse(
            state=state,
            message=messages[state],
            evidence={
                "identity": authenticated_login,
                "authenticated_login": authenticated_login,
                "identity_status_code": identity_response.status_code,
                "repository": f"{owner}/{repo}",
                "status_code": response.status_code,
                "request_id": response.headers.get("x-github-request-id", ""),
                "decision": state,
                "control": control,
            },
        )

    async def verify_access(self, identity: str, target: TargetConfig) -> AccessResponse:
        return await self._probe(
            identity,
            target,
            target.metadata["probe_token_env"],
        )

    def has_control_probe(self, target: TargetConfig) -> bool:
        return bool(
            target.metadata.get("control_token_env") or target.metadata.get("admin_token_env")
        )

    async def verify_control_access(self, identity: str, target: TargetConfig) -> AccessResponse:
        token_env = target.metadata.get("control_token_env", target.metadata["admin_token_env"])
        control_identity = target.metadata.get("control_identity")
        return await self._probe(
            identity,
            target,
            token_env,
            control=True,
            expected_identity=str(control_identity) if control_identity else None,
        )

    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        api_url, owner, repo = self._metadata(identity, target)
        username = str(target.metadata.get("username", identity))
        url = (
            f"{api_url}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/collaborators/{quote(username, safe='')}"
        )
        headers = self._headers(target.metadata["admin_token_env"])
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, transport=self.transport
        ) as client:
            admin_login, identity_response = await self._authenticated_login(
                client, api_url, headers
            )
            if not admin_login or admin_login.casefold() == identity.casefold():
                return ProviderResponse(
                    success=False,
                    message="GitHub admin credential owner was unavailable or not independent",
                    evidence={
                        "identity": identity,
                        "repository": f"{owner}/{repo}",
                        "action": "remove_repository_collaborator",
                        "identity_status_code": identity_response.status_code,
                        "admin_login": admin_login,
                    },
                )
            response = await client.delete(url, headers=headers)
        accepted = response.status_code == 204
        return ProviderResponse(
            success=accepted,
            message=(
                "GitHub collaborator removal accepted"
                if accepted
                else "GitHub collaborator removal failed"
            ),
            evidence={
                "identity": identity,
                "repository": f"{owner}/{repo}",
                "action": "remove_repository_collaborator",
                "status_code": response.status_code,
                "request_id": response.headers.get("x-github-request-id", ""),
                "admin_login": admin_login,
            },
        )
