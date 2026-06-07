from __future__ import annotations

import os
from typing import Any

import httpx

from containmentci.models import TargetConfig
from containmentci.providers.base import ContainmentProvider, ProviderResponse


class GitHubRepositoryAccessProvider(ContainmentProvider):
    """Proves repository access removal for a dedicated synthetic collaborator."""

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
        for key in ("probe_token_env", "admin_token_env"):
            env_name = metadata.get(key)
            if env_name and not os.getenv(str(env_name)):
                problems.append(f"{target.name}: environment variable {env_name} is not set")
        api_url = str(metadata.get("api_url", "https://api.github.com"))
        if not api_url.startswith("https://"):
            problems.append(f"{target.name}: metadata.api_url must use HTTPS")
        owner = metadata.get("owner")
        repo = metadata.get("repo")
        if owner and repo and target.resource != f"github://{owner}/{repo}":
            problems.append(
                f"{target.name}: resource must match github://{owner}/{repo}"
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
            "User-Agent": "ContainmentCI/0.1",
            "X-GitHub-Api-Version": "2026-03-10",
        }

    async def verify_access(self, identity: str, target: TargetConfig) -> ProviderResponse:
        api_url, owner, repo = self._metadata(identity, target)
        url = f"{api_url}/repos/{owner}/{repo}"
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, transport=self.transport
        ) as client:
            response = await client.get(
                url,
                headers=self._headers(target.metadata["probe_token_env"]),
            )
        accessible = response.status_code == 200
        return ProviderResponse(
            success=accessible,
            message="GitHub repository access succeeded" if accessible else "GitHub access denied",
            evidence={
                "identity": identity,
                "repository": f"{owner}/{repo}",
                "status_code": response.status_code,
                "request_id": response.headers.get("x-github-request-id", ""),
            },
        )

    async def contain(self, identity: str, target: TargetConfig) -> ProviderResponse:
        api_url, owner, repo = self._metadata(identity, target)
        username = str(target.metadata.get("username", identity))
        url = f"{api_url}/repos/{owner}/{repo}/collaborators/{username}"
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, transport=self.transport
        ) as client:
            response = await client.delete(
                url,
                headers=self._headers(target.metadata["admin_token_env"]),
            )
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
            },
        )
