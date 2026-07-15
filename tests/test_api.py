from pathlib import Path

from fastapi.testclient import TestClient
from fastapi import HTTPException
import pytest

import containmentci.api as api
from containmentci.models import RunResult
from containmentci.store import RunStore


TEST_API_TOKEN = "test-api-token-with-at-least-32-bytes"
WRONG_API_TOKEN = "wrong-api-token-with-at-least-32-bytes"


def configure_test_api(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(api, "store", RunStore(tmp_path / "runs.db"))
    monkeypatch.setenv("CONTAINMENTCI_SCENARIO_ROOT", str(tmp_path))
    monkeypatch.setenv("TEST_HTTP_SUBJECT_TOKEN", "subject-secret")
    monkeypatch.setenv("TEST_HTTP_ADMIN_TOKEN", "admin-secret")
    return TestClient(api.app)


def write_live_scenario(tmp_path: Path) -> None:
    (tmp_path / "live.yaml").write_text(
        """name: live-api-test
identity: synthetic@example.com
targets:
  - name: Live HTTP target
    provider: http
    resource: test://live
    metadata:
      safety_acknowledgement: dedicated-synthetic-identity
      probe_url: https://example.com/probe
      containment_url: https://example.com/contain
      denied_statuses: [401, 403]
      headers_from_env:
        Authorization: TEST_HTTP_SUBJECT_TOKEN
      containment_headers_from_env:
        Authorization: TEST_HTTP_ADMIN_TOKEN
""",
        encoding="utf-8",
    )


def forbid_execution(monkeypatch) -> None:
    async def fail_if_run(*args, **kwargs):
        raise AssertionError("A rejected API request must not execute its scenario")

    monkeypatch.setattr(api.ExecutionEngine, "run", fail_if_run)


def test_api_runs_scenario_and_serves_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(api, "store", RunStore(tmp_path / "runs.db"))
    client = TestClient(api.app)

    health = client.get("/health")
    assert health.json() == {"status": "ok"}

    response = client.post("/api/runs", params={"scenario": "compromised-user.yaml"})
    assert response.status_code == 200
    run = response.json()
    assert run["status"] == "fail"

    report = client.get(f"/runs/{run['id']}")
    assert report.status_code == 200
    assert "Containment coverage" in report.text

    traversal = client.post("/api/runs", params={"scenario": "../pyproject.toml"})
    assert traversal.status_code == 400


def test_api_returns_preflight_problems_without_running(tmp_path: Path, monkeypatch) -> None:
    client = configure_test_api(tmp_path, monkeypatch)
    (tmp_path / "invalid.yaml").write_text(
        """name: invalid-provider
identity: synthetic@example.com
targets:
  - name: Invalid target
    provider: missing-provider
    resource: test://invalid
""",
        encoding="utf-8",
    )

    async def fail_if_run(*args, **kwargs):
        raise AssertionError("A scenario with preflight problems must not execute")

    monkeypatch.setattr(api.ExecutionEngine, "run", fail_if_run)
    response = client.post("/api/runs", params={"scenario": "invalid.yaml"})

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Scenario preflight failed"
    assert any("Unknown provider 'missing-provider'" in problem for problem in detail["problems"])


def test_live_api_requires_explicit_request_approval(tmp_path: Path, monkeypatch) -> None:
    write_live_scenario(tmp_path)
    client = configure_test_api(tmp_path, monkeypatch)
    forbid_execution(monkeypatch)
    monkeypatch.setenv("CONTAINMENTCI_API_ALLOW_LIVE", "true")
    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)

    response = client.post(
        "/api/runs",
        params={"scenario": "live.yaml"},
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    )

    assert response.status_code == 403
    assert "approve_live=true" in response.json()["detail"]


def test_live_api_requires_server_gate(tmp_path: Path, monkeypatch) -> None:
    write_live_scenario(tmp_path)
    client = configure_test_api(tmp_path, monkeypatch)
    forbid_execution(monkeypatch)
    monkeypatch.delenv("CONTAINMENTCI_API_ALLOW_LIVE", raising=False)
    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)

    response = client.post(
        "/api/runs",
        params={"scenario": "live.yaml", "approve_live": "true"},
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    )

    assert response.status_code == 503
    assert "disabled by server configuration" in response.json()["detail"]


def test_live_api_requires_configured_and_matching_token(tmp_path: Path, monkeypatch) -> None:
    write_live_scenario(tmp_path)
    client = configure_test_api(tmp_path, monkeypatch)
    forbid_execution(monkeypatch)
    monkeypatch.setenv("CONTAINMENTCI_API_ALLOW_LIVE", "true")
    monkeypatch.delenv("CONTAINMENTCI_API_TOKEN", raising=False)

    missing_token = client.post(
        "/api/runs",
        params={"scenario": "live.yaml", "approve_live": "true"},
        headers={"Authorization": "Bearer supplied-token"},
    )
    assert missing_token.status_code == 503
    assert "CONTAINMENTCI_API_TOKEN" in missing_token.json()["detail"]

    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)
    wrong_token = client.post(
        "/api/runs",
        params={"scenario": "live.yaml", "approve_live": "true"},
        headers={"Authorization": f"Bearer {WRONG_API_TOKEN}"},
    )
    assert wrong_token.status_code == 403
    assert "valid Bearer token" in wrong_token.json()["detail"]


def test_live_api_runs_only_after_all_authorization_checks(tmp_path: Path, monkeypatch) -> None:
    write_live_scenario(tmp_path)
    client = configure_test_api(tmp_path, monkeypatch)
    monkeypatch.setenv("CONTAINMENTCI_API_ALLOW_LIVE", "true")
    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)
    monkeypatch.setenv("CONTAINMENTCI_SIGNING_KEY", "test-signing-key-with-at-least-32-bytes")
    executed = False

    async def fake_run(engine, scenario):
        nonlocal executed
        executed = True
        assert engine.allow_live is True
        return RunResult(scenario=scenario.name, identity=scenario.identity)

    monkeypatch.setattr(api.ExecutionEngine, "run", fake_run)
    response = client.post(
        "/api/runs",
        params={"scenario": "live.yaml", "approve_live": "true"},
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    )

    assert response.status_code == 200
    assert executed is True
    assert response.json()["scenario"] == "live-api-test"


def test_live_api_rejects_reused_authentication_and_signing_secret(
    tmp_path: Path, monkeypatch
) -> None:
    write_live_scenario(tmp_path)
    client = configure_test_api(tmp_path, monkeypatch)
    forbid_execution(monkeypatch)
    monkeypatch.setenv("CONTAINMENTCI_API_ALLOW_LIVE", "true")
    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)
    monkeypatch.setenv("CONTAINMENTCI_SIGNING_KEY", TEST_API_TOKEN)

    response = client.post(
        "/api/runs",
        params={"scenario": "live.yaml", "approve_live": "true"},
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    )

    assert response.status_code == 503
    assert "independent secrets" in response.json()["detail"]


def test_configured_api_token_protects_stored_run_data(tmp_path: Path, monkeypatch) -> None:
    client = configure_test_api(tmp_path, monkeypatch)
    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)

    assert client.get("/health").status_code == 200
    assert client.get("/api/runs").status_code == 401
    authorized = client.get(
        "/api/runs",
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    )
    assert authorized.status_code == 200


def test_stored_run_api_rejects_reused_authentication_and_signing_secret(
    tmp_path: Path, monkeypatch
) -> None:
    client = configure_test_api(tmp_path, monkeypatch)
    monkeypatch.setenv("CONTAINMENTCI_API_TOKEN", TEST_API_TOKEN)
    monkeypatch.setenv("CONTAINMENTCI_SIGNING_KEY", TEST_API_TOKEN)

    response = client.get(
        "/api/runs",
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    )

    assert response.status_code == 503
    assert "independent secrets" in response.json()["detail"]


def test_live_fixture_claim_rejects_overlapping_identity_or_resource() -> None:
    api._active_live_runs.clear()
    with api._claim_live_fixture("synthetic-a", frozenset({"resource-a"})):
        with pytest.raises(HTTPException) as same_identity:
            with api._claim_live_fixture("synthetic-a", frozenset({"resource-b"})):
                pass
        with pytest.raises(HTTPException) as same_resource:
            with api._claim_live_fixture("synthetic-b", frozenset({"resource-a"})):
                pass

    assert same_identity.value.status_code == 409
    assert same_resource.value.status_code == 409
    assert not api._active_live_runs


def test_live_fixture_claim_normalizes_case_aliases() -> None:
    api._active_live_runs.clear()
    with api._claim_live_fixture("Synthetic-A", frozenset({"github://Org/Repo"})):
        with pytest.raises(HTTPException) as collision:
            with api._claim_live_fixture("synthetic-a", frozenset({"github://org/repo"})):
                pass

    assert collision.value.status_code == 409
