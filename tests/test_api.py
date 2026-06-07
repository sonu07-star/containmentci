from pathlib import Path

from fastapi.testclient import TestClient

import containmentci.api as api
from containmentci.store import RunStore


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
