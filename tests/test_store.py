from pathlib import Path

from containmentci.models import RunResult
from containmentci.store import RunStore


def test_store_round_trip(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs.db")
    run = RunResult(scenario="demo", identity="synthetic@example.com")
    store.save(run)
    restored = store.get(run.id)
    assert restored is not None
    assert restored.id == run.id

