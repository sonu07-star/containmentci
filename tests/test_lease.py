from pathlib import Path
import time

import pytest

from containmentci.lease import FixtureLease, FixtureLeaseConflict


def lease(path: Path, identity: str, resources: set[str]) -> FixtureLease:
    return FixtureLease(identity, resources, ttl_seconds=60, path=path)


def test_fixture_lease_rejects_identity_and_resource_overlap(tmp_path: Path) -> None:
    path = tmp_path / "leases.db"
    first = lease(path, "synthetic-a", {"resource-a"})

    with first.hold():
        with pytest.raises(FixtureLeaseConflict, match="identity"):
            with lease(path, "synthetic-a", {"resource-b"}).hold():
                pass
        with pytest.raises(FixtureLeaseConflict, match="resource-a"):
            with lease(path, "synthetic-b", {"resource-a"}).hold():
                pass

    with lease(path, "synthetic-a", {"resource-a"}).hold():
        pass


def test_fixture_lease_normalizes_aliases_and_renews_expiry(tmp_path: Path) -> None:
    path = tmp_path / "leases.db"
    first = FixtureLease(
        "ContainmentCI-Bot",
        {"github://Org/Repo"},
        ttl_seconds=0.05,
        path=path,
    )

    with first.hold():
        time.sleep(0.12)
        with pytest.raises(FixtureLeaseConflict):
            with FixtureLease(
                "containmentci-bot",
                {"github://org/repo"},
                ttl_seconds=0.05,
                path=path,
            ).hold():
                pass
