from __future__ import annotations

from pathlib import Path

import yaml

from containmentci.models import ScenarioConfig


def load_scenario(path: Path) -> ScenarioConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ScenarioConfig.model_validate(raw)

