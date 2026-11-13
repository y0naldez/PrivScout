from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any

import yaml


@lru_cache(maxsize=None)
def load_yaml(name: str) -> dict[str, Any]:
    resource = files("privesc_triage.data").joinpath(name)
    parsed = yaml.safe_load(resource.read_text(encoding="utf-8"))
    return parsed if isinstance(parsed, dict) else {}

