from __future__ import annotations

import re
from pathlib import PurePosixPath

from .data_loader import load_yaml


class BinaryNormalizer:
    """Canonicalize binary names using explicit, maintained aliases."""

    def __init__(self) -> None:
        aliases = load_yaml("aliases.yaml")
        self._patterns: list[tuple[str, re.Pattern[str]]] = []
        for canonical, config in aliases.items():
            if canonical.startswith("_") or not isinstance(config, dict):
                continue
            for pattern in config.get("patterns", []):
                self._patterns.append((canonical, re.compile(pattern, re.IGNORECASE)))

    def normalize(self, path_or_name: str) -> str:
        name = PurePosixPath(path_or_name.strip()).name.lower()
        for canonical, pattern in self._patterns:
            if pattern.fullmatch(name):
                return canonical
        return name

