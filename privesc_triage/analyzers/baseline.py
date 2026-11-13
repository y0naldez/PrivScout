from __future__ import annotations

from pathlib import PurePosixPath

from .data_loader import load_yaml


def matches_expected_path(path: str, patterns: list[str]) -> bool:
    """Match only maintained absolute path patterns, never a basename alone."""
    candidate = PurePosixPath(path)
    return any(
        isinstance(pattern, str)
        and pattern.startswith("/")
        and candidate.match(pattern)
        for pattern in patterns
    )


class SuidBaseline:
    def __init__(self) -> None:
        data = load_yaml("common_suid.yaml")
        entries = data.get("entries", {})
        self.entries = entries if isinstance(entries, dict) else {}

    def classification(
        self,
        canonical: str,
        path: str,
        *,
        known_context_vector: bool = False,
    ) -> str:
        # An exact-context technique must never be hidden by a common-package baseline.
        if known_context_vector:
            return "known_interesting"
        entry = self.entries.get(canonical, {})
        paths = entry.get("paths", []) if isinstance(entry, dict) else []
        if matches_expected_path(path, paths):
            return "common"
        return "unknown_custom"
