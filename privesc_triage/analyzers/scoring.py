from __future__ import annotations

from .data_loader import load_yaml
from ..models.finding import ScoreComponent


class ScoringEngine:
    """Central source for deterministic, explainable score modifiers."""

    def __init__(self) -> None:
        self._config = load_yaml("scoring.yaml")

    def component(self, key: str, label: str | None = None) -> ScoreComponent:
        value = self._config.get("factors", {}).get(key)
        if not isinstance(value, int):
            raise KeyError(f"Unknown scoring factor: {key}")
        return ScoreComponent(value, label or key.replace("_", " "))

