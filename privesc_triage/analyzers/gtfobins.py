from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from .data_loader import load_yaml


def cache_directory() -> Path:
    override = os.environ.get("PRIVSCOUT_CACHE") or os.environ.get("PRIVESC_TRIAGE_CACHE")
    if override:
        return Path(override)
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "privscout"
    return Path.home() / ".cache" / "privscout"


def gtfobins_cache_path() -> Path:
    return cache_directory() / "gtfobins.json"


class GTFOBinsDataset:
    """Function-level GTFOBins index with an offline packaged fallback."""

    def __init__(self, cache_path: Path | None = None) -> None:
        self.cache_path = cache_path or gtfobins_cache_path()
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        seed = load_yaml("gtfobins_seed.yaml")
        seed_payload = {"metadata": seed.get("_metadata", {}), "binaries": seed.get("binaries", {})}
        if self.cache_path.is_file():
            try:
                parsed = json.loads(self.cache_path.read_text(encoding="utf-8"))
                binaries = parsed.get("binaries") if isinstance(parsed, dict) else None
                if (
                    isinstance(binaries, dict)
                    and binaries
                    and any(
                        isinstance(entry, dict) and bool(entry.get("functions"))
                        for entry in binaries.values()
                    )
                ):
                    # Enrich an older function-only cache with detailed packaged
                    # techniques for seed entries without discarding its full index.
                    merged = deepcopy(parsed)
                    merged_binaries = merged.setdefault("binaries", {})
                    for canonical, seed_entry in seed_payload["binaries"].items():
                        cached_entry = merged_binaries.get(canonical)
                        if not isinstance(cached_entry, dict):
                            merged_binaries[canonical] = deepcopy(seed_entry)
                            continue
                        if not cached_entry.get("techniques") and seed_entry.get("techniques"):
                            cached_entry["techniques"] = deepcopy(seed_entry["techniques"])
                        seed_contexts = seed_entry.get("contexts", {})
                        cached_contexts = cached_entry.setdefault("contexts", {})
                        if isinstance(seed_contexts, dict) and isinstance(cached_contexts, dict):
                            for context, functions in seed_contexts.items():
                                cached_contexts.setdefault(context, deepcopy(functions))
                    return merged
            except (OSError, ValueError):
                pass
        return seed_payload

    @property
    def metadata(self) -> dict[str, Any]:
        value = self.data.get("metadata", {})
        return value if isinstance(value, dict) else {}

    def functions(self, canonical: str) -> list[str]:
        binary = self.data.get("binaries", {}).get(canonical, {})
        functions = binary.get("functions", []) if isinstance(binary, dict) else []
        return sorted(str(item) for item in functions)

    def techniques_for(self, canonical: str, context: str) -> list[str]:
        binary = self.data.get("binaries", {}).get(canonical, {})
        if not isinstance(binary, dict):
            return []
        contexts = binary.get("contexts", {})
        if isinstance(contexts, dict) and isinstance(contexts.get(context), list):
            return sorted(str(item) for item in contexts[context])
        # Backward compatibility for early caches that stored context markers
        # in the function list rather than indexing the current GTFOBins schema.
        return [context] if context in self.functions(canonical) else []

    def context_index(self, context: str) -> dict[str, list[str]]:
        return {
            canonical: techniques
            for canonical in self.data.get("binaries", {})
            if (techniques := self.techniques_for(canonical, context))
        }

    def technique_details_for(self, canonical: str, context: str) -> list[dict[str, Any]]:
        binary = self.data.get("binaries", {}).get(canonical, {})
        if not isinstance(binary, dict):
            return []
        techniques = binary.get("techniques", {})
        if isinstance(techniques, dict) and isinstance(techniques.get(context), list):
            result: list[dict[str, Any]] = []
            for item in techniques[context]:
                if isinstance(item, dict) and item.get("function"):
                    detail = deepcopy(item)
                    detail.setdefault("source_context", context)
                    result.append(detail)
            if result:
                return result
        # Old caches remain useful: expose a function-only detail so the CLI can
        # still explain the action and link to GTFOBins even without a body.
        return [
            {
                "function": function_name,
                "source_context": context,
                "legacy_function_only": True,
            }
            for function_name in self.techniques_for(canonical, context)
        ]

    def technique_details_index(self, context: str) -> dict[str, list[dict[str, Any]]]:
        return {
            canonical: details
            for canonical in self.data.get("binaries", {})
            if (details := self.technique_details_for(canonical, context))
        }
