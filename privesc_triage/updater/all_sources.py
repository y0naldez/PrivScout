from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .common import atomic_write_json
from .cve import update_cve
from .exploitdb import update_exploitdb
from .gtfobins import UpdaterResult, update_gtfobins
from .progress import ProgressCallback
from ..analyzers.data_loader import load_yaml
from ..analyzers.gtfobins import cache_directory


def manifest_cache_path() -> Path:
    return cache_directory() / "update-manifest.json"


@dataclass(frozen=True, slots=True)
class UpdateSummary:
    results: list[UpdaterResult]
    products: int
    candidates: int
    manifest_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": [item.to_dict() for item in self.results],
            "products": self.products,
            "candidates": self.candidates,
            "manifest_path": self.manifest_path,
        }


def update_all(
    *,
    destination_directory: Path | None = None,
    progress: ProgressCallback | None = None,
) -> UpdateSummary:
    directory = destination_directory or cache_directory()
    products = load_yaml("third_party_products.yaml").get("products", {})
    products = products if isinstance(products, dict) else {}
    gtfo = update_gtfobins(
        cache_path=directory / "gtfobins.json", progress=progress
    )
    exploitdb, exploitdb_payload = update_exploitdb(
        cache_path=directory / "exploitdb.json",
        candidates_path=directory / "third_party_candidates.json",
        maintained_products=products,
        progress=progress,
    )
    cve = update_cve(
        exploitdb_payload,
        maintained_products=products,
        cache_path=directory / "cve.json",
        progress=progress,
    )
    candidates_payload = build_candidates_for_manifest(directory)
    manifest = directory / "update-manifest.json"
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    payload = {
        "schema_version": 1,
        "updated": timestamp,
        "sources": [asdict(item) for item in (gtfo, exploitdb, cve)],
        "products": {"status": "maintained", "entries": len(products)},
        "candidates": len(candidates_payload),
    }
    atomic_write_json(manifest, payload)
    return UpdateSummary(
        [gtfo, exploitdb, cve], len(products), len(candidates_payload), str(manifest)
    )


def build_candidates_for_manifest(directory: Path) -> list[dict[str, Any]]:
    import json

    path = directory / "third_party_candidates.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    candidates = parsed.get("candidates", []) if isinstance(parsed, dict) else []
    return candidates if isinstance(candidates, list) else []
