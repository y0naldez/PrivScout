from __future__ import annotations

import re
import json
from copy import deepcopy
from shlex import quote
from pathlib import Path
from typing import Any

from .data_loader import load_yaml
from .gtfobins import cache_directory
from ..models.binary import BinaryIdentity


_GENERIC_BINARY_NAMES = {
    "agent",
    "app",
    "application",
    "client",
    "daemon",
    "helper",
    "install",
    "installer",
    "manager",
    "monitor",
    "product",
    "runner",
    "server",
    "service",
    "tool",
    "update",
    "updater",
    "utility",
    "worker",
    "wrapper",
}


def _normalized_words(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _heuristic_name(binary: BinaryIdentity) -> str | None:
    """Return a discriminative full-name phrase, never a loose token."""
    phrase = _normalized_words(binary.canonical)
    words = phrase.split()
    if not phrase or phrase in _GENERIC_BINARY_NAMES:
        return None
    # A multiword full name (for example, product-helper) is sufficiently
    # bounded even when its individual words are generic. Single-word names
    # need to be discriminative on their own.
    if len(words) == 1 and not any(
        len(word) >= 4 and word not in _GENERIC_BINARY_NAMES for word in words
    ):
        return None
    return phrase


class ThirdPartyDataset:
    """Conservative offline product signatures for privileged third-party software."""

    def __init__(self, cache_path: Path | None = None) -> None:
        data = load_yaml("third_party_products.yaml")
        products = data.get("products", {})
        self.products = products if isinstance(products, dict) else {}
        directory = cache_path or cache_directory()
        self.exploitdb = self._load_cache(directory / "exploitdb.json")
        self.cves = self._load_cache(directory / "cve.json")
        self.candidates = self._load_cache(directory / "third_party_candidates.json")

    @staticmethod
    def _load_cache(path: Path) -> dict[str, Any]:
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _enrich(self, entry: dict[str, Any]) -> dict[str, Any]:
        exploits_by_id = {
            int(item["id"]): item
            for item in self.exploitdb.get("exploits", [])
            if isinstance(item, dict) and isinstance(item.get("id"), int)
        }
        collected = {
            int(item["id"]): item
            for item in entry.get("exploitdb", [])
            if isinstance(item, dict) and isinstance(item.get("id"), int)
        }
        cve_ids = {
            str(item.get("id", "")).upper()
            for item in entry.get("vulnerabilities", [])
            if isinstance(item, dict) and item.get("id")
        }
        for cve_id in cve_ids:
            for exploit_id in self.exploitdb.get("by_cve", {}).get(cve_id, []):
                if exploit_id in exploits_by_id:
                    collected[exploit_id] = exploits_by_id[exploit_id]
        aliases = [
            str(item).lower() for item in entry.get("product_aliases", []) if item
        ]
        for exploit in self.exploitdb.get("relevant_exploits", []):
            if not isinstance(exploit, dict) or not isinstance(exploit.get("id"), int):
                continue
            title = str(exploit.get("title", "")).lower()
            if any(alias in title for alias in aliases):
                collected[exploit["id"]] = exploit
        entry["exploitdb"] = list(collected.values())

        cached_cves = self.cves.get("cves", {})
        for vulnerability in entry.get("vulnerabilities", []):
            if not isinstance(vulnerability, dict):
                continue
            cached = cached_cves.get(str(vulnerability.get("id", "")).upper())
            if isinstance(cached, dict):
                vulnerability["record"] = deepcopy(cached)
        return entry

    def match(self, binary: BinaryIdentity) -> dict[str, Any]:
        for product_id, raw_entry in self.products.items():
            if not isinstance(raw_entry, dict):
                continue
            canonical_names = {
                str(item).lower() for item in raw_entry.get("canonical_names", [])
            }
            if binary.canonical.lower() not in canonical_names:
                continue
            patterns = raw_entry.get("path_patterns", [])
            if not any(
                isinstance(pattern, str)
                and re.fullmatch(pattern, binary.path, flags=re.IGNORECASE)
                for pattern in patterns
            ):
                continue
            entry = deepcopy(raw_entry)
            entry = self._enrich(entry)
            entry["match"] = True
            entry["match_type"] = "maintained-signature"
            entry["product_id"] = str(product_id)
            entry["owner_status"] = "unconfirmed"
            entry["version"] = None
            entry["version_status"] = "not-detected"
            entry["exploitdb_status"] = "product-candidates"
            entry["cve_status"] = "possible"
            return entry
        return {}

    def match_heuristic(self, binary: BinaryIdentity) -> dict[str, Any]:
        """Correlate an unknown binary with untrusted offline review candidates.

        This intentionally uses the entire normalized binary name as a bounded
        phrase. It does not identify a product and never changes the risk score.
        """
        phrase = _heuristic_name(binary)
        if phrase is None:
            return {}

        matches: list[dict[str, Any]] = []
        for exploit in self.candidates.get("candidates", []):
            if not isinstance(exploit, dict) or not isinstance(exploit.get("id"), int):
                continue
            title = _normalized_words(str(exploit.get("title", "")))
            if f" {phrase} " in f" {title} ":
                matches.append(deepcopy(exploit))

        if not matches:
            return {}
        matches.sort(key=lambda item: (not bool(item.get("verified")), int(item["id"])))
        matches = matches[:10]

        cve_ids = sorted(
            {
                str(cve_id).upper()
                for exploit in matches
                for cve_id in exploit.get("cves", [])
                if cve_id
            }
        )
        cached_cves = self.cves.get("cves", {})
        vulnerabilities: list[dict[str, Any]] = []
        for cve_id in cve_ids:
            vulnerability: dict[str, Any] = {
                "id": cve_id,
                "source": "CVE Program",
                "status": "related-to-heuristic-exploit",
            }
            cached = cached_cves.get(cve_id)
            if isinstance(cached, dict):
                vulnerability["record"] = deepcopy(cached)
            vulnerabilities.append(vulnerability)

        return {
            "match": True,
            "match_type": "heuristic-exploit-title",
            "product": None,
            "product_status": "unconfirmed",
            "owner_status": "unconfirmed",
            "software_type": "unconfirmed",
            "version": None,
            "version_status": "not-detected",
            "confidence": "low",
            "matched_name": phrase,
            "exploitdb": matches,
            "exploitdb_status": "heuristic-name-match",
            "vulnerabilities": vulnerabilities,
            "cve_status": "related-to-heuristic-exploit",
            "applicability": (
                "Requires identifying the product and version and confirming root ownership."
            ),
            "applicability_es": (
                "requiere identificar producto y versión, y confirmar propietario root"
            ),
            "recommendation": "Validate the product manually before using any exploit.",
            "recommendation_es": "validar manualmente el producto antes de usar el exploit",
        }


def third_party_checks(entry: dict[str, Any], path: str) -> list[str]:
    """Render catalog checks for display only; PrivScout never executes them."""
    target = quote(path)
    checks: list[str] = []
    for template in entry.get("suggested_checks", []):
        if isinstance(template, str):
            checks.append(template.format(path=target))
    if entry.get("match_type") == "heuristic-exploit-title":
        words = str(entry.get("matched_name", "")).split()
        pattern = quote("|".join(["version", *words]))
        checks.extend(
            [
                f"file {target}",
                f"ls -la {target}",
                f"{target} --version",
                f"strings {target} | grep -Ei {pattern}",
                f"dpkg -S {target} 2>/dev/null",
                f"rpm -qf {target} 2>/dev/null",
            ]
        )
    return checks
