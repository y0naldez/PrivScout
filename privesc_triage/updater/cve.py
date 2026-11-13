from __future__ import annotations

import hashlib
import json
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import httpx

from .common import atomic_write_json
from .gtfobins import UpdaterResult
from .progress import ProgressCallback, report
from ..analyzers.gtfobins import cache_directory


CVE_LIST_ARCHIVE_URL = (
    "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
)


def cve_cache_path() -> Path:
    return cache_directory() / "cve.json"


def _english(items: list[dict[str, Any]]) -> str:
    for item in items:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    return ""


def compact_cve_record(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record.get("cveMetadata", {})
    containers = record.get("containers", {})
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
    affected: list[dict[str, Any]] = []
    for item in cna.get("affected", []):
        if not isinstance(item, dict):
            continue
        affected.append(
            {
                key: item[key]
                for key in ("vendor", "product", "packageName", "platforms", "cpes", "versions")
                if key in item
            }
        )
    references = [
        str(item.get("url"))
        for item in cna.get("references", [])
        if isinstance(item, dict) and item.get("url")
    ]
    return {
        "id": str(metadata.get("cveId", "")),
        "state": str(metadata.get("state", "")),
        "published": metadata.get("datePublished"),
        "updated": metadata.get("dateUpdated"),
        "description": _english(cna.get("descriptions", [])),
        "affected": affected,
        "references": references,
    }


def parse_cve_archive(
    source: str | Path | BinaryIO, relevant_ids: set[str]
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(source) as archive:
        wanted = {item.upper() for item in relevant_ids}
        for name in archive.namelist():
            filename = Path(name).name
            if not filename.startswith("CVE-") or not filename.endswith(".json"):
                continue
            cve_id = filename[:-5].upper()
            if cve_id not in wanted:
                continue
            try:
                record = json.loads(archive.read(name))
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
            compact = compact_cve_record(record)
            if compact["id"]:
                records[compact["id"].upper()] = compact
    return dict(sorted(records.items()))


def _catalog_cve_ids(maintained_products: dict[str, Any]) -> set[str]:
    return {
        str(vulnerability.get("id", "")).upper()
        for product in maintained_products.values()
        if isinstance(product, dict)
        for vulnerability in product.get("vulnerabilities", [])
        if isinstance(vulnerability, dict) and vulnerability.get("id")
    }


def _download_to_temporary(
    url: str, progress: ProgressCallback | None = None
) -> tuple[Path, str, int]:
    digest = hashlib.sha256()
    handle = tempfile.NamedTemporaryFile(prefix="privscout-cve-", suffix=".zip", delete=False)
    path = Path(handle.name)
    try:
        with handle, httpx.stream(
            "GET", url, follow_redirects=True, timeout=180.0
        ) as response:
            response.raise_for_status()
            total = int(response.headers["content-length"]) if response.headers.get("content-length", "").isdigit() else None
            completed = 0
            report(progress, "CVE", "descargando", completed, total)
            for chunk in response.iter_bytes():
                handle.write(chunk)
                digest.update(chunk)
                completed += len(chunk)
                report(progress, "CVE", "descargando", completed, total)
        return path, digest.hexdigest(), completed
    except Exception:
        path.unlink(missing_ok=True)
        raise


def update_cve(
    exploitdb_payload: dict[str, Any],
    *,
    maintained_products: dict[str, Any] | None = None,
    cache_path: Path | None = None,
    url: str = CVE_LIST_ARCHIVE_URL,
    progress: ProgressCallback | None = None,
) -> UpdaterResult:
    products = maintained_products or {}
    relevant_ids = {
        str(item).upper() for item in exploitdb_payload.get("by_cve", {})
    } | _catalog_cve_ids(products)
    if not relevant_ids:
        raise ValueError("No relevant CVE identifiers were found")
    temporary, digest, downloaded = _download_to_temporary(url, progress)
    report(progress, "CVE", "filtrando", downloaded, downloaded)
    try:
        try:
            records = parse_cve_archive(temporary, relevant_ids)
        except zipfile.BadZipFile as exc:
            raise ValueError("Downloaded CVE List archive is not a valid ZIP file") from exc
    finally:
        temporary.unlink(missing_ok=True)
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    exploit_ids = exploitdb_payload.get("by_cve", {})
    for cve_id in relevant_ids:
        records.setdefault(
            cve_id,
            {
                "id": cve_id,
                "state": "unresolved",
                "description": "",
                "affected": [],
                "references": [],
            },
        )["exploitdb_ids"] = list(exploit_ids.get(cve_id, []))
    payload = {
        "metadata": {
            "schema_version": 1,
            "source": "CVE List V5",
            "source_url": url,
            "updated": timestamp,
            "sha256": digest,
            "requested_records": len(relevant_ids),
            "resolved_records": sum(
                item.get("state") != "unresolved" for item in records.values()
            ),
        },
        "cves": dict(sorted(records.items())),
    }
    destination = cache_path or cve_cache_path()
    atomic_write_json(destination, payload)
    report(progress, "CVE", "completado", downloaded, downloaded)
    return UpdaterResult(
        "CVE",
        timestamp,
        digest[:12],
        "updated",
        len(records),
        str(destination),
    )
