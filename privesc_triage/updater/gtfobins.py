from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
import yaml

from ..analyzers.gtfobins import gtfobins_cache_path
from ..analyzers.normalizer import BinaryNormalizer
from .common import atomic_write_json
from .progress import ProgressCallback, report

GTFOBINS_ARCHIVE_URL = "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.tar.gz"


@dataclass(frozen=True, slots=True)
class UpdaterResult:
    source: str
    timestamp: str
    version: str
    status: str
    entries: int
    path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _front_matter(markdown: str) -> dict[str, Any]:
    lines = markdown.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    try:
        closing = next(
            index
            for index, line in enumerate(lines[1:], 1)
            if line.strip() in {"---", "..."}
        )
    except StopIteration:
        return {}
    parsed = yaml.safe_load("\n".join(lines[1:closing]))
    return parsed if isinstance(parsed, dict) else {}


def parse_gtfobins_archive(content: bytes) -> dict[str, dict[str, Any]]:
    normalizer = BinaryNormalizer()
    binaries: dict[str, dict[str, Any]] = {}
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        for member in archive.getmembers():
            pure_path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or "_gtfobins" not in pure_path.parts
                or pure_path.name.startswith(".")
            ):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            data = _front_matter(extracted.read().decode("utf-8", errors="replace"))
            functions = data.get("functions", {})
            if not isinstance(functions, dict):
                continue
            filename = pure_path.stem if pure_path.suffix == ".md" else pure_path.name
            canonical = normalizer.normalize(filename)
            context_index: dict[str, set[str]] = {
                "sudo": set(),
                "suid": set(),
                "capabilities": set(),
                "unprivileged": set(),
            }
            technique_index: dict[str, list[dict[str, Any]]] = {
                context: [] for context in context_index
            }
            for function_name, techniques in functions.items():
                if not isinstance(techniques, list):
                    continue
                for technique in techniques:
                    if not isinstance(technique, dict):
                        continue
                    contexts = technique.get("contexts", {})
                    if not isinstance(contexts, dict):
                        continue
                    for context in context_index:
                        if context in contexts:
                            context_index[context].add(str(function_name))
                            detail: dict[str, Any] = {"function": str(function_name)}
                            code = technique.get("code")
                            comment = technique.get("comment")
                            if code is not None:
                                detail["code"] = str(code).strip()
                            if comment is not None:
                                detail["comment"] = str(comment).strip()
                            attributes = {
                                str(key): value
                                for key, value in technique.items()
                                if key not in {"contexts", "code", "comment"}
                            }
                            if attributes:
                                detail["attributes"] = attributes
                            context_details = contexts.get(context)
                            if isinstance(context_details, dict) and context_details:
                                detail["context_details"] = context_details
                            technique_index[context].append(detail)
            binaries[canonical] = {
                "functions": sorted(str(key) for key in functions),
                "contexts": {
                    context: sorted(techniques)
                    for context, techniques in context_index.items()
                    if techniques
                },
                "techniques": {
                    context: sorted(
                        techniques,
                        key=lambda item: (
                            str(item.get("function", "")),
                            str(item.get("code", "")),
                        ),
                    )
                    for context, techniques in technique_index.items()
                    if techniques
                },
            }
    return dict(sorted(binaries.items()))


def update_gtfobins(
    *,
    cache_path: Path | None = None,
    url: str = GTFOBINS_ARCHIVE_URL,
    progress: ProgressCallback | None = None,
) -> UpdaterResult:
    destination = cache_path or gtfobins_cache_path()
    content = bytearray()
    with httpx.stream("GET", url, follow_redirects=True, timeout=60.0) as response:
        response.raise_for_status()
        total = int(response.headers["content-length"]) if response.headers.get("content-length", "").isdigit() else None
        report(progress, "GTFOBins", "descargando", 0, total)
        for chunk in response.iter_bytes():
            content.extend(chunk)
            report(progress, "GTFOBins", "descargando", len(content), total)
    report(progress, "GTFOBins", "procesando", len(content), len(content))
    binaries = parse_gtfobins_archive(bytes(content))
    if not binaries or not any(entry.get("functions") for entry in binaries.values()):
        raise ValueError("Downloaded GTFOBins archive contained no usable function entries")
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    digest = hashlib.sha256(content).hexdigest()
    payload = {
        "metadata": {
            "schema_version": 2,
            "source": "GTFOBins",
            "source_url": url,
            "updated": timestamp,
            "sha256": digest,
            "description": "Contextual GTFOBins functions with operator guidance and technique bodies",
        },
        "binaries": binaries,
    }
    atomic_write_json(destination, payload)
    report(progress, "GTFOBins", "completado", len(content), len(content))
    return UpdaterResult("GTFOBins", timestamp, digest[:12], "updated", len(binaries), str(destination))
