from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..analyzers.normalizer import BinaryNormalizer
from ..models.capability import CapabilityGrant, CapabilityRecord

_LINE = re.compile(r"^\s*(?P<path>/\S+)\s+(?P<spec>.+?)\s*$")
_GROUP = re.compile(
    r"(?P<names>cap_[a-z0-9_]+(?:,cap_[a-z0-9_]+)*)\s*[=+]\s*(?P<flags>[eip]+)",
    re.IGNORECASE,
)


def parse_capabilities(
    text: str, normalizer: BinaryNormalizer | None = None
) -> list[CapabilityRecord]:
    normalizer = normalizer or BinaryNormalizer()
    records: list[CapabilityRecord] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for line in text.splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        grants: list[CapabilityGrant] = []
        for group in _GROUP.finditer(match.group("spec")):
            flags = "".join(char for char in "eip" if char in group.group("flags").lower())
            grants.extend(
                CapabilityGrant(name.strip().lower(), flags)
                for name in group.group("names").split(",")
            )
        if not grants:
            continue
        path = match.group("path")
        key = (path, tuple((grant.name, grant.flags) for grant in grants))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            CapabilityRecord(
                path=path,
                basename=PurePosixPath(path).name,
                canonical=normalizer.normalize(path),
                capabilities=grants,
            )
        )
    return records

