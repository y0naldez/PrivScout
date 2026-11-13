from __future__ import annotations

import re

from ..analyzers.normalizer import BinaryNormalizer
from ..models.binary import BinaryIdentity

_PATH_ONLY = re.compile(r"^\s*(/[^\x00\r\n]+?)\s*$")


def parse_suid(text: str, normalizer: BinaryNormalizer | None = None) -> list[BinaryIdentity]:
    normalizer = normalizer or BinaryNormalizer()
    parsed: list[BinaryIdentity] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = _PATH_ONLY.match(line)
        if not match:
            continue
        path = match.group(1)
        if any(char.isspace() for char in path) or path in seen:
            continue
        seen.add(path)
        parsed.append(BinaryIdentity.from_path(path, normalizer.normalize(path)))
    return parsed

