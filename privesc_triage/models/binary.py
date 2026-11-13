from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class BinaryIdentity:
    path: str
    basename: str
    canonical: str

    @classmethod
    def from_path(cls, path: str, canonical: str) -> "BinaryIdentity":
        normalized_path = path.strip()
        return cls(
            path=normalized_path,
            basename=PurePosixPath(normalized_path).name,
            canonical=canonical,
        )

