from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SudoRule:
    command: str
    binary_path: str
    basename: str
    canonical: str
    runas_users: list[str] = field(default_factory=lambda: ["root"])
    runas_groups: list[str] = field(default_factory=list)
    nopasswd: bool = False
    arguments: list[str] = field(default_factory=list)
    wildcards: bool = False
    negated: bool = False
    noexec: bool = False
    tags: list[str] = field(default_factory=list)
    digest: str | None = None

    @property
    def restricted(self) -> bool:
        return bool(self.arguments)
