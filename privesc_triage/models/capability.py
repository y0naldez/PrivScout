from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    name: str
    flags: str

    @property
    def effective(self) -> bool:
        return "e" in self.flags

    @property
    def permitted(self) -> bool:
        return "p" in self.flags

    @property
    def inheritable(self) -> bool:
        return "i" in self.flags


@dataclass(frozen=True, slots=True)
class CapabilityRecord:
    path: str
    basename: str
    canonical: str
    capabilities: list[CapabilityGrant] = field(default_factory=list)

