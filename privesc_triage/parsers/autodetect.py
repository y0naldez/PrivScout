from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models.binary import BinaryIdentity
from ..models.capability import CapabilityRecord
from ..models.sudo_rule import SudoRule
from .capabilities import parse_capabilities
from .suid import parse_suid
from .sudo import parse_sudo

_SECTION = re.compile(r"^\s*=+\s*(SUID|CAPABILIT(?:Y|IES)|CAPS|SUDO)\s*=+\s*$", re.IGNORECASE)


@dataclass(slots=True)
class ParsedEnumeration:
    suid: list[BinaryIdentity] = field(default_factory=list)
    sudo: list[SudoRule] = field(default_factory=list)
    capabilities: list[CapabilityRecord] = field(default_factory=list)
    input_lines: int = 0

    @property
    def parsed_entries(self) -> int:
        return len(self.suid) + len(self.sudo) + len(self.capabilities)


def _section_name(label: str) -> str:
    upper = label.upper()
    if upper == "SUID":
        return "suid"
    if upper == "SUDO":
        return "sudo"
    return "capabilities"


def parse_enumeration(text: str) -> ParsedEnumeration:
    lines = text.splitlines()
    sections: dict[str, list[str]] = {"suid": [], "sudo": [], "capabilities": []}
    current: str | None = None
    found_sections = False
    for line in lines:
        marker = _SECTION.match(line)
        if marker:
            current = _section_name(marker.group(1))
            found_sections = True
            continue
        if current is not None:
            sections[current].append(line)

    if found_sections:
        suid_text = "\n".join(sections["suid"])
        sudo_text = "\n".join(sections["sudo"])
        capability_text = "\n".join(sections["capabilities"])
    else:
        suid_text = sudo_text = capability_text = text

    return ParsedEnumeration(
        suid=parse_suid(suid_text),
        sudo=parse_sudo(sudo_text),
        capabilities=parse_capabilities(capability_text),
        input_lines=len(lines),
    )

