from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from ..analyzers.normalizer import BinaryNormalizer
from ..models.sudo_rule import SudoRule

_TAG_NAMES = (
    "EXEC|NOEXEC|FOLLOW|NOFOLLOW|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|"
    "NOLOG_OUTPUT|MAIL|NOMAIL|INTERCEPT|NOINTERCEPT|PASSWD|NOPASSWD|"
    "SETENV|NOSETENV"
)
_CLAUSE = re.compile(
    r"^\s*(?:\((?P<runas>[^)]*)\)\s*)?"
    rf"(?P<tags>(?:(?:{_TAG_NAMES}):\s*)*)"
    r"(?:(?P<digest>(?:sha224|sha256|sha384|sha512):[0-9a-f]+)\s+)?"
    r"(?P<negated>!)?(?P<path>/\S+)(?P<arguments>.*)$",
    re.IGNORECASE,
)
_SPLIT_COMMANDS = re.compile(
    rf",\s*(?=(?:\([^)]*\)\s*)?(?:(?:{_TAG_NAMES}):\s*)*"
    r"(?:(?:sha224|sha256|sha384|sha512):[0-9a-f]+\s+)?!?/)",
    re.IGNORECASE,
)
_TAGS = re.compile(_TAG_NAMES, re.IGNORECASE)


def _runas(value: str | None, inherited_users: list[str], inherited_groups: list[str]) -> tuple[list[str], list[str]]:
    if value is None:
        return inherited_users, inherited_groups
    user_part, separator, group_part = value.partition(":")
    users = [item.strip() for item in user_part.split(",") if item.strip()] or ["root"]
    groups = [item.strip() for item in group_part.split(",") if item.strip()] if separator else []
    return users, groups


def _arguments(value: str) -> list[str]:
    stripped = value.strip()
    if not stripped:
        return []
    try:
        return shlex.split(stripped, posix=True)
    except ValueError:
        return stripped.split()


def parse_sudo(text: str, normalizer: BinaryNormalizer | None = None) -> list[SudoRule]:
    normalizer = normalizer or BinaryNormalizer()
    rules: list[SudoRule] = []
    seen: set[tuple] = set()
    for physical_line in text.splitlines():
        stripped = physical_line.strip()
        if not stripped or stripped.startswith(("Matching Defaults", "User ", "Sudoers entry")):
            continue
        inherited_users = ["root"]
        inherited_groups: list[str] = []
        inherited_nopasswd = False
        inherited_noexec = False
        parsed_in_line = False
        for clause in _SPLIT_COMMANDS.split(stripped):
            match = _CLAUSE.match(clause)
            if not match:
                continue
            if not parsed_in_line and not any(
                (match.group("runas"), match.group("tags"), match.group("negated"))
            ):
                continue
            users, groups = _runas(match.group("runas"), inherited_users, inherited_groups)
            tags = [item.upper() for item in _TAGS.findall(match.group("tags") or "")]
            nopasswd = inherited_nopasswd
            noexec = inherited_noexec
            for tag in tags:
                if tag == "NOPASSWD":
                    nopasswd = True
                elif tag == "PASSWD":
                    nopasswd = False
                elif tag == "NOEXEC":
                    noexec = True
                elif tag == "EXEC":
                    noexec = False
            path = match.group("path")
            arguments = _arguments(match.group("arguments"))
            negated = bool(match.group("negated"))
            digest = match.group("digest")
            key = (
                path,
                tuple(users),
                tuple(groups),
                nopasswd,
                noexec,
                tuple(arguments),
                negated,
                digest,
            )
            if key in seen:
                continue
            seen.add(key)
            canonical = normalizer.normalize(path)
            rules.append(
                SudoRule(
                    command=clause.strip(),
                    binary_path=path,
                    basename=PurePosixPath(path).name,
                    canonical=canonical,
                    runas_users=list(users),
                    runas_groups=list(groups),
                    nopasswd=nopasswd,
                    arguments=arguments,
                    wildcards=any(any(char in token for char in "*?[") for token in [path, *arguments]),
                    negated=negated,
                    noexec=noexec,
                    tags=tags,
                    digest=digest,
                )
            )
            parsed_in_line = True
            inherited_users, inherited_groups = list(users), list(groups)
            inherited_nopasswd, inherited_noexec = nopasswd, noexec
    return rules
