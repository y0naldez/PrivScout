from __future__ import annotations

from typing import Any

from .data_loader import load_yaml
from ..models.sudo_rule import SudoRule


def _tar_create_mode(arguments: list[str]) -> bool:
    """Return true only when the fixed tar arguments select archive creation."""
    for argument in arguments:
        if argument == "--create":
            return True
        if argument.startswith("-") and not argument.startswith("--") and "c" in argument[1:]:
            return True
    first = arguments[0] if arguments else ""
    # GNU tar also accepts a traditional alphabetic option cluster without '-'
    # in the first position. Do not inspect archive paths or filenames here.
    return first.isalpha() and "c" in first


def _matches(rule: SudoRule, matcher: str) -> bool:
    if matcher == "tar-create-trailing-standalone-wildcard":
        return (
            rule.canonical == "tar"
            and len(rule.arguments) >= 2
            and rule.arguments[-1] == "*"
            and _tar_create_mode(rule.arguments[:-1])
        )
    return False


def sudo_wildcard_vectors(rule: SudoRule) -> list[dict[str, Any]]:
    """Detect wildcard routes without claiming a target-specific command."""
    catalog = load_yaml("sudo_argument_vectors.yaml")
    definitions = catalog.get(rule.canonical, [])
    if rule.negated or rule.noexec or not isinstance(definitions, list):
        return []

    vectors: list[dict[str, Any]] = []
    for definition in definitions:
        if not isinstance(definition, dict) or not _matches(rule, str(definition.get("matcher", ""))):
            continue
        vectors.append(
            {
                "id": str(definition.get("id", "")),
                "type": str(definition.get("type", "wildcard-injection-candidate")),
            }
        )
    return vectors
