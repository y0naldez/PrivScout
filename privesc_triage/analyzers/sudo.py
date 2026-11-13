from __future__ import annotations

from .anomaly import suggested_sudo_checks, unusual_location
from .data_loader import load_yaml
from .guidance import build_actions
from .scoring import ScoringEngine
from .sudo_arguments import sudo_wildcard_vectors
from ..models.finding import Finding
from ..models.sudo_rule import SudoRule


NOEXEC_BLOCKED_FUNCTIONS = {
    "bind-shell",
    "command",
    "inherit",
    "reverse-shell",
    "shell",
}


def _privileged_runas(rule: SudoRule) -> bool:
    values = {item.lower() for item in rule.runas_users}
    denied = {item[1:] for item in values if item.startswith("!")}
    allowed = {item for item in values if not item.startswith("!")}
    if denied & {"all", "root", "#0"}:
        return False
    return bool(allowed & {"all", "root", "#0"})


def _root_excluded(rule: SudoRule) -> bool:
    return any(item.lower() in {"!all", "!root", "!#0"} for item in rule.runas_users)


def analyze_sudo_rules(
    rules: list[SudoRule],
    *,
    gtfobins_context: dict[str, list[str]] | None = None,
    gtfobins_details: dict[str, list[dict]] | None = None,
) -> list[Finding]:
    scoring = ScoringEngine()
    types = load_yaml("binary_types.yaml")
    high_utility = {item for group in types.values() if isinstance(group, list) for item in group}
    vectors = gtfobins_context or {}
    detail_vectors = gtfobins_details or {}
    findings: list[Finding] = []

    for rule in rules:
        wildcard_vectors = sudo_wildcard_vectors(rule)
        details = detail_vectors.get(rule.canonical, [])
        techniques = sorted(
            set(vectors.get(rule.canonical, []))
            | {str(item.get("function")) for item in details if item.get("function")}
        )
        if not details:
            details = [{"function": item, "source_context": "sudo"} for item in techniques]
        blocked_functions = (
            sorted(set(techniques) & NOEXEC_BLOCKED_FUNCTIONS) if rule.noexec else []
        )
        actionable_details = [
            detail
            for detail in details
            if str(detail.get("function")) not in blocked_functions
        ]
        if rule.restricted:
            # A binary-level match does not prove that generic GTFOBins syntax
            # fits a restricted sudo rule. Only maintained argument routes are
            # actionable in that case.
            actionable_details = []
        if rule.negated:
            actionable_details = []
        actionable_techniques = sorted(set(techniques) - set(blocked_functions))
        privileged = _privileged_runas(rule)
        root_excluded = _root_excluded(rule)
        custom = unusual_location(rule.binary_path)
        custom_root_nopasswd = (
            not rule.negated
            and privileged
            and rule.nopasswd
            and custom
            and not rule.restricted
        )
        components = []
        reasons: list[str] = []
        checks: list[str] = []

        if rule.negated:
            classification = "manual_review"
            components.append(scoring.component("negated_rule", "Negated sudo rule"))
            reasons.append("Negated rule; retained for policy context")
        elif wildcard_vectors:
            classification = "sudo_wildcard_injection"
        elif actionable_techniques and not rule.restricted and not blocked_functions:
            classification = "direct_gtfo"
        elif techniques and (rule.restricted or blocked_functions):
            classification = "restricted_gtfo"
        elif custom_root_nopasswd:
            classification = "custom_root_nopasswd"
        elif custom or rule.wildcards or rule.canonical in high_utility:
            classification = "manual_review"
        else:
            classification = "no_gtfo_match"

        if privileged:
            components.append(scoring.component("runas_privileged", "RunAs root/ALL"))
            reasons.append("Rule permits a privileged RunAs identity")
        if root_excluded:
            reasons.append(
                "RunAs explicitly excludes root; sudo version and alternate identities require review"
            )
        if rule.nopasswd:
            components.append(scoring.component("nopasswd", "NOPASSWD sudo rule"))
            reasons.append("No sudo password prompt is required by this rule")
        if techniques and not rule.negated:
            components.append(scoring.component("gtfo_current_context", "GTFOBins sudo technique"))
            reasons.append("Known GTFOBins technique for the sudo context")
        if blocked_functions:
            reasons.append("NOEXEC blocks techniques that require launching another program")
        if rule.restricted:
            components.append(scoring.component("restricted_arguments", "Command arguments restrict direct use"))
            reasons.append("Arguments may prevent direct use of a known technique")
        else:
            components.append(scoring.component("unrestricted_sudo", "Command arguments unrestricted"))
            reasons.append("The sudo rule does not restrict command arguments")
        if rule.wildcards:
            components.append(scoring.component("wildcard_arguments", "Wildcard in sudo rule"))
            reasons.append("Wildcard semantics require manual review")
        if wildcard_vectors:
            reasons.append("The tar rule contains a wildcard injection pattern that requires manual validation")
        if rule.canonical in high_utility:
            components.append(scoring.component("high_utility", "High-utility binary"))
            reasons.append("Interpreter, editor, archive, package, or service utility")
        if custom:
            components.append(scoring.component("custom_binary", "Custom sudo binary location"))
            reasons.append("Sudo command is in a location commonly used for custom software")
            checks = suggested_sudo_checks(rule.binary_path)
        if custom_root_nopasswd:
            components.append(
                scoring.component(
                    "custom_unrestricted_nopasswd_root",
                    "Unrestricted custom command as root without a password",
                )
            )
            reasons.append(
                "High-risk combination: custom command can run as root without a password or argument restriction"
            )

        metadata = {
            "command": rule.command,
            "runas_users": rule.runas_users,
            "runas_groups": rule.runas_groups,
            "nopasswd": rule.nopasswd,
            "arguments": rule.arguments,
            "wildcards": rule.wildcards,
            "negated": rule.negated,
            "restricted": rule.restricted,
            "noexec": rule.noexec,
            "tags": rule.tags,
            "digest": rule.digest,
            "blocked_functions": blocked_functions,
            "root_excluded": root_excluded,
            "argument_vectors": [item["id"] for item in wildcard_vectors],
            "wildcard_injection": bool(wildcard_vectors),
        }
        findings.append(
            Finding(
                source="sudo",
                path=rule.binary_path,
                basename=rule.basename,
                canonical=rule.canonical,
                classification=classification,
                score_components=components,
                reasons=reasons,
                suggested_checks=checks,
                actions=(
                    []
                    if wildcard_vectors
                    else build_actions(
                        actionable_details, source="sudo", canonical=rule.canonical, metadata=metadata
                    )
                ),
                gtfobins={
                    "match": bool(techniques) and not rule.negated,
                    "context": "sudo",
                    "match_type": (
                        "sudoers-wildcard-candidate"
                        if wildcard_vectors
                        else "exact-context"
                        if techniques
                        else None
                    ),
                    "techniques": [] if wildcard_vectors else techniques,
                    "other_functions": [],
                    "blocked_functions": blocked_functions,
                    "selection_basis": (
                        "PrivScout detected a tar wildcard pattern but did not assert a GTFOBins command for the restricted arguments."
                        if wildcard_vectors
                        else "GTFOBins explicitly lists the selected functions for its sudo context."
                        if techniques
                        else None
                    ),
                    "reference": f"https://gtfobins.github.io/gtfobins/{rule.canonical}/",
                },
                metadata=metadata,
            )
        )
    return sorted(findings, key=lambda item: (-item.score, item.path))
