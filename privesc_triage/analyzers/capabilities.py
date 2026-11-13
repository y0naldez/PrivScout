from __future__ import annotations

from .anomaly import suggested_binary_checks, unusual_location
from .baseline import matches_expected_path
from .data_loader import load_yaml
from .guidance import (
    build_actions,
    capability_assisted_techniques,
    capability_specific_actions,
)
from .scoring import ScoringEngine
from ..models.capability import CapabilityRecord
from ..models.finding import Finding, ScoreComponent


def _required_capabilities(technique: dict) -> set[str]:
    context_details = technique.get("context_details", {})
    if not isinstance(context_details, dict):
        return set()
    required = context_details.get("list", [])
    if not isinstance(required, list):
        return set()
    return {str(item).lower() for item in required if str(item).lower().startswith("cap_")}


def _applicable_exact_details(
    details: list[dict], capability_names: set[str]
) -> list[dict]:
    applicable: list[dict] = []
    for technique in details:
        if technique.get("legacy_function_only"):
            continue
        required = _required_capabilities(technique)
        if required and not required.issubset(capability_names):
            continue
        enriched = dict(technique)
        if required:
            enriched["required_capabilities"] = sorted(required)
        applicable.append(enriched)
    return applicable


def analyze_capability_records(
    records: list[CapabilityRecord],
    *,
    gtfobins_context: dict[str, list[str]] | None = None,
    gtfobins_details: dict[str, list[dict]] | None = None,
    gtfobins_unprivileged: dict[str, list[dict]] | None = None,
) -> list[Finding]:
    scoring = ScoringEngine()
    semantics = load_yaml("linux_capabilities.yaml")
    risk_data = load_yaml("capability_risk.yaml")
    expected_data = load_yaml("expected_capabilities.yaml")
    binary_types = load_yaml("binary_types.yaml")
    high_utility = {
        item for group in binary_types.values() if isinstance(group, list) for item in group
    }
    vectors = gtfobins_context or {}
    detail_vectors = gtfobins_details or {}
    unprivileged_vectors = gtfobins_unprivileged or {}
    findings: list[Finding] = []

    for record in records:
        names = {grant.name for grant in record.capabilities}
        effective_names = {
            grant.name for grant in record.capabilities if grant.effective
        }
        risk_entries = [risk_data.get(name, {}) for name in names]
        maximum = max(risk_entries, key=lambda item: int(item.get("base_score", 0)), default={})
        base_score = int(maximum.get("base_score", 0))
        risk = str(maximum.get("risk", "unknown"))
        expected = expected_data.get(record.canonical, {})
        expected_names = set(expected.get("capabilities", [])) if isinstance(expected, dict) else set()
        configured_sets = expected.get("capability_sets", []) if isinstance(expected, dict) else []
        expected_name_sets = [
            {str(name) for name in combination}
            for combination in configured_sets
            if isinstance(combination, list)
        ]
        if expected_names:
            expected_name_sets.append(expected_names)
        expected_paths = expected.get("paths", []) if isinstance(expected, dict) else []
        required_flags = expected.get("required_flags") if isinstance(expected, dict) else None
        flags_match = required_flags is None or all(
            grant.flags == required_flags for grant in record.capabilities
        )
        raw_exact_details = detail_vectors.get(record.canonical, [])
        exact_details = _applicable_exact_details(raw_exact_details, effective_names)
        # Function-only indexes predate capability requirements. Retain them
        # only when no detailed index was supplied by the caller.
        legacy_functions = set(vectors.get(record.canonical, [])) if not detail_vectors else set()
        exact_functions = legacy_functions | {
            str(item.get("function")) for item in exact_details if item.get("function")
        }
        if not exact_details:
            exact_details = [
                {"function": item, "source_context": "capabilities"}
                for item in sorted(exact_functions)
            ]
        assisted_details = capability_assisted_techniques(
            effective_names, unprivileged_vectors.get(record.canonical, [])
        )
        documented_unprivileged_functions = {
            str(item.get("function"))
            for item in unprivileged_vectors.get(record.canonical, [])
            if item.get("function")
        }
        details = [*exact_details, *assisted_details]
        techniques = sorted(
            exact_functions
            | {str(item.get("function")) for item in assisted_details if item.get("function")}
        )
        specific_actions = capability_specific_actions(record.canonical, effective_names)
        specific_functions = {
            str(item.get("function")) for item in specific_actions if item.get("function")
        }
        supported_functions = set(techniques) | specific_functions
        is_expected = (
            bool(expected_name_sets)
            and names in expected_name_sets
            and matches_expected_path(record.path, expected_paths)
            and flags_match
        )
        custom = unusual_location(record.path)

        components = [ScoreComponent(base_score, f"Highest capability risk ({risk})")]
        reasons: list[str] = []
        checks: list[str] = []
        if base_score:
            reasons.append(f"Highest capability risk is {risk}")
        if any(grant.effective and grant.permitted for grant in record.capabilities):
            components.append(scoring.component("effective_permitted", "Effective and permitted flags"))
            reasons.append("Capability is effective and permitted")
        if names and not effective_names:
            reasons.append(
                "No capability is effective; direct abuse depends on additional process state"
            )
        if is_expected:
            if supported_functions:
                reasons.append(
                    "Expected package combination, but a context-supported technique prevents suppression"
                )
            else:
                modifier = int(expected.get("score_modifier", 0))
                components.append(ScoreComponent(modifier, "Expected binary/capability combination"))
                reasons.append("Known expected combination; common does not mean safe")
        else:
            components.append(scoring.component("unexpected_capability", "Unusual capability combination"))
            reasons.append("Binary/capability combination is not in the expected baseline")
        if record.canonical in high_utility:
            components.append(scoring.component("high_utility", "General-purpose/high-utility binary"))
            reasons.append("General-purpose binary increases capability utility")
        if supported_functions:
            if specific_actions and not techniques:
                components.append(
                    scoring.component(
                        "contextual_capability",
                        "Capability-specific operation supported by this binary",
                    )
                )
                reasons.append(
                    "The binary directly exposes an operation governed by the assigned capability"
                )
            else:
                components.append(
                    scoring.component("gtfo_capability", "GTFOBins capability technique")
                )
            if techniques and assisted_details and not exact_functions:
                reasons.append(
                    "A file capability directly strengthens an unprivileged GTFOBins technique"
                )
            elif techniques:
                reasons.append("Known GTFOBins technique for the capabilities context")
        if custom:
            components.append(scoring.component("custom_binary", "Custom binary"))
            components.append(scoring.component("unusual_location", "Unusual binary location"))
            reasons.append("Custom or locally installed binary with file capabilities")
            checks = suggested_binary_checks(record.path)

        if supported_functions:
            classification = "known_vector"
        elif is_expected:
            classification = "expected_combination"
        elif custom:
            classification = "custom_unusual"
        else:
            classification = "capability_review"

        capability_metadata = []
        for grant in record.capabilities:
            semantic = semantics.get(grant.name, {})
            risk_entry = risk_data.get(grant.name, {})
            capability_metadata.append(
                {
                    "name": grant.name,
                    "flags": grant.flags,
                    "effective": grant.effective,
                    "permitted": grant.permitted,
                    "inheritable": grant.inheritable,
                    "category": semantic.get("category", "unknown"),
                    "description": semantic.get("description", "Unknown capability"),
                    "description_es": semantic.get(
                        "description_es", semantic.get("description", "Capability desconocida")
                    ),
                    "risk": risk_entry.get("risk", "unknown"),
                    "base_score": int(risk_entry.get("base_score", 0)),
                }
            )
        metadata = {
            "capabilities": capability_metadata,
            "capability_specs": [f"{grant.name}={grant.flags}" for grant in record.capabilities],
            "effective_capabilities": sorted(effective_names),
            "expected": is_expected,
            "expected_source": expected.get("source") if isinstance(expected, dict) else None,
            "contextual_techniques": sorted(supported_functions),
            "contextual_selection_basis": (
                "A maintained binary-specific rule maps the observed capability to an operation "
                "the binary directly exposes."
                if specific_actions
                else None
            ),
        }
        match_type = None
        if exact_functions:
            match_type = "exact-context"
        elif assisted_details:
            match_type = "capability-assisted"
        if match_type == "exact-context":
            selection_basis = (
                "GTFOBins explicitly lists the selected functions for its capabilities context."
            )
        elif match_type == "capability-assisted":
            selection_basis = (
                "PrivScout intersected the observed Linux capability semantics with GTFOBins' "
                "unprivileged functions and retained only directly strengthened operations."
            )
        else:
            selection_basis = None
        actions = [
            *build_actions(
                details,
                source="capability",
                canonical=record.canonical,
                metadata=metadata,
            ),
            *specific_actions,
        ]
        actions.sort(key=lambda item: (int(item.get("priority", 100)), str(item.get("function", ""))))
        findings.append(
            Finding(
                source="capability",
                path=record.path,
                basename=record.basename,
                canonical=record.canonical,
                classification=classification,
                score_components=components,
                reasons=reasons,
                suggested_checks=checks,
                actions=actions,
                gtfobins={
                    "match": bool(techniques),
                    "context": "capabilities",
                    "match_type": match_type,
                    "techniques": techniques,
                    "selection_basis": selection_basis,
                    "other_functions": sorted(documented_unprivileged_functions - set(techniques)),
                    "reference": f"https://gtfobins.github.io/gtfobins/{record.canonical}/",
                },
                metadata=metadata,
            )
        )
    return sorted(findings, key=lambda item: (-item.score, item.path))
