from __future__ import annotations

import re

from .anomaly import suggested_binary_checks, unusual_location
from .baseline import SuidBaseline
from .data_loader import load_yaml
from .guidance import build_actions
from .scoring import ScoringEngine
from .third_party import ThirdPartyDataset, third_party_checks
from ..models.binary import BinaryIdentity
from ..models.finding import Finding

_SNAP_PATH = re.compile(r"^/snap/[^/]+/[^/]+/(?P<relative>.+)$")


def _collapse_snap_revisions(findings: list[Finding]) -> list[Finding]:
    """Collapse equivalent files repeated by mounted Snap revisions."""
    grouped: dict[tuple[str, str, str, int], Finding] = {}
    result: list[Finding] = []
    for finding in findings:
        match = _SNAP_PATH.match(finding.path)
        if not match:
            result.append(finding)
            continue
        key = (
            finding.canonical,
            match.group("relative"),
            finding.classification,
            finding.score,
        )
        existing = grouped.get(key)
        if existing is None:
            finding.metadata["occurrences"] = 1
            finding.metadata["paths"] = [finding.path]
            grouped[key] = finding
            result.append(finding)
            continue
        paths = existing.metadata.setdefault("paths", [existing.path])
        paths.append(finding.path)
        existing.metadata["occurrences"] = len(paths)
    return result


def analyze_suid_binaries(
    binaries: list[BinaryIdentity],
    *,
    gtfobins_context: dict[str, list[str]] | None = None,
    gtfobins_details: dict[str, list[dict]] | None = None,
    third_party_dataset: ThirdPartyDataset | None = None,
) -> list[Finding]:
    baseline = SuidBaseline()
    scoring = ScoringEngine()
    types = load_yaml("binary_types.yaml")
    high_utility = {item for group in types.values() if isinstance(group, list) for item in group}
    vectors = gtfobins_context or {}
    detail_vectors = gtfobins_details or {}
    third_party_dataset = third_party_dataset or ThirdPartyDataset()
    findings: list[Finding] = []

    for binary in binaries:
        details = detail_vectors.get(binary.canonical, [])
        techniques = sorted(
            set(vectors.get(binary.canonical, []))
            | {str(item.get("function")) for item in details if item.get("function")}
        )
        if not details:
            details = [{"function": item, "source_context": "suid"} for item in techniques]
        classification = baseline.classification(
            binary.canonical,
            binary.path,
            known_context_vector=bool(techniques),
        )
        components = [scoring.component("suid_present", "SUID bit present")]
        reasons: list[str] = []
        checks: list[str] = []
        third_party = third_party_dataset.match(binary)
        if not third_party and classification == "unknown_custom" and not techniques:
            third_party = third_party_dataset.match_heuristic(binary)

        if techniques:
            components.append(scoring.component("gtfo_current_context", "GTFOBins SUID technique"))
            reasons.append("Known GTFOBins technique for the SUID context")
        if classification == "common":
            components.append(scoring.component("expected_suid", "Common SUID baseline"))
            reasons.append("Common SUID baseline entry (not a safety guarantee)")
        elif classification == "unknown_custom":
            components.append(scoring.component("unknown_custom", "Unknown/custom SUID binary"))
            reasons.append("Custom or uncommon SUID binary")
            checks = suggested_binary_checks(binary.path)
            if third_party:
                product_checks = third_party_checks(third_party, binary.path)
                checks = list(dict.fromkeys([*product_checks, *checks]))
        if binary.canonical in high_utility:
            components.append(scoring.component("high_utility", "High-utility binary"))
            reasons.append("General-purpose or high-utility binary")
        if unusual_location(binary.path):
            components.append(scoring.component("unusual_location", "Unusual binary location"))
            reasons.append("Binary is in a location commonly used for custom software")

        metadata = {"baseline": classification}
        findings.append(
            Finding(
                source="suid",
                path=binary.path,
                basename=binary.basename,
                canonical=binary.canonical,
                classification=classification,
                score_components=components,
                reasons=reasons,
                suggested_checks=checks,
                actions=build_actions(
                    details,
                    source="suid",
                    canonical=binary.canonical,
                    metadata=metadata,
                ),
                gtfobins={
                    "match": bool(techniques),
                    "context": "suid",
                    "match_type": "exact-context" if techniques else None,
                    "techniques": techniques,
                    "selection_basis": (
                        "GTFOBins explicitly lists the selected functions for its SUID context."
                        if techniques
                        else None
                    ),
                    "reference": f"https://gtfobins.github.io/gtfobins/{binary.canonical}/",
                },
                third_party=third_party,
                metadata=metadata,
            )
        )
    collapsed = _collapse_snap_revisions(findings)
    return sorted(collapsed, key=lambda item: (-item.score, item.path))
