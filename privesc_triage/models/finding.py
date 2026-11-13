from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..output.i18n import (
    Language,
    classification_label,
    localized_action,
    localized_gtfobins,
    localized_metadata,
    localized_third_party,
    severity_label,
    source_label,
    translate_text,
)


def severity_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "low"
    return "info"


@dataclass(frozen=True, slots=True)
class ScoreComponent:
    delta: int
    label: str

    def to_dict(self, *, language: Language = "en") -> dict[str, Any]:
        result = asdict(self)
        result["label"] = translate_text(self.label, language)
        return result


@dataclass(slots=True)
class Finding:
    source: str
    path: str
    basename: str
    canonical: str
    classification: str
    score_components: list[ScoreComponent] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    suggested_checks: list[str] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    gtfobins: dict[str, Any] = field(default_factory=dict)
    third_party: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def raw_score(self) -> int:
        return sum(component.delta for component in self.score_components)

    @property
    def score(self) -> int:
        return max(0, min(100, self.raw_score))

    @property
    def severity(self) -> str:
        return severity_for_score(self.score)

    def to_dict(
        self, *, explain: bool = False, language: Language = "en"
    ) -> dict[str, Any]:
        metadata = localized_metadata(self.metadata, language)
        result: dict[str, Any] = {
            "score": self.score,
            "severity": self.severity,
            "severity_label": severity_label(self.severity, language),
            "source": self.source,
            "source_label": source_label(self.source, language),
            "path": self.path,
            "basename": self.basename,
            "canonical": self.canonical,
            "classification": self.classification,
            "classification_label": classification_label(self.classification, language),
            "gtfobins": localized_gtfobins(self.gtfobins, language),
            "third_party": localized_third_party(self.third_party, language),
            "reasons": [translate_text(reason, language) for reason in self.reasons],
            "suggested_checks": self.suggested_checks,
            "actions": [localized_action(action, language) for action in self.actions],
            "metadata": metadata,
        }
        if explain:
            result["score_components"] = [
                item.to_dict(language=language) for item in self.score_components
            ]
            result["raw_score"] = self.raw_score
        if self.source == "capability":
            result["capabilities"] = metadata.get("capabilities", [])
        elif self.source == "sudo":
            result.update(
                {
                    "runas_users": metadata.get("runas_users", []),
                    "runas_groups": metadata.get("runas_groups", []),
                    "nopasswd": metadata.get("nopasswd", False),
                    "arguments": metadata.get("arguments", []),
                    "wildcards": metadata.get("wildcards", False),
                    "negated": metadata.get("negated", False),
                    "noexec": metadata.get("noexec", False),
                    "tags": metadata.get("tags", []),
                    "digest": metadata.get("digest"),
                }
            )
        return result
