from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..output.i18n import Language
from .finding import Finding


@dataclass(slots=True)
class AnalysisReport:
    findings: list[Finding] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.findings.sort(key=lambda item: (-item.score, item.source, item.path))

    @property
    def total(self) -> int:
        return sum(int(item.metadata.get("occurrences", 1)) for item in self.findings)

    @property
    def counts(self) -> dict[str, int]:
        result = {"suid": 0, "sudo": 0, "capability": 0}
        for finding in self.findings:
            result[finding.source] = result.get(finding.source, 0) + int(
                finding.metadata.get("occurrences", 1)
            )
        return result

    def select(self, *, show_all: bool = False, min_score: int | None = None) -> list[Finding]:
        threshold = min_score if min_score is not None else (0 if show_all else 40)
        return [finding for finding in self.findings if finding.score >= threshold]

    def to_dict(
        self,
        *,
        show_all: bool = False,
        min_score: int | None = None,
        explain: bool = False,
        language: Language = "en",
    ) -> dict[str, Any]:
        selected = self.select(show_all=show_all, min_score=min_score)
        interesting = sum(finding.score >= 40 for finding in self.findings)
        return {
            "summary": {
                "total": self.total,
                "interesting": interesting,
                "shown": len(selected),
                "by_source": self.counts,
                "language": language,
            },
            "findings": [
                finding.to_dict(explain=explain, language=language) for finding in selected
            ],
        }
