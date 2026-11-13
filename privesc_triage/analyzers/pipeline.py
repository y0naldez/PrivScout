from __future__ import annotations

from dataclasses import dataclass

from .capabilities import analyze_capability_records
from .gtfobins import GTFOBinsDataset
from .suid import analyze_suid_binaries
from .sudo import analyze_sudo_rules
from ..models.report import AnalysisReport
from ..parsers.autodetect import ParsedEnumeration, parse_enumeration


@dataclass(slots=True)
class PipelineResult:
    report: AnalysisReport
    parsed: ParsedEnumeration
    dataset_metadata: dict


def analyze_enumeration(text: str, dataset: GTFOBinsDataset | None = None) -> PipelineResult:
    dataset = dataset or GTFOBinsDataset()
    parsed = parse_enumeration(text)
    findings = [
        *analyze_suid_binaries(
            parsed.suid,
            gtfobins_context=dataset.context_index("suid"),
            gtfobins_details=dataset.technique_details_index("suid"),
        ),
        *analyze_sudo_rules(
            parsed.sudo,
            gtfobins_context=dataset.context_index("sudo"),
            gtfobins_details=dataset.technique_details_index("sudo"),
        ),
        *analyze_capability_records(
            parsed.capabilities,
            gtfobins_context=dataset.context_index("capabilities"),
            gtfobins_details=dataset.technique_details_index("capabilities"),
            gtfobins_unprivileged=dataset.technique_details_index("unprivileged"),
        ),
    ]
    return PipelineResult(AnalysisReport(findings), parsed, dataset.metadata)
