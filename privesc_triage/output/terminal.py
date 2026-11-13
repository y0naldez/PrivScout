from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models.finding import Finding
from .i18n import (
    Language,
    classification_label,
    localized_action,
    localized_metadata,
    severity_label,
    source_label,
    tr,
    translate_text,
)

SEVERITY_STYLES = {
    "critical": "bold bright_red",
    "high": "red",
    "suspicious": "yellow",
    "low": "cyan",
    "info": "dim",
}

MAX_ACTIONS = 3


def _summary_line(
    label: str, found: int, shown: int, language: Language
) -> str:
    if language == "es":
        found_word = "encontrado" if found == 1 else "encontrados"
        shown_word = "mostrado" if shown == 1 else "mostrados"
        return f"{label:<14} {found:>4} {found_word:<11} {shown:>4} {shown_word}"
    return tr("found_shown", language, label=label, found=found, shown=shown)


def _footer(shown: int, total: int, language: Language) -> str:
    if language == "es":
        finding_word = "hallazgo" if shown == 1 else "hallazgos"
        entry_word = "entrada" if total == 1 else "entradas"
        return f"Mostrando {shown} {finding_word} de {total} {entry_word}."
    return tr("showing", language, shown=shown, total=total)

def gtfobins_text(
    *,
    available: bool,
    match_type: str | None = None,
    custom_review: bool = False,
    language: Language = "en",
) -> Text:
    """Reserve green for exact GTFOBins contexts; capability correlations are inferred."""
    if match_type == "sudoers-wildcard-candidate":
        return Text(tr("gtfo_wildcard", language), style="yellow")
    if available:
        if match_type == "capability-assisted":
            return Text(tr("gtfo_assisted", language), style="cyan")
        return Text(tr("gtfo_exact", language), style="bold green")
    if custom_review:
        return Text(tr("gtfo_custom", language), style="dim")
    return Text(tr("gtfo_no_match", language), style="dim")


def render_findings(
    findings: list[Finding],
    *,
    total: int,
    explain: bool = False,
    no_color: bool = False,
    title: str = "SUID",
    counts: dict[str, int] | None = None,
    language: Language = "en",
) -> None:
    console = Console(color_system=None if no_color else "auto", no_color=no_color)
    if counts is None:
        summary = _summary_line(title, total, len(findings), language)
    else:
        shown_counts = {source: sum(item.source == source for item in findings) for source in counts}
        summary = "\n".join(
            _summary_line(
                source_label(source, language), count, shown_counts[source], language
            )
            for source, count in counts.items()
        )
    console.print(Panel(summary, title="PrivScout", border_style="cyan"))
    if not findings:
        console.print(tr("no_findings", language), style="dim")
        return

    console.print(tr("priority_findings", language), style="bold cyan")
    correlated = [finding for finding in findings if finding.gtfobins.get("match")]
    third_party = [
        finding
        for finding in findings
        if not finding.gtfobins.get("match")
        and finding.third_party.get("match")
        and finding.third_party.get("match_type") != "heuristic-exploit-title"
    ]
    heuristic = [
        finding
        for finding in findings
        if not finding.gtfobins.get("match")
        and finding.third_party.get("match_type") == "heuristic-exploit-title"
    ]
    manual_review = [
        finding
        for finding in findings
        if not finding.gtfobins.get("match") and not finding.third_party.get("match")
    ]
    ordered_findings = [*correlated, *third_party, *heuristic, *manual_review]
    previous_group: str | None = None
    for finding in ordered_findings:
        if finding.gtfobins.get("match"):
            group = "gtfo_matches"
        elif finding.third_party.get("match_type") == "heuristic-exploit-title":
            group = "heuristic_findings"
        elif finding.third_party.get("match"):
            group = "third_party_findings"
        else:
            group = "manual_review_findings"
        if group != previous_group:
            counts_by_group = {
                "gtfo_matches": len(correlated),
                "third_party_findings": len(third_party),
                "heuristic_findings": len(heuristic),
                "manual_review_findings": len(manual_review),
            }
            styles_by_group = {
                "gtfo_matches": "bold green",
                "third_party_findings": "bold magenta",
                "heuristic_findings": "bold yellow",
                "manual_review_findings": "bold yellow",
            }
            console.print(
                tr(group, language, count=counts_by_group[group]),
                style=styles_by_group[group],
            )
            previous_group = group
        metadata = localized_metadata(finding.metadata, language)
        heading = Text()
        heading.append(
            f"{finding.score:>3}  {severity_label(finding.severity, language):<10} ",
            SEVERITY_STYLES[finding.severity],
        )
        heading.append(finding.path, "bold")
        console.print(heading)
        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim")
        table.add_column()
        source = source_label(finding.source, language)
        if finding.source == "suid" and finding.third_party.get("match"):
            source = tr("suid_observed", language)
        table.add_row(tr("source", language), source)
        table.add_row(tr("canonical", language), finding.canonical)
        table.add_row(tr("class", language), classification_label(finding.classification, language))
        if finding.third_party.get("match"):
            heuristic_match = (
                finding.third_party.get("match_type") == "heuristic-exploit-title"
            )
            product = str(finding.third_party.get("product") or (
                "not confirmed" if language == "en" else "no confirmado"
            ))
            confidence = finding.third_party.get("confidence")
            if confidence == "probable-path":
                product += " (probable by path)" if language == "en" else " (probable por ruta)"
            owner = "unconfirmed" if language == "en" else "sin confirmar"
            software_type = (
                "unconfirmed" if language == "en" else "sin confirmar"
            ) if heuristic_match else (
                "third-party software" if language == "en" else "software de terceros"
            )
            version = finding.third_party.get("version") or (
                "not detected" if language == "en" else "no detectada"
            )
            exploits = finding.third_party.get("exploitdb", [])
            if heuristic_match:
                if language == "en":
                    exploit_text = f"{len(exploits)} heuristic name " + (
                        "match" if len(exploits) == 1 else "matches"
                    )
                else:
                    exploit_text = f"{len(exploits)} " + (
                        "coincidencia heurística por nombre"
                        if len(exploits) == 1
                        else "coincidencias heurísticas por nombre"
                    )
            else:
                exploit_text = (
                    f"{len(exploits)} related candidates"
                    if language == "en"
                    else f"{len(exploits)} candidatos relacionados"
                )
            vulnerabilities = finding.third_party.get("vulnerabilities", [])
            cve_ids = ", ".join(
                str(item.get("id")) for item in vulnerabilities if item.get("id")
            )
            if heuristic_match:
                if cve_ids:
                    multiple_cves = len(vulnerabilities) != 1
                    cve_text = (
                        f"{cve_ids} related through those exploits"
                        if language == "en"
                        else f"{cve_ids} "
                        + (
                            "relacionados con esos exploits"
                            if multiple_cves
                            else "relacionado con esos exploits"
                        )
                    )
                else:
                    cve_text = (
                        "no associated CVE in the offline data"
                        if language == "en"
                        else "sin CVE asociado en los datos offline"
                    )
            else:
                cve_text = f"{cve_ids} possible" if language == "en" else f"{cve_ids} posible"
            table.add_row(tr("owner", language), owner)
            table.add_row(tr("product", language), product)
            table.add_row(tr("software_type", language), software_type)
            table.add_row(tr("version", language), str(version))
            if heuristic_match:
                table.add_row(
                    tr("confidence", language),
                    "low" if language == "en" else "baja",
                )
        if finding.source == "sudo":
            runas_users = metadata.get("runas_users", [])
            table.add_row(tr("runas", language), ", ".join(runas_users))
            nopasswd = bool(metadata.get("nopasswd"))
            table.add_row("NOPASSWD", tr("yes" if nopasswd else "no", language))
            if metadata.get("noexec"):
                table.add_row("NOEXEC", tr("yes", language))
            arguments = metadata.get("arguments", [])
            if arguments == [""]:
                argument_text = tr("no_arguments", language)
            elif arguments:
                argument_text = " ".join(arguments)
            else:
                argument_text = tr("unrestricted", language)
            table.add_row(tr("arguments", language), argument_text)
            blocked_functions = metadata.get("blocked_functions", [])
            if blocked_functions:
                table.add_row(
                    tr("blocked_functions", language),
                    ", ".join(str(item) for item in blocked_functions),
                )
        if finding.source == "capability":
            table.add_row(tr("capability", language), ", ".join(metadata.get("capability_specs", [])))
            contextual_techniques = metadata.get("contextual_techniques", [])
            if contextual_techniques:
                table.add_row(
                    tr("supported_actions", language),
                    ", ".join(str(item) for item in contextual_techniques),
                )
            contextual_basis = metadata.get("contextual_selection_basis")
            if contextual_basis:
                table.add_row(tr("action_basis", language), str(contextual_basis))
        gtfo_match = bool(finding.gtfobins.get("match"))
        match_type = finding.gtfobins.get("match_type")
        custom_review = finding.classification == "custom_root_nopasswd"
        table.add_row(
            "GTFOBins",
            gtfobins_text(
                available=gtfo_match,
                match_type=str(match_type) if match_type else None,
                custom_review=custom_review,
                language=language,
            ),
        )
        if finding.third_party.get("match"):
            table.add_row(tr("exploitdb", language), exploit_text)
            table.add_row(tr("cve", language), cve_text)
            table.add_row(
                tr("applicability", language),
                str(
                    finding.third_party.get(
                        "applicability_es" if language == "es" else "applicability", ""
                    )
                ),
            )
            table.add_row(
                tr("recommendation", language),
                str(
                    finding.third_party.get(
                        "recommendation_es" if language == "es" else "recommendation", ""
                    )
                ),
            )
        occurrences = int(metadata.get("occurrences", 1))
        if occurrences > 1:
            table.add_row(tr("occurrences", language), str(occurrences))
            other_paths = metadata.get("paths", [])[1:]
            table.add_row(tr("also_seen", language), "\n".join(str(path) for path in other_paths))
        techniques = finding.gtfobins.get("techniques", [])
        if gtfo_match and techniques:
            table.add_row(tr("techniques", language), ", ".join(str(item) for item in techniques))
            selection_basis = finding.gtfobins.get("selection_basis")
            if selection_basis:
                table.add_row(
                    tr("selection_basis", language),
                    translate_text(str(selection_basis), language),
                )
            other_functions = finding.gtfobins.get("other_functions", [])
            if other_functions:
                table.add_row(
                    tr("not_promoted", language),
                    ", ".join(str(item) for item in other_functions)
                    + f" ({tr('not_elevated', language)})",
                )
        if explain:
            for reason in finding.reasons:
                table.add_row(tr("reason", language), translate_text(reason, language))
        console.print(table)
        if finding.suggested_checks:
            console.print(tr("inspect_next", language), style="dim")
            for check in finding.suggested_checks:
                console.print(f"    {check}")
        if finding.actions:
            actions = [localized_action(item, language) for item in finding.actions]
            console.print(tr("context_actions", language), style="bold")
            for index, action in enumerate(actions[:MAX_ACTIONS], 1):
                console.print(f"    {index}. {action.get('title', action.get('function', 'Review'))}")
                description = action.get("description")
                if description:
                    console.print(f"       {description}", style="dim")
                why = action.get("why")
                if why:
                    console.print(f"       {tr('why', language)}: {why}")
                source = action.get("source")
                if source:
                    console.print(f"       {tr('action_source', language)}: {source}", style="dim")
                command = action.get("command")
                if command:
                    command_label = "gtfo_command" if source == "GTFOBins" else "suggested_command"
                    console.print(f"       {tr(command_label, language)}", style="dim")
                    for line in str(command).splitlines():
                        console.print(Text(f"         {line}"))
                for note in action.get("notes", []):
                    console.print(f"       {tr('note', language)}: {note}", style="dim")
                if source != "GTFOBins" and action.get("reference"):
                    console.print(
                        f"       {tr('action_reference', language)}: {action['reference']}",
                        style="dim",
                    )
            remaining = len(actions) - MAX_ACTIONS
            if remaining > 0:
                console.print(
                    tr("additional_action" if remaining == 1 else "additional_actions", language, count=remaining),
                    style="dim",
                )
            reference = finding.gtfobins.get("reference") or actions[0].get("reference")
            if reference:
                console.print(tr("visit_gtfo", language, reference=reference), style="dim")
        if explain:
            console.print(tr("score_explanation", language), style="dim")
            for component in finding.score_components:
                console.print(f"    {component.delta:+d} {translate_text(component.label, language)}")
            rule_character = "-" if no_color else "─"
            console.print(
                f"    {rule_character * 28}\n    {finding.score}",
                style=SEVERITY_STYLES[finding.severity],
            )
        console.print()
    console.print(_footer(len(findings), total, language), style="dim")


def render_suid(
    findings: list[Finding], *, total: int, explain: bool, no_color: bool, language: Language = "en"
) -> None:
    render_findings(
        findings, total=total, explain=explain, no_color=no_color, title="SUID", language=language
    )


def render_sudo(
    findings: list[Finding], *, total: int, explain: bool, no_color: bool, language: Language = "en"
) -> None:
    render_findings(
        findings, total=total, explain=explain, no_color=no_color, title="sudo", language=language
    )


def render_capabilities(
    findings: list[Finding], *, total: int, explain: bool, no_color: bool, language: Language = "en"
) -> None:
    render_findings(
        findings,
        total=total,
        explain=explain,
        no_color=no_color,
        title="Capabilities",
        language=language,
    )


def render_analysis(
    findings: list[Finding],
    *,
    total: int,
    counts: dict[str, int],
    explain: bool,
    no_color: bool,
    language: Language = "en",
) -> None:
    render_findings(
        findings,
        total=total,
        explain=explain,
        no_color=no_color,
        title="All sources",
        counts=counts,
        language=language,
    )
