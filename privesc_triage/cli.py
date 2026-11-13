from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Literal

import httpx
import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)

from . import __version__
from .analyzers.gtfobins import GTFOBinsDataset
from .analyzers.capabilities import analyze_capability_records
from .analyzers.pipeline import analyze_enumeration
from .analyzers.suid import analyze_suid_binaries
from .analyzers.sudo import analyze_sudo_rules
from .parsers.suid import parse_suid
from .parsers.sudo import parse_sudo
from .parsers.capabilities import parse_capabilities
from .output.terminal import render_analysis, render_capabilities, render_suid, render_sudo
from .output.i18n import Language
from .updater.all_sources import update_all

app = typer.Typer(
    name="privscout",
    help="Offline-first triage for authorized Linux privilege-escalation enumeration.",
    no_args_is_help=True,
)


def _read_input(file: str, language: Language = "en") -> str:
    if file == "-":
        return sys.stdin.read()
    try:
        return Path(file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        if language == "es":
            if isinstance(exc, FileNotFoundError):
                detail = "el archivo no existe"
            elif isinstance(exc, PermissionError):
                detail = "permiso denegado"
            else:
                detail = f"error del sistema {exc.errno or 'desconocido'}"
            message = f"No se pudo leer {file!r}: {detail}"
        else:
            message = f"Could not read {file!r}: {exc}"
        raise typer.BadParameter(message) from exc


def _emit_json(
    findings: list, total: int, explain: bool, language: Language = "en"
) -> None:
    payload = {
        "summary": {
            "total": total,
            "interesting": len(findings),
            "language": language,
        },
        "findings": [
            finding.to_dict(explain=explain, language=language) for finding in findings
        ],
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _observation_total(findings: list) -> int:
    return sum(int(item.metadata.get("occurrences", 1)) for item in findings)


def _diagnostic(language: Language, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


@app.command("suid")
def suid_command(
    file: Annotated[str, typer.Argument(help="SUID enumeration file, or '-' for stdin")],
    show_all: Annotated[bool, typer.Option("--show-all", help="Include expected and low-priority entries")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON instead of terminal output")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable ANSI colors")] = False,
    min_score: Annotated[int | None, typer.Option("--min-score", min=0, max=100)] = None,
    explain: Annotated[bool, typer.Option("--explain", help="Show score components")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show parser diagnostics")] = False,
    language: Annotated[
        Literal["en", "es"],
        typer.Option("--lang", help="Output language / Idioma de salida: en o es"),
    ] = "en",
) -> None:
    text = _read_input(file, language)
    binaries = parse_suid(text)
    dataset = GTFOBinsDataset()
    all_findings = analyze_suid_binaries(
        binaries,
        gtfobins_context=dataset.context_index("suid"),
        gtfobins_details=dataset.technique_details_index("suid"),
    )
    threshold = min_score if min_score is not None else (0 if show_all else 40)
    findings = [item for item in all_findings if item.score >= threshold]
    total = _observation_total(all_findings)
    if verbose:
        typer.echo(
            _diagnostic(
                language,
                f"Parsed {len(binaries)} SUID paths; threshold={threshold}",
                f"Se analizaron {len(binaries)} rutas SUID; umbral={threshold}",
            ),
            err=True,
        )
    if json_output:
        _emit_json(findings, total, explain, language)
    else:
        render_suid(
            findings, total=total, explain=explain, no_color=no_color, language=language
        )


@app.command("sudo")
def sudo_command(
    file: Annotated[str, typer.Argument(help="sudo -l output file, or '-' for stdin")],
    show_all: Annotated[bool, typer.Option("--show-all")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
    min_score: Annotated[int | None, typer.Option("--min-score", min=0, max=100)] = None,
    explain: Annotated[bool, typer.Option("--explain")] = False,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    language: Annotated[
        Literal["en", "es"],
        typer.Option("--lang", help="Output language / Idioma de salida: en o es"),
    ] = "en",
) -> None:
    rules = parse_sudo(_read_input(file, language))
    dataset = GTFOBinsDataset()
    all_findings = analyze_sudo_rules(
        rules,
        gtfobins_context=dataset.context_index("sudo"),
        gtfobins_details=dataset.technique_details_index("sudo"),
    )
    threshold = min_score if min_score is not None else (0 if show_all else 40)
    findings = [item for item in all_findings if item.score >= threshold]
    if verbose:
        typer.echo(
            _diagnostic(
                language,
                f"Parsed {len(rules)} sudo rules; threshold={threshold}",
                f"Se analizaron {len(rules)} reglas sudo; umbral={threshold}",
            ),
            err=True,
        )
    if json_output:
        _emit_json(findings, len(all_findings), explain, language)
    else:
        render_sudo(
            findings,
            total=len(all_findings),
            explain=explain,
            no_color=no_color,
            language=language,
        )


@app.command("caps")
def caps_command(
    file: Annotated[str, typer.Argument(help="getcap output file, or '-' for stdin")],
    show_all: Annotated[bool, typer.Option("--show-all")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
    min_score: Annotated[int | None, typer.Option("--min-score", min=0, max=100)] = None,
    explain: Annotated[bool, typer.Option("--explain")] = False,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    language: Annotated[
        Literal["en", "es"],
        typer.Option("--lang", help="Output language / Idioma de salida: en o es"),
    ] = "en",
) -> None:
    records = parse_capabilities(_read_input(file, language))
    dataset = GTFOBinsDataset()
    all_findings = analyze_capability_records(
        records,
        gtfobins_context=dataset.context_index("capabilities"),
        gtfobins_details=dataset.technique_details_index("capabilities"),
        gtfobins_unprivileged=dataset.technique_details_index("unprivileged"),
    )
    threshold = min_score if min_score is not None else (0 if show_all else 40)
    findings = [item for item in all_findings if item.score >= threshold]
    if verbose:
        typer.echo(
            _diagnostic(
                language,
                f"Parsed {len(records)} capability entries; threshold={threshold}",
                f"Se analizaron {len(records)} entradas de capabilities; umbral={threshold}",
            ),
            err=True,
        )
    if json_output:
        _emit_json(findings, len(all_findings), explain, language)
    else:
        render_capabilities(
            findings,
            total=len(all_findings),
            explain=explain,
            no_color=no_color,
            language=language,
        )


@app.command("analyze")
def analyze_command(
    file: Annotated[str, typer.Argument(help="Enumeration file, or '-' for stdin")],
    show_all: Annotated[bool, typer.Option("--show-all")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
    min_score: Annotated[int | None, typer.Option("--min-score", min=0, max=100)] = None,
    explain: Annotated[bool, typer.Option("--explain")] = False,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    language: Annotated[
        Literal["en", "es"],
        typer.Option("--lang", help="Output language / Idioma de salida: en o es"),
    ] = "en",
) -> None:
    result = analyze_enumeration(_read_input(file, language))
    findings = result.report.select(show_all=show_all, min_score=min_score)
    if verbose:
        updated = result.dataset_metadata.get("updated", "unknown")
        typer.echo(
            _diagnostic(
                language,
                f"Input lines={result.parsed.input_lines}; parsed entries={result.parsed.parsed_entries}; "
                f"GTFOBins updated={updated}",
                f"Líneas de entrada={result.parsed.input_lines}; entradas analizadas="
                f"{result.parsed.parsed_entries}; actualización de GTFOBins={updated}",
            ),
            err=True,
        )
    if json_output:
        typer.echo(
            json.dumps(
                result.report.to_dict(
                    show_all=show_all,
                    min_score=min_score,
                    explain=explain,
                    language=language,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    else:
        render_analysis(
            findings,
            total=result.report.total,
            counts=result.report.counts,
            explain=explain,
            no_color=no_color,
            language=language,
        )





@app.command("version")
def version_command() -> None:
    """Print the installed PrivScout version."""
    typer.echo(__version__)


@app.command("update")
def update_command(
    json_output: Annotated[bool, typer.Option("--json", help="Emit update result as JSON")] = False,
) -> None:
    """Sincroniza GTFOBins, Exploit-DB y los CVE relevantes para uso offline."""
    try:
        if json_output:
            # La salida JSON debe poder redirigirse y procesarse sin texto auxiliar.
            result = update_all()
        else:
            console = Console(stderr=True)
            tasks: dict[str, TaskID] = {}
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.fields[source]:<10}"),
                TextColumn("{task.description:<11}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=False,
                refresh_per_second=10,
            ) as display:
                def show_progress(
                    source: str,
                    phase: str,
                    completed: int | None,
                    total: int | None,
                ) -> None:
                    task_id = tasks.get(source)
                    if task_id is None:
                        task_id = display.add_task(
                            phase,
                            source=source,
                            completed=completed or 0,
                            total=total,
                        )
                        tasks[source] = task_id
                    else:
                        changes: dict[str, object] = {"description": phase}
                        if completed is not None:
                            changes["completed"] = completed
                        if total is not None:
                            changes["total"] = total
                        display.update(task_id, **changes)

                    if phase == "completado":
                        final = completed if completed is not None else 1
                        display.update(task_id, completed=final, total=total or final)

                result = update_all(progress=show_progress)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        typer.echo(f"La actualización de PrivScout falló: {exc}", err=True)
        raise typer.Exit(1) from exc
    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        units = {
            "GTFOBins": "binarios",
            "Exploit-DB": "exploits",
            "CVE": "registros relevantes",
        }
        for item in result.results:
            typer.echo(
                f"{item.source:<12} actualizado {item.entries:>7} "
                f"{units.get(item.source, 'entradas')}"
            )
        typer.echo(f"{'Productos':<12} mantenidos  {result.products:>7} firmas")
        typer.echo(f"Candidatos    revisión    {result.candidates:>7} entradas")
        typer.echo(f"Manifiesto: {result.manifest_path}")



if __name__ == "__main__":
    app()
