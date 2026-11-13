from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable

from .data_loader import load_yaml


# These capabilities make an ordinary GTFOBins file operation materially more
# powerful. The mapping is deliberately narrow: it only infers actions whose
# permission check is directly bypassed by the capability.
CAPABILITY_FUNCTIONS: dict[str, set[str]] = {
    "cap_dac_read_search": {"file-read"},
    "cap_dac_override": {"file-read", "file-write"},
}


def capability_assisted_techniques(
    capability_names: Iterable[str],
    unprivileged_techniques: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    allowed: dict[str, list[str]] = {}
    for capability in sorted(set(capability_names)):
        for function_name in CAPABILITY_FUNCTIONS.get(capability, set()):
            allowed.setdefault(function_name, []).append(capability)

    result: list[dict[str, Any]] = []
    for technique in unprivileged_techniques:
        function_name = str(technique.get("function", ""))
        capabilities = allowed.get(function_name)
        if not capabilities:
            continue
        enriched = deepcopy(technique)
        enriched["source_context"] = "unprivileged"
        enriched["matched_capabilities"] = capabilities
        result.append(enriched)
    return result


def capability_specific_actions(
    canonical: str, capability_names: Iterable[str]
) -> list[dict[str, Any]]:
    rules = load_yaml("capability_actions.yaml").get(canonical, [])
    if not isinstance(rules, list):
        return []
    present = set(capability_names)
    actions: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        required_all = {str(item).lower() for item in rule.get("required_all", [])}
        if not required_all or not required_all.issubset(present):
            continue
        actions.append(
            {
                "function": str(rule.get("function", "manual-review")),
                "title": str(rule.get("title", "Review capability-specific operation")),
                "title_es": str(rule.get("title_es", "Revisar la operación específica de la capability")),
                "description": str(rule.get("description", "")),
                "description_es": str(rule.get("description_es", rule.get("description", ""))),
                "why": str(rule.get("why", "")),
                "why_es": str(rule.get("why_es", rule.get("why", ""))),
                "command": str(rule.get("command", "")).strip() or None,
                "notes": [str(item) for item in rule.get("notes", [])],
                "notes_es": [str(item) for item in rule.get("notes_es", [])],
                "source": "Linux capability semantics",
                "source_es": "Semántica de las capabilities de Linux",
                "source_context": "capabilities",
                "match_type": "capability-specific",
                "matched_capabilities": sorted(required_all),
                "reference": str(rule.get("reference", "")),
                "expanded_reference": str(rule.get("expanded_reference", "")),
                "priority": int(rule.get("priority", 100)),
            }
        )
    return sorted(actions, key=lambda item: (item["priority"], item["function"]))


def _why_for(
    *,
    source: str,
    function_name: str,
    metadata: dict[str, Any],
    technique: dict[str, Any],
) -> str:
    if technique.get("matched_capabilities"):
        capabilities = ", ".join(str(item) for item in technique["matched_capabilities"])
        if function_name == "file-read":
            return (
                f"{capabilities} lets this process bypass normal file-read or directory-search "
                "permission checks."
            )
        if function_name == "file-write":
            return f"{capabilities} lets this process bypass normal file-write permission checks."
        return f"The assigned {capabilities} capability directly supports this operation."
    if technique.get("required_capabilities"):
        capabilities = ", ".join(str(item) for item in technique["required_capabilities"])
        return (
            f"GTFOBins explicitly documents this capabilities-context technique for "
            f"{capabilities}, which is present on the binary."
        )
    if source == "suid":
        return (
            "GTFOBins documents this function for SUID execution; it may run with the file "
            "owner's effective identity when the binary preserves privileges."
        )
    if source == "sudo":
        runas = ", ".join(str(item) for item in metadata.get("runas_users", [])) or "the permitted user"
        return f"GTFOBins documents this function for sudo and this rule permits RunAs {runas}."
    return "GTFOBins documents this function for the detected capabilities context."


def _why_for_es(
    *,
    source: str,
    function_name: str,
    metadata: dict[str, Any],
    technique: dict[str, Any],
) -> str:
    if technique.get("matched_capabilities"):
        capabilities = ", ".join(str(item) for item in technique["matched_capabilities"])
        if function_name == "file-read":
            return (
                f"{capabilities} permite que este proceso omita las comprobaciones normales "
                "de lectura de archivos o búsqueda en directorios."
            )
        if function_name == "file-write":
            return (
                f"{capabilities} permite que este proceso omita las comprobaciones normales "
                "de escritura de archivos."
            )
        return f"La capability asignada ({capabilities}) respalda directamente esta operación."
    if technique.get("required_capabilities"):
        capabilities = ", ".join(str(item) for item in technique["required_capabilities"])
        return (
            "GTFOBins documenta explícitamente esta técnica en el contexto de capabilities "
            f"para {capabilities}, presente en el binario."
        )
    if source == "suid":
        return (
            "GTFOBins documenta esta función para una ejecución SUID; puede ejecutarse con "
            "la identidad efectiva del propietario si el binario conserva los privilegios."
        )
    if source == "sudo":
        runas = ", ".join(str(item) for item in metadata.get("runas_users", [])) or "el usuario permitido"
        return (
            "GTFOBins documenta esta función para sudo y la regla permite ejecutarla "
            f"como {runas}."
        )
    return "GTFOBins documenta esta función para el contexto de capabilities detectado."


def build_actions(
    techniques: list[dict[str, Any]],
    *,
    source: str,
    canonical: str,
    metadata: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    catalog = load_yaml("gtfobins_functions.yaml")
    metadata = metadata or {}
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for technique in techniques:
        function_name = str(technique.get("function", "unknown"))
        context_details = technique.get("context_details", {})
        if not isinstance(context_details, dict):
            context_details = {}
        context_code = context_details.get("code")
        code = str(context_code if context_code is not None else technique.get("code", "")).strip()
        dedupe_key = (function_name, code)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        definition = catalog.get(function_name, {})
        if not isinstance(definition, dict):
            definition = {}
        notes: list[str] = []
        notes_es: list[str] = []
        upstream_remarks = False
        comment = str(technique.get("comment", "")).strip()
        if comment:
            notes.append(comment)
            upstream_remarks = True
        context_comment = str(context_details.get("comment", "")).strip()
        if context_comment and context_comment != comment:
            notes.append(context_comment)
            upstream_remarks = True
        if source == "sudo" and metadata.get("restricted"):
            notes.append("The sudo rule restricts arguments; verify that the shown syntax is permitted.")
            notes_es.append("La regla sudo restringe los argumentos; comprueba que permita la sintaxis mostrada.")
        if source == "sudo" and metadata.get("noexec"):
            notes.append(
                "NOEXEC is enabled; helper programs invoked by this technique may still be blocked."
            )
            notes_es.append(
                "NOEXEC está habilitado; los programas auxiliares que invoque esta técnica aún podrían estar bloqueados."
            )
        if source == "suid":
            notes.append("Confirm the file is owned by a privileged user and that the binary does not drop privileges.")
            notes_es.append(
                "Confirma que el archivo pertenezca a un usuario privilegiado y que el binario "
                "no descarte los privilegios."
            )
        if technique.get("matched_capabilities"):
            notes.append("Replace the placeholder path with the specific file you are authorized to inspect.")
            notes_es.append(
                "Sustituye la ruta de ejemplo por el archivo concreto que estás autorizado a inspeccionar."
            )

        actions.append(
            {
                "function": function_name,
                "title": str(definition.get("label", function_name.replace("-", " ").title())),
                "title_es": str(definition.get("label_es", function_name.replace("-", " ").title())),
                "description": str(definition.get("description", "Review this GTFOBins function.")),
                "description_es": str(definition.get("description_es", "Revisa esta función de GTFOBins.")),
                "why": _why_for(
                    source=source,
                    function_name=function_name,
                    metadata=metadata,
                    technique=technique,
                ),
                "why_es": _why_for_es(
                    source=source,
                    function_name=function_name,
                    metadata=metadata,
                    technique=technique,
                ),
                "command": code or None,
                "notes": notes,
                "notes_es": notes_es,
                "upstream_remarks": upstream_remarks,
                "source": "GTFOBins",
                "source_es": "GTFOBins",
                "source_context": str(technique.get("source_context", source)),
                "match_type": (
                    "capability-assisted"
                    if technique.get("matched_capabilities")
                    else "exact-context"
                ),
                "reference": f"https://gtfobins.github.io/gtfobins/{canonical}/",
                "priority": int(definition.get("priority", 100)),
            }
        )

    actions.sort(key=lambda item: (item["priority"], item["function"], item["command"] or ""))
    return actions
