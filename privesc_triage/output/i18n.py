from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

Language = Literal["en", "es"]


MESSAGES: dict[str, dict[Language, str]] = {
    "found_shown": {"en": "{label:<14} {found:>4} found       {shown:>4} shown", "es": "{label:<14} {found:>4} encontrados  {shown:>4} mostrados"},
    "no_findings": {"en": "No findings matched the current display threshold.", "es": "Ningún hallazgo cumple el umbral de visualización actual."},
    "priority_findings": {"en": "Priority findings", "es": "Hallazgos prioritarios"},
    "gtfo_matches": {"en": "With GTFOBins correlation ({count})", "es": "Con correlación GTFOBins ({count})"},
    "third_party_findings": {"en": "Third-party software — offline vulnerability leads ({count})", "es": "Software de terceros — pistas offline de vulnerabilidades ({count})"},
    "heuristic_findings": {"en": "Heuristic offline matches — manual review ({count})", "es": "Coincidencias heurísticas offline — revisión manual ({count})"},
    "manual_review_findings": {"en": "Without GTFOBins correlation — manual review ({count})", "es": "Sin correlación GTFOBins — revisión manual ({count})"},
    "source": {"en": "Source", "es": "Origen"},
    "suid_observed": {"en": "Observed SUID", "es": "SUID observado"},
    "owner": {"en": "Owner", "es": "Propietario"},
    "product": {"en": "Product", "es": "Producto"},
    "software_type": {"en": "Type", "es": "Tipo"},
    "version": {"en": "Version", "es": "Versión"},
    "exploitdb": {"en": "Exploit-DB", "es": "Exploit-DB"},
    "cve": {"en": "CVE", "es": "CVE"},
    "applicability": {"en": "Applicability", "es": "Aplicabilidad"},
    "recommendation": {"en": "Recommendation", "es": "Recomendación"},
    "confidence": {"en": "Confidence", "es": "Confianza"},
    "canonical": {"en": "Canonical", "es": "Nombre normalizado"},
    "class": {"en": "Class", "es": "Clasificación"},
    "runas": {"en": "RunAs", "es": "Ejecutar como"},
    "yes": {"en": "yes", "es": "sí"},
    "no": {"en": "no", "es": "no"},
    "arguments": {"en": "Arguments", "es": "Argumentos"},
    "blocked_functions": {"en": "Blocked by NOEXEC", "es": "Bloqueadas por NOEXEC"},
    "no_arguments": {"en": "no arguments allowed", "es": "no se permiten argumentos"},
    "unrestricted": {"en": "unrestricted", "es": "sin restricciones"},
    "capability": {"en": "Capability", "es": "Capability de Linux"},
    "supported_actions": {"en": "Supported actions", "es": "Acciones respaldadas"},
    "action_basis": {"en": "Action basis", "es": "Fundamento"},
    "occurrences": {"en": "Occurrences", "es": "Apariciones"},
    "also_seen": {"en": "Also seen", "es": "También aparece en"},
    "techniques": {"en": "Techniques", "es": "Técnicas"},
    "selection_basis": {"en": "Selection basis", "es": "Criterio de selección"},
    "not_promoted": {"en": "Not promoted", "es": "No recomendadas"},
    "not_elevated": {"en": "not supported as elevated actions by the observed capability", "es": "la capability observada no respalda estas funciones como acciones elevadas"},
    "reason": {"en": "Reason", "es": "Motivo"},
    "inspect_next": {"en": "  Inspect next:", "es": "  Inspeccionar a continuación:"},
    "context_actions": {"en": "  Context-supported actions (manual validation required):", "es": "  Acciones respaldadas por el contexto (requieren validación manual):"},
    "why": {"en": "Why", "es": "Por qué aplica"},
    "action_source": {"en": "Source", "es": "Fuente"},
    "gtfo_command": {"en": "GTFOBins command (not executed by PrivScout):", "es": "Comando de GTFOBins (PrivScout no lo ejecuta):"},
    "suggested_command": {"en": "Context-compatible command (not executed by PrivScout):", "es": "Comando compatible con el contexto (PrivScout no lo ejecuta):"},
    "note": {"en": "Note", "es": "Nota"},
    "cap_reference": {"en": "Capability reference", "es": "Referencia de la capability"},
    "action_reference": {"en": "Reference", "es": "Referencia"},
    "additional_action": {"en": "    +1 additional action available in --json.", "es": "    Hay 1 acción adicional disponible en --json."},
    "additional_actions": {"en": "    +{count} additional actions available in --json.", "es": "    Hay {count} acciones adicionales disponibles en --json."},
    "visit_gtfo": {"en": "    Visit {reference} for every documented function, full remarks, and context requirements.", "es": "    Visita {reference} para consultar todas las funciones documentadas, las observaciones completas y los requisitos de cada contexto."},
    "score_explanation": {"en": "  Score explanation:", "es": "  Explicación de la puntuación:"},
    "showing": {"en": "Showing {shown} findings from {total} entries.", "es": "Mostrando {shown} hallazgos de {total} entradas."},
    "gtfo_exact": {"en": "exact-context technique available", "es": "técnica disponible para el contexto exacto"},
    "gtfo_assisted": {"en": "capability-assisted correlation", "es": "correlación asistida por capability"},
    "gtfo_wildcard": {"en": "wildcard detected; GTFOBins command not validated", "es": "wildcard detectado; comando GTFOBins no validado"},
    "gtfo_no_match": {"en": "no context match", "es": "sin coincidencia para este contexto"},
    "gtfo_custom": {"en": "no context match; inspect custom implementation", "es": "sin coincidencia contextual; inspecciona la implementación personalizada"},
    "upstream_remarks": {"en": "Review the original GTFOBins remarks for technique-specific limitations.", "es": "Consulta en GTFOBins las observaciones originales y las limitaciones específicas de esta técnica."},
}


SEVERITIES = {
    "critical": {"en": "CRITICAL", "es": "CRÍTICO"},
    "high": {"en": "HIGH", "es": "ALTO"},
    "suspicious": {"en": "SUSPICIOUS", "es": "SOSPECHOSO"},
    "low": {"en": "LOW", "es": "BAJO"},
    "info": {"en": "INFO", "es": "INFO"},
}

SOURCE_LABELS = {
    "suid": {"en": "SUID", "es": "SUID"},
    "sudo": {"en": "sudo", "es": "sudo"},
    "capability": {"en": "Capabilities", "es": "Capabilities"},
}

CLASSIFICATIONS = {
    "known_vector": "vector conocido",
    "known_interesting": "vector conocido de interés",
    "expected_combination": "combinación esperada",
    "capability_review": "revisión de capability",
    "custom_unusual": "binario personalizado o inusual",
    "common": "binario común",
    "unknown_custom": "binario desconocido o personalizado",
    "direct_gtfo": "técnica directa de GTFOBins",
    "restricted_gtfo": "técnica de GTFOBins con restricciones",
    "sudo_wildcard_injection": "wildcard injection en tar (validación manual)",
    "custom_root_nopasswd": "comando personalizado como root sin contraseña",
    "manual_review": "revisión manual",
    "no_gtfo_match": "sin coincidencia en GTFOBins",
}

TEXT_ES = {
    "Expected package combination, but a context-supported technique prevents suppression": "La combinación coincide con un paquete esperado, pero existe una técnica respaldada por el contexto y no debe ocultarse",
    "Known expected combination; common does not mean safe": "Combinación esperada conocida; que sea común no significa que sea segura",
    "Binary/capability combination is not in the expected baseline": "La combinación de binario y capability no figura en la línea base esperada",
    "General-purpose binary increases capability utility": "Un binario de propósito general aumenta la utilidad de la capability",
    "The binary directly exposes an operation governed by the assigned capability": "El binario expone directamente una operación controlada por la capability asignada",
    "A file capability directly strengthens an unprivileged GTFOBins technique": "La capability del archivo potencia directamente una técnica no privilegiada de GTFOBins",
    "Known GTFOBins technique for the capabilities context": "GTFOBins documenta una técnica para este contexto de capabilities",
    "Custom or locally installed binary with file capabilities": "Binario personalizado o instalado localmente con capabilities de archivo",
    "Capability is effective and permitted": "La capability está en los conjuntos efectivo y permitido",
    "No capability is effective; direct abuse depends on additional process state": "Ninguna capability está efectiva; el abuso directo depende de estado adicional del proceso",
    "Known GTFOBins technique for the SUID context": "GTFOBins documenta una técnica para el contexto SUID",
    "Common SUID baseline entry (not a safety guarantee)": "Entrada común de la línea base SUID; esto no garantiza que sea segura",
    "Custom or uncommon SUID binary": "Binario SUID personalizado o poco común",
    "General-purpose or high-utility binary": "Binario de propósito general o gran utilidad",
    "Binary is in a location commonly used for custom software": "El binario está en una ubicación habitual para software personalizado",
    "Negated rule; retained for policy context": "Regla negada; se conserva para entender la política",
    "Rule permits a privileged RunAs identity": "La regla permite ejecutarse con una identidad privilegiada",
    "RunAs explicitly excludes root; sudo version and alternate identities require review": "RunAs excluye explícitamente a root; es necesario revisar la versión de sudo y las identidades alternativas",
    "No sudo password prompt is required by this rule": "La regla no exige contraseña de sudo",
    "Known GTFOBins technique for the sudo context": "GTFOBins documenta una técnica para el contexto sudo",
    "Arguments may prevent direct use of a known technique": "Las restricciones de argumentos pueden impedir el uso directo de una técnica conocida",
    "NOEXEC blocks techniques that require launching another program": "NOEXEC bloquea las técnicas que necesitan iniciar otro programa",
    "The sudo rule does not restrict command arguments": "La regla sudo no restringe los argumentos del comando",
    "Wildcard semantics require manual review": "El comportamiento de los comodines requiere revisión manual",
    "The tar rule contains a wildcard injection pattern that requires manual validation": "La regla de tar contiene un patrón de wildcard injection que requiere validación manual",
    "Interpreter, editor, archive, package, or service utility": "Intérprete, editor o herramienta de archivos, paquetes o servicios",
    "Sudo command is in a location commonly used for custom software": "El comando sudo está en una ubicación habitual para software personalizado",
    "High-risk combination: custom command can run as root without a password or argument restriction": "Combinación de alto riesgo: un comando personalizado puede ejecutarse como root sin contraseña ni restricción de argumentos",
    "GTFOBins explicitly lists the selected functions for its capabilities context.": "GTFOBins enumera explícitamente las funciones seleccionadas para su contexto de capabilities.",
    "PrivScout intersected the observed Linux capability semantics with GTFOBins' unprivileged functions and retained only directly strengthened operations.": "PrivScout cruzó la semántica de las capabilities de Linux observadas con las funciones no privilegiadas de GTFOBins y conservó únicamente las operaciones potenciadas de forma directa.",
    "A maintained binary-specific rule maps the observed capability to an operation the binary directly exposes.": "Una regla mantenida específicamente para este binario relaciona la capability observada con una operación que el binario expone directamente.",
    "GTFOBins explicitly lists the selected functions for its SUID context.": "GTFOBins enumera explícitamente las funciones seleccionadas para su contexto SUID.",
    "GTFOBins explicitly lists the selected functions for its sudo context.": "GTFOBins enumera explícitamente las funciones seleccionadas para su contexto sudo.",
    "PrivScout detected a tar wildcard pattern but did not assert a GTFOBins command for the restricted arguments.": "PrivScout detectó un patrón wildcard en tar, pero no afirmó ningún comando de GTFOBins para los argumentos restringidos.",
    "SUID bit present": "Bit SUID presente",
    "GTFOBins SUID technique": "Técnica SUID de GTFOBins",
    "Common SUID baseline": "Línea base de binarios SUID comunes",
    "Unknown/custom SUID binary": "Binario SUID desconocido o personalizado",
    "High-utility binary": "Binario de gran utilidad",
    "Unusual binary location": "Ubicación inusual del binario",
    "Negated sudo rule": "Regla sudo negada",
    "RunAs root/ALL": "Ejecución permitida como root/ALL",
    "NOPASSWD sudo rule": "Regla sudo NOPASSWD",
    "GTFOBins sudo technique": "Técnica sudo de GTFOBins",
    "Command arguments restrict direct use": "Los argumentos restringen el uso directo",
    "Command arguments unrestricted": "Argumentos del comando sin restricciones",
    "Wildcard in sudo rule": "Comodín en la regla sudo",
    "General-purpose/high-utility binary": "Binario de propósito general o gran utilidad",
    "Custom sudo binary location": "Ubicación personalizada del binario sudo",
    "Unrestricted custom command as root without a password": "Comando personalizado sin restricciones como root y sin contraseña",
    "Effective and permitted flags": "Indicadores efectivo y permitido",
    "Expected binary/capability combination": "Combinación esperada de binario y capability",
    "Unusual capability combination": "Combinación inusual de capabilities",
    "GTFOBins capability technique": "Técnica de capabilities de GTFOBins",
    "Capability-specific operation supported by this binary": "Operación específica de la capability compatible con este binario",
    "Custom binary": "Binario personalizado",
}

RISK_ES = {"critical": "crítico", "high": "alto", "medium": "medio", "low": "bajo", "unknown": "desconocido"}


def tr(key: str, language: Language = "en", **values: Any) -> str:
    return MESSAGES[key][language].format(**values)


def translate_text(value: str, language: Language) -> str:
    if language == "en":
        return value
    if value in TEXT_ES:
        return TEXT_ES[value]
    if value.startswith("Highest capability risk is "):
        risk = value.removeprefix("Highest capability risk is ")
        return f"El riesgo más alto de las capabilities es {RISK_ES.get(risk, risk)}"
    if value.startswith("Highest capability risk (") and value.endswith(")"):
        risk = value[len("Highest capability risk (") : -1]
        return f"Riesgo más alto de las capabilities ({RISK_ES.get(risk, risk)})"
    return value


def classification_label(value: str, language: Language) -> str:
    return CLASSIFICATIONS.get(value, value) if language == "es" else value


def source_label(value: str, language: Language) -> str:
    return SOURCE_LABELS.get(value, {language: value}).get(language, value)


def severity_label(value: str, language: Language) -> str:
    return SEVERITIES.get(value, {language: value.upper()}).get(language, value.upper())


def localized_action(action: dict[str, Any], language: Language) -> dict[str, Any]:
    result = deepcopy(action)
    if language == "es":
        for field in ("title", "description", "why", "source"):
            translated = result.get(f"{field}_es")
            if translated:
                result[field] = translated
        result["notes"] = list(result.get("notes_es", []))
        if result.get("upstream_remarks"):
            result["notes"].append(tr("upstream_remarks", "es"))
    for key in list(result):
        if key.endswith("_es") or key == "upstream_remarks":
            result.pop(key, None)
    return result


def localized_metadata(metadata: dict[str, Any], language: Language) -> dict[str, Any]:
    result = deepcopy(metadata)
    if language == "es":
        basis = result.get("contextual_selection_basis")
        if basis:
            result["contextual_selection_basis"] = translate_text(str(basis), language)
        for capability in result.get("capabilities", []):
            if capability.get("description_es"):
                capability["description"] = capability["description_es"]
            capability.pop("description_es", None)
    else:
        for capability in result.get("capabilities", []):
            capability.pop("description_es", None)
    return result


def localized_gtfobins(gtfobins: dict[str, Any], language: Language) -> dict[str, Any]:
    result = deepcopy(gtfobins)
    basis = result.get("selection_basis")
    if basis:
        result["selection_basis"] = translate_text(str(basis), language)
    return result


def localized_third_party(third_party: dict[str, Any], language: Language) -> dict[str, Any]:
    result = deepcopy(third_party)
    if language == "es":
        for field in ("applicability", "recommendation"):
            translated = result.get(f"{field}_es")
            if translated:
                result[field] = translated
        for vulnerability in result.get("vulnerabilities", []):
            if vulnerability.get("affected_es"):
                vulnerability["affected"] = vulnerability["affected_es"]
    for key in list(result):
        if key.endswith("_es") or key in {"path_patterns", "canonical_names", "suggested_checks"}:
            result.pop(key, None)
    for vulnerability in result.get("vulnerabilities", []):
        vulnerability.pop("affected_es", None)
    return result
