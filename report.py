"""
Generación de reportes de riesgo para auditorías de dependencias (QA).

Dos capas:
  1. Modelo de riesgo DETERMINISTA: a partir de los hallazgos duros (CVEs y su
     severidad CVSS desde OSV, atraso de versión major/minor/patch desde npm,
     EOL), calcula un nivel de riesgo por dependencia y un puntaje global. Esto
     siempre funciona, sin depender de IA ni de conexión adicional.
  2. Narrativa con IA (Claude, vía la API de Anthropic): redacta el "Análisis
     General" y la "Conclusión General" y refina las mitigaciones, anclándose en
     los hallazgos del paso 1 (con instrucción explícita de NO inventar CVEs ni
     versiones). Es OPCIONAL: si no hay API key configurada, se usa una
     redacción basada en plantilla a partir de los mismos datos.

El reporte sigue la estructura:
    Análisis General
    Análisis Técnico
      - aplicativo (paquete) con su versión y grado de severidad de riesgo
      - riesgos conocidos
      - precisión técnica
      - medidas de mitigación recomendadas
    Conclusión General
"""

import json

import net

ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-6"

# Pesos del modelo de riesgo (orden: cuanto más alto, peor).
_LEVEL_RANK = {"crítico": 4, "alto": 3, "medio": 2, "bajo": 1, "ok": 0, "desconocido": 0}


# ---------------------------------------------------------------- severidad
def _cvss_band(score):
    """Mapea un puntaje/categoría CVSS a una banda en español."""
    if score is None:
        return None
    s = str(score).upper()
    # OSV a veces entrega un vector CVSS, no un número. Intentar extraer número.
    num = None
    try:
        num = float(s)
    except ValueError:
        # vector tipo "CVSS:3.1/AV:N/..." — no trae el score base directo.
        if "CRITICAL" in s:
            return "crítica"
        if "HIGH" in s:
            return "alta"
        if "MEDIUM" in s or "MODERATE" in s:
            return "media"
        if "LOW" in s:
            return "baja"
        return None
    if num >= 9.0:
        return "crítica"
    if num >= 7.0:
        return "alta"
    if num >= 4.0:
        return "media"
    if num > 0:
        return "baja"
    return None


def _max_severity(details):
    """Severidad máxima entre los CVE de una dependencia."""
    order = {"crítica": 4, "alta": 3, "media": 2, "baja": 1}
    best, best_label = 0, None
    for d in details or []:
        band = _cvss_band(d.get("severity"))
        if band and order.get(band, 0) > best:
            best, best_label = order[band], band
    return best_label


# ---------------------------------------------------------------- riesgo dep
def _dep_risk(entry):
    """Nivel + puntaje de riesgo de una dependencia."""
    # Ítems de plataforma (compileSdk/targetSdk/minSdk, AGP, Gradle) traen su nivel.
    if entry.get("platform_kind"):
        lvl = entry.get("platform_level") or "ok"
        score = {"crítico": 12, "alto": 8, "medio": 4, "bajo": 1.5, "ok": 0, "desconocido": 0}.get(lvl, 0)
        return lvl, score, None

    cve_count = entry.get("vuln_count") or 0
    sev = _max_severity(entry.get("vuln_details"))
    gap = entry.get("gap")
    note = entry.get("note")

    score = 0.0
    level = "ok"

    if cve_count > 0:
        # Base por tener CVEs + ponderación por severidad.
        sev_w = {"crítica": 10, "alta": 7, "media": 4, "baja": 2}.get(sev, 3)
        score += sev_w + min(cve_count, 5) * 0.5
        level = "crítico" if sev == "crítica" else "alto" if sev == "alta" else "medio"
    # Atraso de versión.
    if gap == "major":
        score += 3; level = level if _LEVEL_RANK[level] >= 2 else "medio"
    elif gap == "minor":
        score += 1.5; level = level if _LEVEL_RANK[level] >= 1 else "bajo"
    elif gap == "patch":
        score += 0.5; level = level if _LEVEL_RANK[level] >= 1 else "bajo"

    if note == "neterror":
        level = "desconocido" if level == "ok" else level

    # Elevación por hallazgo de cumplimiento legal (Ley 21.459 / 19.628).
    comp = entry.get("compliance")
    if comp:
        c_level = comp.get("nivel")
        bump = {"crítico": (12, "crítico"), "alto": (8, "alto"), "medio": (4, "medio")}.get(c_level)
        if bump:
            add, target = bump
            score += add
            if _LEVEL_RANK.get(target, 0) > _LEVEL_RANK.get(level, 0):
                level = target
    return level, round(score, 1), sev


def _severity_label(entry, level, sev):
    """Texto del 'grado de severidad de riesgo' por aplicativo."""
    if entry.get("platform_kind"):
        k = entry["platform_kind"]
        mapping = {"alto": "ALTO", "medio": "MEDIO", "bajo": "BAJO", "ok": "OK", "desconocido": "INDETERMINADO"}
        return f"PLATAFORMA ({k}) — {mapping.get(level, level.upper())}"
    comp = entry.get("compliance")
    if comp and comp.get("nivel") == "crítico":
        return "GRAVÍSIMO — riesgo legal: posible paquete malicioso (Ley 21.459)"
    if comp and comp.get("nivel") == "alto":
        return "GRAVE — riesgo legal: posible tratamiento de datos de fuente ilícita (Ley 21.459 Art. 6)"
    if level == "crítico":
        return f"CRÍTICO — CVE de severidad {sev or 'alta'}"
    if level == "alto":
        return f"ALTO — vulnerabilidad {sev or 'alta'}"
    if level == "medio":
        if comp and comp.get("nivel") == "medio":
            return "MEDIO — revisión de cumplimiento (tratamiento de datos personales)"
        return "MEDIO" + (f" — CVE {sev}" if sev else " — versión major atrasada")
    if level == "bajo":
        return "BAJO — desactualización menor"
    if level == "desconocido":
        return "INDETERMINADO — sin datos de CVE (sin conexión a OSV)"
    return "OK — sin observaciones"


def _known_risks(entry):
    risks = []
    if entry.get("platform_kind"):
        if entry.get("platform_note"):
            risks.append(entry["platform_note"])
        return risks or ["Sin observaciones."]
    comp = entry.get("compliance")
    if comp:
        risks.append("⚖ RIESGO LEGAL/CUMPLIMIENTO: " + comp.get("rationale", ""))
    if (entry.get("vuln_count") or 0) > 0:
        ids = ", ".join(entry.get("vuln_ids") or []) or "ver detalle"
        sev = _max_severity(entry.get("vuln_details"))
        risks.append(f"{entry['vuln_count']} CVE conocido(s) para la versión "
                     f"{entry.get('installed')}{' (severidad máx. ' + sev + ')' if sev else ''}: {ids}.")
        for d in (entry.get("vuln_details") or [])[:3]:
            if d.get("summary"):
                risks.append(f"{d.get('id')}: {d['summary']}")
    if entry.get("gap") == "major":
        risks.append(f"Versión major atrasada: instalada {entry.get('installed')} vs. "
                     f"última {entry.get('latest')} — posible deuda técnica y falta de parches.")
    elif entry.get("gap") in ("minor", "patch"):
        risks.append(f"Desactualización {entry.get('gap')}: {entry.get('installed')} → {entry.get('latest')}.")
    if entry.get("note") and entry.get("note") != "neterror":
        risks.append(f"Especificación no resoluble ({entry.get('note')}): no se pudo evaluar la versión.")
    if not risks:
        risks.append("Sin riesgos conocidos detectados.")
    return risks


def _technical_precision(entry):
    if entry.get("platform_kind"):
        return (f"Componente de plataforma Android. Valor declarado: {entry.get('installed')}; "
                f"referencia vigente: {entry.get('latest_label') or entry.get('latest')}.")
    eco = "Maven Central / Google Maven" if entry.get("ecosystem") == "Maven" else "npm"
    if entry.get("note") == "neterror":
        return ("Evaluación parcial: no se pudo consultar OSV para esta dependencia "
                f"(sin conexión). El estado de versión proviene de {eco}; los CVE quedan pendientes.")
    if entry.get("note"):
        return ("Precisión limitada: la versión no se pudo resolver "
                "(catálogo/variable/alias o artefacto no encontrado), por lo que no se evalúa "
                "versión exacta ni CVE.")
    if not entry.get("installed"):
        return "Precisión limitada: no se pudo determinar la versión instalada."
    base = (f"Alta: versión declarada ({entry.get('installed')}); "
            f"última versión verificada en {eco}")
    if entry.get("vuln_status") in ("ok", "vulnerable", "clean"):
        base += "; CVE consultados en OSV con coincidencia exacta de versión."
    else:
        base += "."
    return base


def _mitigations(entry):
    m = []
    if entry.get("platform_kind"):
        if entry.get("platform_reco"):
            m.append(entry["platform_reco"])
        return m or ["Mantener al día según el ciclo de versiones de Android."]
    comp = entry.get("compliance")
    if comp and comp.get("recomendacion"):
        m.append("⚖ " + comp["recomendacion"])
    if (entry.get("vuln_count") or 0) > 0:
        m.append(f"Actualizar {entry['package']} a una versión sin los CVE reportados "
                 f"(referencia: última {entry.get('latest')}) y re-auditar.")
        m.append("Revisar el detalle de cada CVE (impacto/explotabilidad) antes de aprobar el build.")
    if entry.get("gap") == "major":
        m.append(f"Planificar migración a la versión major {entry.get('latest')} "
                 "(revisar breaking changes y guía de migración del paquete).")
    elif entry.get("gap") in ("minor", "patch"):
        m.append(f"Actualizar a {entry.get('latest')} ({entry.get('gap')}), de bajo riesgo de ruptura.")
    if entry.get("pinned") is False and entry.get("installed"):
        m.append("Considerar fijar la versión (lockfile / versión exacta) para builds reproducibles.")
    if entry.get("note") == "neterror":
        m.append("Reintentar la auditoría con conexión a OSV para confirmar ausencia de CVE.")
    if not m:
        m.append("Mantener monitoreo; sin acción inmediata requerida.")
    return m


# ---------------------------------------------------------------- reporte
def _overall(audit, tecnico):
    counts = {"crítico": 0, "alto": 0, "medio": 0, "bajo": 0, "ok": 0, "desconocido": 0}
    total_score = 0.0
    comp_critico = comp_alto = 0
    for t in tecnico:
        counts[t["nivel"]] = counts.get(t["nivel"], 0) + 1
        total_score += t["score"]
        cl = (t.get("cumplimiento") or {}).get("nivel")
        if cl == "crítico":
            comp_critico += 1
        elif cl == "alto":
            comp_alto += 1
    n = max(len(tecnico), 1)
    avg = total_score / n
    # Los hallazgos legales graves fuerzan el rechazo, con motivo explícito.
    # Los hallazgos legales graves fuerzan una recomendación negativa, con motivo
    # explícito. Esto es un INSUMO de la revisión del inventario de software, no
    # el veredicto final de QA (que considera además otros factores).
    if comp_critico > 0:
        verdict, vlevel = "NO RECOMENDADO — RIESGO LEGAL GRAVÍSIMO", "crítico"
    elif counts["crítico"] > 0:
        verdict, vlevel = "NO RECOMENDADO — riesgo técnico crítico", "crítico"
    elif comp_alto > 0:
        verdict, vlevel = "NO RECOMENDADO — RIESGO LEGAL GRAVE", "alto"
    elif counts["alto"] > 0:
        verdict, vlevel = "NO RECOMENDADO — riesgo técnico alto", "alto"
    elif counts["medio"] > 0:
        verdict, vlevel = "RECOMENDADO CON OBSERVACIONES", "medio"
    elif counts["bajo"] > 0:
        verdict, vlevel = "RECOMENDADO CON OBSERVACIONES MENORES", "bajo"
    else:
        verdict, vlevel = "RECOMENDADO", "ok"
    return {"counts": counts, "avg_score": round(avg, 2),
            "verdict": verdict, "verdict_level": vlevel,
            "compliance_critico": comp_critico, "compliance_alto": comp_alto}


def build_report(audit, ai=False, api_key=None, model=None, author=None, generated_at=None):
    """Construye el reporte estructurado. Si ai=True y hay api_key, redacta la
    narrativa con Claude; si no, usa plantilla determinista.
    `author` y `generated_at` se incluyen en el encabezado del informe."""
    import datetime
    proj = audit.get("project") or {}
    deps = audit.get("deps") or []

    tecnico = []
    for e in deps:
        level, score, sev = _dep_risk(e)
        tecnico.append({
            "package": e["package"], "section": e.get("section"),
            "installed": e.get("installed"), "latest": e.get("latest"),
            "latest_release": e.get("latest_release"),
            "range": e.get("range"), "gap": e.get("gap"),
            "nivel": level, "score": score,
            "severidad": _severity_label(e, level, sev),
            "riesgos_conocidos": _known_risks(e),
            "precision_tecnica": _technical_precision(e),
            "mitigaciones": _mitigations(e),
            # enlaces + EOL + detalle CVE para el reporte exportable
            "npm_url": e.get("npm_url"), "homepage": e.get("homepage"),
            "repository": e.get("repository"), "description": e.get("description"),
            "eol_url": e.get("eol_url"), "eol_info": e.get("eol_info"),
            "vuln_count": e.get("vuln_count") or 0,
            "vuln_ids": e.get("vuln_ids") or [],
            "cve_detalle": e.get("vuln_details") or [],
            "cumplimiento": e.get("compliance"),
        })
    # Orden por riesgo descendente.
    tecnico.sort(key=lambda t: (-_LEVEL_RANK.get(t["nivel"], 0), -t["score"], t["package"]))
    overall = _overall(audit, tecnico)

    report = {
        "project": proj,
        "author": author or "no indicado",
        "generated_at": generated_at or datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "summary": audit.get("summary") or {},
        "overall": overall,
        "tecnico": tecnico,
        "cumplimiento_legal": _legal_section(tecnico),
        "general": _fallback_general(proj, audit, overall),
        "conclusion": _fallback_conclusion(overall, tecnico),
        "ai_used": False,
        "ai_error": None,
    }

    if ai and api_key:
        narrative, err = _ai_narrative(report, api_key, model or DEFAULT_MODEL)
        if narrative:
            report["general"] = narrative.get("general") or report["general"]
            report["conclusion"] = narrative.get("conclusion") or report["conclusion"]
            report["ai_used"] = True
        else:
            report["ai_error"] = err
    return report


def _legal_section(tecnico):
    """Detalle de cumplimiento legal por dependencia flagueada (Ley 21.459)."""
    items = []
    for t in tecnico:
        comp = t.get("cumplimiento")
        if not comp:
            continue
        items.append({
            "package": t["package"],
            "nivel": comp["nivel"],
            "categoria": comp["categoria"],
            "leyes": comp.get("leyes", []),
            "rationale": comp["rationale"],
            "articulos": comp.get("articulos", []),
            "recomendacion": comp.get("recomendacion"),
            "disclaimer": comp.get("disclaimer"),
        })
    return items


def _fallback_general(proj, audit, overall):
    s = audit.get("summary") or {}
    c = overall["counts"]
    txt = (
        f"Se auditó el proyecto «{proj.get('name') or 'sin nombre'}» "
        f"(versión {proj.get('version') or 'n/d'}), con {s.get('total', 0)} dependencias "
        f"declaradas. Del análisis automatizado contra el registro npm y la base de "
        f"vulnerabilidades OSV, {s.get('outdated', 0)} dependencias están desactualizadas "
        f"({s.get('major_behind', 0)} con una versión major de atraso) y {s.get('vulnerable', 0)} "
        f"presentan CVE conocidos. La distribución de riesgo es: {c['crítico']} crítico(s), "
        f"{c['alto']} alto(s), {c['medio']} medio(s) y {c['bajo']} bajo(s). "
        f"El puntaje de riesgo promedio es {overall['avg_score']}."
    )
    cc, ca = overall.get("compliance_critico", 0), overall.get("compliance_alto", 0)
    if cc or ca:
        txt += (f" Adicionalmente, el análisis de cumplimiento detectó hallazgos de riesgo "
                f"legal: {cc} de nivel gravísimo y {ca} de nivel grave, asociados al "
                f"tratamiento de datos personales o a código potencialmente malicioso, "
                f"evaluados frente a la Ley 21.459 sobre delitos informáticos.")
    return txt


def _fallback_conclusion(overall, tecnico):
    top = [t["package"] for t in tecnico if _LEVEL_RANK.get(t["nivel"], 0) >= 3][:5]
    base = (f"Recomendación sobre el inventario de software: {overall['verdict']}. "
            "Este resultado corresponde a la revisión del inventario de dependencias "
            "(versiones, vulnerabilidades y cumplimiento) y constituye un insumo para la "
            "evaluación final de QA, no su veredicto único. ")
    legal = [t["package"] for t in tecnico if t.get("cumplimiento")]
    if (overall.get("compliance_critico") or overall.get("compliance_alto")):
        base += ("Se identificaron riesgos LEGALES que deberían resolverse antes de avanzar: "
                 + ", ".join(legal[:6]) + ". Conforme a la Ley 21.459, el uso de paquetes "
                 "que traten datos de fuentes ilícitas (Art. 6, receptación de datos "
                 "informáticos) o de código malicioso (Arts. 1, 2, 4, 7 y 8) podría acarrear "
                 "responsabilidad; se recomienda revisión del área legal/cumplimiento "
                 "y, de no acreditarse la licitud de las fuentes, no utilizar dichas "
                 "dependencias. ")
    if top:
        base += ("Atención técnica prioritaria a: " + ", ".join(top) + ". ")
    if overall["verdict_level"] in ("crítico", "alto"):
        base += ("Se recomienda remediar las vulnerabilidades de severidad alta/crítica y "
                 "los hallazgos legales, y re-auditar, antes de considerar el inventario apto.")
    elif overall["verdict_level"] == "medio":
        base += ("El inventario puede considerarse con observaciones; conviene planificar la "
                 "actualización de las dependencias con atraso major en el corto plazo.")
    else:
        base += "No se observan bloqueantes en el inventario; mantener el monitoreo periódico de dependencias."
    return base


# ---------------------------------------------------------------- IA (Claude)
def _ai_narrative(report, api_key, model):
    """Pide a Claude que redacte Análisis General y Conclusión General a partir
    de los hallazgos (sin inventar datos). Devuelve (dict|None, error|None)."""
    # Resumen compacto de hallazgos para anclar al modelo.
    findings = {
        "proyecto": report["project"],
        "resumen": report["summary"],
        "veredicto_modelo": report["overall"],
        "dependencias_riesgo": [
            {"paquete": t["package"], "instalada": t["installed"], "ultima": t["latest"],
             "nivel": t["nivel"], "severidad": t["severidad"],
             "riesgos": t["riesgos_conocidos"][:3]}
            for t in report["tecnico"] if _LEVEL_RANK.get(t["nivel"], 0) >= 1
        ][:25],
        "hallazgos_legales": report.get("cumplimiento_legal", []),
    }
    prompt = (
        "Eres un analista de seguridad de software y cumplimiento legal senior, en Chile. "
        "A partir EXCLUSIVAMENTE de los hallazgos en formato JSON que se entregan (NO "
        "inventes CVEs, versiones, artículos ni datos que no estén ahí), redacta en español "
        "de Chile, tono profesional y conciso, dos textos:\n"
        "1) 'general': un Análisis General del estado de las dependencias del proyecto "
        "(2-4 párrafos). Si existen 'hallazgos_legales', dedícales un párrafo explicando el "
        "riesgo de cumplimiento. NO uses lenguaje de aprobación/rechazo de QA; este informe "
        "es la revisión del INVENTARIO DE SOFTWARE y es un INSUMO para la evaluación final de "
        "QA, no su veredicto. Expresa los resultados como una RECOMENDACIÓN.\n"
        "2) 'conclusion': una Conclusión General redactada como RECOMENDACIÓN sobre el "
        "inventario de software y las acciones prioritarias (1-2 párrafos), aclarando que es "
        "un insumo para la evaluación final de QA. Si hay hallazgos legales de nivel 'alto' o "
        "'crítico', ALUDE EXPLÍCITAMENTE a los artículos de la Ley 21.459 indicados en cada "
        "hallazgo (usa exactamente los identificadores y textos provistos en 'articulos'), "
        "describiendo la posible falta o delito que se configuraría, SIEMPRE en condicional "
        "('podría configurar', 'a verificar') y sin afirmar culpabilidad. Incluye la "
        "advertencia de que no es asesoría legal. Evita las palabras 'aprobado'/'rechazado'.\n"
        "Responde ÚNICAMENTE con un objeto JSON válido: {\"general\": \"...\", \"conclusion\": \"...\"} "
        "sin texto adicional ni markdown.\n\n"
        "HALLAZGOS:\n" + json.dumps(findings, ensure_ascii=False, default=str)
    )
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {"model": model, "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}]}
    try:
        r = net.post(ANTHROPIC_ENDPOINT, headers=headers, json=body, timeout=60)
    except net.NetworkError as e:
        return None, f"sin conexión a la API de Anthropic ({e})"
    if r.status_code == 401:
        return None, "API key inválida o no autorizada (401)"
    if r.status_code != 200:
        return None, f"la API respondió HTTP {r.status_code}"
    try:
        data = r.json()
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text").strip()
        # Quitar posibles ```json ... ```
        text = text.replace("```json", "").replace("```", "").strip()
        parsed = json.loads(text)
        return {"general": parsed.get("general"), "conclusion": parsed.get("conclusion")}, None
    except Exception as e:
        return None, f"respuesta de IA no parseable ({e})"


# ---------------------------------------------------------------- markdown
def report_to_markdown(report):
    """Serializa el reporte a Markdown para descargar/adjuntar al ticket de QA."""
    proj = report["project"]; ov = report["overall"]
    L = []
    L.append(f"# Informe de inventario de software — {report.get('generated_at','')}")
    L.append(f"**Proyecto:** {proj.get('name') or 'n/d'}  ·  **Versión:** {proj.get('version') or 'n/d'}")
    L.append(f"**Generado por:** {report.get('author') or 'no indicado'}  ·  **Fecha y hora:** {report.get('generated_at','')}")
    L.append(f"**Recomendación sobre el inventario:** {ov['verdict']}  ·  **Puntaje de riesgo promedio:** {ov['avg_score']}")
    L.append(f"_Insumo para la evaluación final de QA. Generado {'con asistencia de IA (Claude)' if report.get('ai_used') else 'por el modelo de riesgo determinista'}._\n")

    L.append("## Análisis General\n")
    L.append(report["general"] + "\n")

    L.append("## Análisis Técnico\n")
    for t in report["tecnico"]:
        L.append(f"### {t['package']} {t['installed'] or ''} — {t['severidad']}")
        L.append(f"- **Sección:** {t['section']}  ·  **Última npm:** {t['latest'] or 'n/d'}  ·  **Atraso:** {t['gap'] or 'al día'}")
        L.append("- **Riesgos conocidos:**")
        for r in t["riesgos_conocidos"]:
            L.append(f"    - {r}")
        L.append(f"- **Precisión técnica:** {t['precision_tecnica']}")
        L.append("- **Medidas de mitigación recomendadas:**")
        for m in t["mitigaciones"]:
            L.append(f"    - {m}")
        L.append("")

    leg = report.get("cumplimiento_legal") or []
    if leg:
        L.append("## Análisis de Cumplimiento Legal\n")
        for h in leg:
            L.append(f"### ⚖ {h['package']} — {h['nivel'].upper()} ({h['categoria']})")
            L.append(h["rationale"])
            for a in h.get("articulos", []):
                L.append(f"- **{a['art']}**: {a['texto']}")
            L.append(f"- **Recomendación:** {h.get('recomendacion') or ''}")
            L.append("")

    L.append("## Conclusión General\n")
    L.append(report["conclusion"] + "\n")
    return "\n".join(L)
