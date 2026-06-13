"""
Análisis de flujo de datos (taint analysis) intra-archivo, ligero.

Aproxima el razonamiento "de ejecución" SIN ejecutar el código: rastrea, dentro
de un mismo archivo, datos que provienen de FUENTES no confiables (entrada de
usuario, parámetros de red, intents, etc.) hasta SUMIDEROS peligrosos (consultas
SQL, ejecución de comandos, carga de WebView, registros, escritura de archivos).

Cuando un identificador asignado desde una fuente alcanza un sumidero, se reporta
una RUTA DE FLUJO (fuente → sumidero) que eleva la explotabilidad del hallazgo
asociado y permite explicar el riesgo en términos de comportamiento en tiempo de
ejecución (qué entrada llega a qué operación sensible).

Limitaciones declaradas (honestidad de alcance): es intra-procedural y heurístico
(no resuelve alias, llamadas entre archivos ni flujo inter-procedural completo).
Su objetivo es señalar rutas plausibles de explotación, no probar formalmente la
ausencia de ellas. Complementa —no reemplaza— al análisis dinámico real.
"""

from __future__ import annotations

import re

# FUENTES de datos potencialmente controlados por un actor externo/usuario.
_SOURCES = [
    (re.compile(r"getIntent\(\)|getStringExtra|getSerializableExtra|extras?\.get"), "intent/extras de Android"),
    (re.compile(r"getText\(\)|\.text\b|editText"), "campo de texto de la interfaz"),
    (re.compile(r"getParameter|getQueryString|request\.|req\.(query|body|params)"), "parámetro de petición HTTP"),
    (re.compile(r"location\.(search|hash|href)|document\.URL|window\.name"), "URL/entorno del navegador"),
    (re.compile(r"readLine\(\)|Scanner\(|input\(\)|argv"), "entrada estándar / argumentos"),
    (re.compile(r"Uri\.parse|getData\(\)"), "URI entrante"),
]

# SUMIDEROS: operaciones donde un dato contaminado causa una vulnerabilidad.
_SINKS = [
    (re.compile(r"rawQuery\(|execSQL\(|\.query\(|createStatement\(|executeQuery\("), "consulta SQL", "CWE-89"),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Runtime\.exec|os\.system|subprocess\."), "ejecución de comando", "CWE-78"),
    (re.compile(r"loadUrl\(|loadData\(|loadDataWithBaseURL\(|evaluateJavascript\("), "carga en WebView", "CWE-749"),
    (re.compile(r"\beval\(|new Function\(|setInnerHTML|innerHTML\s*="), "evaluación dinámica / DOM", "CWE-95"),
    (re.compile(r"Log\.[vdiwe]\(|console\.log\(|println\(|System\.out"), "registro/log", "CWE-532"),
    (re.compile(r"new File\(|FileOutputStream\(|openFileOutput\(|fopen\("), "ruta de archivo", "CWE-22"),
]

# Patrón de asignación a un identificador: capta el nombre de la variable.
_ASSIGN = re.compile(r"^\s*(?:val|var|let|const|final|String|int|var|def)?\s*"
                     r"([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.+)$")
_IDENT = re.compile(r"[A-Za-z_]\w*")


def analyze_file(rel: str, lines: list) -> list:
    """Devuelve rutas de flujo detectadas en el archivo:
    [{archivo, fuente, fuente_linea, var, sumidero, sumidero_linea, cwe}]."""
    rutas = []
    # 1) Recolectar variables contaminadas (asignadas desde una fuente) y
    #    propagar un salto: si una asignación usa una variable ya contaminada en
    #    su lado derecho, la nueva variable también queda contaminada.
    tainted = {}     # nombre_var -> (linea, etiqueta_fuente)
    for ln, txt in enumerate(lines, start=1):
        m = _ASSIGN.match(txt)
        if not m:
            continue
        var, rhs = m.group(1), m.group(2)
        matched = False
        for rx, label in _SOURCES:
            if rx.search(rhs):
                tainted[var] = (ln, label)
                matched = True
                break
        if matched:
            continue
        # Propagación: RHS usa una variable contaminada.
        rhs_ids = set(_IDENT.findall(rhs))
        for tv, (tl, tlabel) in list(tainted.items()):
            if tv in rhs_ids and var != tv:
                tainted[var] = (tl, tlabel)   # hereda el origen
                break
    if not tainted:
        return rutas
    # 2) Buscar sumideros que usen una variable contaminada (en la misma o
    #    posterior línea).
    for ln, txt in enumerate(lines, start=1):
        for rx, sink_label, cwe in _SINKS:
            if not rx.search(txt):
                continue
            usados = set(_IDENT.findall(txt))
            for var, (src_ln, src_label) in tainted.items():
                if var in usados and src_ln <= ln:
                    rutas.append({
                        "archivo": rel, "fuente": src_label, "fuente_linea": src_ln,
                        "var": var, "sumidero": sink_label, "sumidero_linea": ln, "cwe": cwe,
                    })
                    break  # una ruta por sumidero basta
    return rutas


def analyze_text(rel: str, text: str) -> list:
    return analyze_file(rel, text.splitlines())
