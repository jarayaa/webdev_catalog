"""
Integración de motores de análisis estático OPEN SOURCE externos.

Robustece el análisis propio con motores de la industria, ejecutados de forma
SEGURA (análisis estático, sin ejecutar el código objetivo, con timeouts y sobre
el árbol ya extraído):

  - Semgrep   : SAST multi-lenguaje, con un conjunto de reglas LOCAL (offline)
                alineado a los controles normativos (ver semgrep_rules.yml).
  - detect-secrets (Yelp): detección de secretos por entropía y plugins.
  - Bandit    : SAST específico de Python.

Todos son OPCIONALES y se autodetectan: si no están instalados, la herramienta
funciona igual con su motor propio. Las salidas se NORMALIZAN al mismo esquema de
hallazgo (con contexto: rol del archivo, constructo y fragmento), de modo que el
informe trate todos los hallazgos de forma homogénea y trazable por motor.

Instalación (opcional):  pip install -r requirements-advanced.txt
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import code_scan as CS

_SEMGREP_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "semgrep_rules.yml")

# Severidad de los motores externos → nuestra escala.
_SEV_MAP = {
    "ERROR": "alto", "WARNING": "medio", "INFO": "bajo",          # semgrep
    "HIGH": "alto", "MEDIUM": "medio", "LOW": "bajo",             # bandit
    "CRITICAL": "crítico",
}

# CWE → controles normativos (best-effort, para trazabilidad de cumplimiento).
_CWE_CONTROLES = {
    "CWE-798": ["D7-A8-CONTROL-ACCESO", "DS83-A28-ROBUSTEZ-CRED", "DS83-A29-CRED-TEXTO-CLARO"],
    "CWE-259": ["D7-A8-CONTROL-ACCESO", "DS83-A29-CRED-TEXTO-CLARO"],
    "CWE-321": ["D7-A8-CONTROL-ACCESO"],
    "CWE-327": ["D9-A6-CIFRADO-FACTOR", "DS83-A26-ANTIMALWARE-CIFRADO"],
    "CWE-89":  ["DS83-A31-ACCESO-NO-AUTORIZADO"],
    "CWE-319": ["D9-A6-TLS", "D7-A8-PROTECCION-DATOS", "DS83-A6-ATRIBUTOS"],
    "CWE-295": ["D9-A6-TLS"],
    "CWE-749": ["D7-A8-PROTECCION-DATOS"],
    "CWE-532": ["D9-A13-TRAZABILIDAD", "D7-A8-REGISTRO-EVENTOS"],
    "CWE-78":  ["DS83-A31-ACCESO-NO-AUTORIZADO"],
    "CWE-22":  ["DS83-A31-ACCESO-NO-AUTORIZADO"],
    "CWE-89-i": ["DS83-A31-ACCESO-NO-AUTORIZADO"],
}


def available_engines() -> dict:
    """Detecta qué motores externos están instalados (sin ejecutarlos)."""
    eng = {}
    eng["semgrep"] = bool(shutil.which("semgrep")) and os.path.exists(_SEMGREP_RULES)
    eng["detect-secrets"] = bool(shutil.which("detect-secrets"))
    try:
        import bandit  # noqa: F401
        eng["bandit"] = True
    except Exception:
        eng["bandit"] = bool(shutil.which("bandit"))
    return eng


def _ctx_for(root: str, rel: str, linea: int | None) -> dict:
    """Reconstruye el contexto (rol, constructo, fragmento) reutilizando los
    helpers del motor propio, para homogeneizar la presentación."""
    rol = CS._infer_file_role(rel)
    constructo, fragmento = "", []
    full = os.path.join(root, rel)
    if linea and os.path.exists(full):
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                lines = f.read(1_500_000).splitlines()
            idx0 = max(0, min(linea - 1, len(lines) - 1))
            constructo = CS._enclosing_construct(lines, idx0)
            fragmento = CS._context_window(lines, idx0)
        except Exception:
            pass
    return {"rol_archivo": rol, "constructo": constructo, "fragmento": fragmento}


def _norm(root, rel, linea, rule_id, titulo, categoria, severidad, evidencia,
          cwe, mitigacion, motor):
    controles = _CWE_CONTROLES.get(cwe or "", [])
    return {
        "rule_id": rule_id, "titulo": titulo, "categoria": categoria,
        "severidad": severidad, "archivo": rel, "linea": linea,
        "evidencia": CS._redact(evidencia or "")[:200],
        "guia": "Hallazgo aportado por motor externo; ver lineamientos SEGPRES de seguridad.",
        "legal": "A verificar contra el marco aplicable (no es asesoría legal).",
        "controles": controles, "cwe": cwe, "mitigacion": mitigacion,
        "motor": motor, "contexto": _ctx_for(root, rel, linea),
    }


def run_semgrep(root: str, timeout: int = 180) -> list:
    """Ejecuta Semgrep con el ruleset LOCAL (offline). No usa red."""
    if not (shutil.which("semgrep") and os.path.exists(_SEMGREP_RULES)):
        return []
    cmd = ["semgrep", "--config", _SEMGREP_RULES, "--json", "--quiet",
           "--metrics=off", "--timeout", "60", "--max-target-bytes", "2000000", root]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
        data = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        rel = os.path.relpath(r.get("path", ""), root)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        sev = _SEV_MAP.get(str(extra.get("severity", "")).upper(), "medio")
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        if cwe and "CWE-" in str(cwe):
            import re as _re
            mm = _re.search(r"CWE-\d+", str(cwe))
            cwe = mm.group(0) if mm else None
        out.append(_norm(
            root, rel, (r.get("start") or {}).get("line"),
            "SG-" + r.get("check_id", "regla").split(".")[-1],
            meta.get("titulo") or extra.get("message", "Hallazgo Semgrep")[:80],
            meta.get("categoria", "SAST EXTERNO"), sev,
            (extra.get("lines") or "")[:200], cwe,
            meta.get("mitigacion") or extra.get("message", "Revisar y corregir según el patrón detectado."),
            "semgrep"))
    return out


def run_detect_secrets(root: str, timeout: int = 120) -> list:
    if not shutil.which("detect-secrets"):
        return []
    try:
        p = subprocess.run(["detect-secrets", "scan", root], capture_output=True,
                           text=True, timeout=timeout)
        data = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out = []
    for path, items in (data.get("results", {}) or {}).items():
        rel = os.path.relpath(path, root) if os.path.isabs(path) else path
        for it in items:
            out.append(_norm(
                root, rel, it.get("line_number"),
                "DS-" + str(it.get("type", "secreto")).replace(" ", "-"),
                f"Secreto detectado: {it.get('type','genérico')}",
                "COMPARTIMENTAJE", "alto", it.get("type", ""), "CWE-798",
                "Remover el secreto del código y rotarlo; usar gestor de secretos.",
                "detect-secrets"))
    return out


def run_bandit(root: str, timeout: int = 120) -> list:
    if not (shutil.which("bandit")):
        return []
    try:
        p = subprocess.run(["bandit", "-r", "-f", "json", "-q", root],
                           capture_output=True, text=True, timeout=timeout)
        data = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        rel = os.path.relpath(r.get("filename", ""), root)
        cwe = (r.get("issue_cwe") or {}).get("id")
        cwe = f"CWE-{cwe}" if cwe else None
        out.append(_norm(
            root, rel, r.get("line_number"),
            "BANDIT-" + str(r.get("test_id", "")),
            r.get("test_name", "Hallazgo Bandit"),
            "SAST EXTERNO (Python)",
            _SEV_MAP.get(str(r.get("issue_severity", "")).upper(), "medio"),
            (r.get("code") or "")[:200], cwe,
            r.get("issue_text", "Revisar el patrón inseguro detectado por Bandit."),
            "bandit"))
    return out


def run_all(root: str, engines: dict | None = None) -> dict:
    """Ejecuta los motores disponibles (o los indicados) y devuelve hallazgos
    normalizados + la lista de motores que efectivamente corrieron."""
    disp = available_engines()
    sel = engines or disp
    findings, corridos = [], []
    if sel.get("semgrep") and disp.get("semgrep"):
        f = run_semgrep(root); findings += f; corridos.append(("semgrep", len(f)))
    if sel.get("detect-secrets") and disp.get("detect-secrets"):
        f = run_detect_secrets(root); findings += f; corridos.append(("detect-secrets", len(f)))
    if sel.get("bandit") and disp.get("bandit"):
        f = run_bandit(root); findings += f; corridos.append(("bandit", len(f)))
    return {"findings": findings, "motores": corridos, "disponibles": disp}
