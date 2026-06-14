"""
Integración de motores de análisis estático OPEN SOURCE externos.

Robustece el análisis propio con motores de la industria, ejecutados de forma
SEGURA (análisis estático, sin ejecutar el código objetivo, con timeouts y sobre
el árbol ya extraído):

  - Semgrep   : SAST multi-lenguaje, con un conjunto de reglas LOCAL (offline)
                alineado a los controles normativos (ver semgrep_rules.yml).
  - detect-secrets (Yelp): detección de secretos por entropía y plugins.
  - Bandit    : SAST específico de Python.
  - njsscan (MobSF): SAST específico de Node.js / JavaScript (complementa a
                Bandit para el stack web).
  - Gitleaks  : detección de secretos por reglas+entropía (motor independiente;
                corrobora a detect-secrets en los mismos hallazgos).
  - Trivy     : escaneo del árbol de archivos — dependencias vulnerables (SCA),
                secretos y configuración insegura (IaC / Dockerfile / k8s).
  - RetireJS (retire): escáner de librerías JavaScript con vulnerabilidades
                conocidas; se instala por npm y NO depende de la versión de Python
                (cubre la dimensión JS cuando njsscan no está disponible, p.ej. 3.14+).

Cada motor cubre una DIMENSIÓN distinta para lograr defensa en profundidad:
secretos (detect-secrets + Gitleaks + Trivy), SAST Python (Bandit), SAST Node/JS
(njsscan + Semgrep), SAST multi-lenguaje (Semgrep), SCA + IaC (Trivy) y
librerías JS vulnerables (RetireJS).

Todos son OPCIONALES y se autodetectan: si no están instalados, la herramienta
funciona igual con su motor propio. Las salidas se NORMALIZAN al mismo esquema de
hallazgo (con contexto: rol del archivo, constructo y fragmento), de modo que el
informe trate todos los hallazgos de forma homogénea y trazable por motor.

Instalación (opcional):  pip install -r requirements-advanced.txt
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

import code_scan as CS

_SEMGREP_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "semgrep_rules.yml")

# Severidad de los motores externos → nuestra escala.
_SEV_MAP = {
    "ERROR": "alto", "WARNING": "medio", "INFO": "bajo",          # semgrep / njsscan
    "HIGH": "alto", "MEDIUM": "medio", "LOW": "bajo",             # bandit / trivy
    "CRITICAL": "crítico",
    "UNKNOWN": "bajo",                                            # trivy (sin severidad)
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
    # Adicionales aportados por njsscan / Trivy (best-effort, reutilizan IDs ya usados).
    "CWE-79":  ["D7-A8-PROTECCION-DATOS"],                        # XSS
    "CWE-94":  ["DS83-A31-ACCESO-NO-AUTORIZADO"],                 # inyección de código
    "CWE-95":  ["DS83-A31-ACCESO-NO-AUTORIZADO"],                 # eval dinámico
    "CWE-502": ["DS83-A31-ACCESO-NO-AUTORIZADO"],                 # deserialización insegura
    "CWE-352": ["D7-A8-PROTECCION-DATOS"],                        # CSRF
    "CWE-918": ["D9-A6-TLS", "D7-A8-PROTECCION-DATOS"],           # SSRF
    "CWE-1321": ["D7-A8-PROTECCION-DATOS"],                       # prototype pollution
}


def _rel_to_root(p: str, root: str) -> str:
    """Normaliza la ruta de un motor externo a ruta RELATIVA al `root` analizado.
    Los motores reportan rutas de forma heterogénea (absolutas, relativas al CWD,
    o relativas al source); homogeneizarlas es lo que permite que la corroboración
    entre motores y el motor interno funcione (la clave de dedup usa la ruta)."""
    if not p:
        return p
    candidatos = []
    if os.path.isabs(p):
        candidatos.append(p)
    else:
        candidatos.append(os.path.join(root, p))   # relativa al root / source
        candidatos.append(os.path.abspath(p))       # relativa al CWD
    for ap in candidatos:
        if os.path.exists(ap):
            try:
                return os.path.relpath(ap, root)
            except Exception:
                pass
    try:
        return os.path.relpath(os.path.abspath(p), root)
    except Exception:
        return p


def _exe(name: str) -> str | None:
    """Ruta COMPLETA del ejecutable de un motor, o None si no está.
    Imprescindible en Windows: los CLIs instalados por npm son `.CMD` y no se
    pueden lanzar por nombre con subprocess (sin shell) — sí por ruta completa."""
    return shutil.which(name)


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
    eng["njsscan"] = bool(shutil.which("njsscan"))
    eng["gitleaks"] = bool(shutil.which("gitleaks"))
    eng["trivy"] = bool(shutil.which("trivy"))
    eng["retire"] = bool(shutil.which("retire"))
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
    rel = _rel_to_root(rel, root)
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
    exe = _exe("semgrep")
    if not (exe and os.path.exists(_SEMGREP_RULES)):
        return []
    cmd = [exe, "--config", _SEMGREP_RULES, "--json", "--quiet",
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
            mm = re.search(r"CWE-\d+", str(cwe))
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
    exe = _exe("detect-secrets")
    if not exe:
        return []
    try:
        p = subprocess.run([exe, "scan", root], capture_output=True,
                           text=True, timeout=timeout)
        data = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out = []
    for path, items in (data.get("results", {}) or {}).items():
        rel = path  # _norm la normaliza a ruta relativa al root
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
    exe = _exe("bandit")
    if not exe:
        return []
    try:
        p = subprocess.run([exe, "-r", "-f", "json", "-q", root],
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


def run_njsscan(root: str, timeout: int = 180) -> list:
    """SAST de Node.js/JavaScript (MobSF njsscan). Estático, sin red ni ejecución."""
    exe = _exe("njsscan")
    if not exe:
        return []
    try:
        p = subprocess.run([exe, "--json", root], capture_output=True,
                           text=True, timeout=timeout)
        data = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out = []
    for seccion in ("nodejs", "templates"):
        for rule_id, info in (data.get(seccion) or {}).items():
            meta = info.get("metadata", {}) or {}
            cwe = meta.get("cwe")
            if cwe:
                mm = re.search(r"CWE-\d+", str(cwe))
                cwe = mm.group(0) if mm else None
            sev = _SEV_MAP.get(str(meta.get("severity", "")).upper(), "medio")
            titulo = (meta.get("description") or rule_id)[:80]
            mitig = meta.get("description") or "Revisar el patrón inseguro detectado por njsscan."
            for fobj in (info.get("files") or []):
                rel = fobj.get("file_path") or ""   # _norm la normaliza
                ml = fobj.get("match_lines") or []
                linea = ml[0] if ml else None
                out.append(_norm(
                    root, rel, linea, "NJS-" + str(rule_id), titulo,
                    "SAST EXTERNO (Node/JS)", sev,
                    fobj.get("match_string") or "", cwe, mitig, "njsscan"))
    return out


def run_gitleaks(root: str, timeout: int = 180) -> list:
    """Detección de secretos (Gitleaks). Motor independiente de detect-secrets:
    cuando ambos coinciden, el hallazgo queda corroborado."""
    exe = _exe("gitleaks")
    if not exe:
        return []
    rep, data = None, []
    try:
        fd, rep = tempfile.mkstemp(suffix=".json", prefix="gitleaks_")
        os.close(fd)
        cmd = [exe, "detect", "--source", root, "--no-git",
               "--report-format", "json", "--report-path", rep,
               "--redact", "--exit-code", "0", "--no-banner"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        with open(rep, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        data = []
    finally:
        if rep and os.path.exists(rep):
            try:
                os.remove(rep)
            except OSError:
                pass
    out = []
    for it in (data or []):
        rel = it.get("File") or ""   # _norm la normaliza a ruta relativa al root
        out.append(_norm(
            root, rel, it.get("StartLine"),
            "GL-" + str(it.get("RuleID", "secreto")),
            ("Secreto detectado: " + str(it.get("Description", "genérico")))[:80],
            "COMPARTIMENTAJE", "alto",
            it.get("Match") or it.get("Secret") or "", "CWE-798",
            "Remover el secreto del código y rotarlo; usar un gestor de secretos.",
            "gitleaks"))
    return out


def run_trivy(root: str, timeout: int = 300) -> list:
    """Trivy en modo filesystem: dependencias vulnerables (SCA), secretos y
    configuración insegura (IaC / Dockerfile / k8s). La base de vulnerabilidades
    se descarga una vez (usa el proxy del entorno); si falla, degrada a []."""
    exe = _exe("trivy")
    if not exe:
        return []
    cmd = [exe, "fs", "--quiet", "--format", "json",
           "--scanners", "vuln,secret,misconfig", "--timeout", "4m", root]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "TRIVY_DISABLE_VEX_NOTICE": "true"})
        data = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out = []
    for res in (data.get("Results") or []):
        rel = res.get("Target") or ""   # _norm la normaliza a ruta relativa al root
        # (1) Dependencias vulnerables (SCA): sin línea, ancladas al manifiesto.
        for v in (res.get("Vulnerabilities") or []):
            cwe = None
            cwes = v.get("CweIDs") or []
            if cwes:
                mm = re.search(r"CWE-\d+", str(cwes[0]))
                cwe = mm.group(0) if mm else None
            ev = f"{v.get('PkgName','')} {v.get('InstalledVersion','')} -> {v.get('VulnerabilityID','')}"
            fix = v.get("FixedVersion")
            mitig = (f"Actualizar {v.get('PkgName','')} a {fix}." if fix
                     else "Actualizar la dependencia a una versión sin la vulnerabilidad.")
            out.append(_norm(
                root, rel, None,
                "TRIVY-" + str(v.get("VulnerabilityID", "VULN")),
                (v.get("Title") or v.get("VulnerabilityID") or "Dependencia vulnerable")[:80],
                "DEPENDENCIA VULNERABLE (SCA)",
                _SEV_MAP.get(str(v.get("Severity", "")).upper(), "medio"),
                ev, cwe, mitig, "trivy"))
        # (2) Secretos embebidos.
        for s in (res.get("Secrets") or []):
            out.append(_norm(
                root, rel, s.get("StartLine"),
                "TRIVY-SEC-" + str(s.get("RuleID", "secreto")),
                ("Secreto detectado: " + str(s.get("Title", "genérico")))[:80],
                "COMPARTIMENTAJE",
                _SEV_MAP.get(str(s.get("Severity", "")).upper(), "alto"),
                s.get("Match") or "", "CWE-798",
                "Remover el secreto del código y rotarlo; usar un gestor de secretos.",
                "trivy"))
        # (3) Configuración insegura (IaC / Dockerfile / manifiestos k8s).
        for m in (res.get("Misconfigurations") or []):
            cm = m.get("CauseMetadata") or {}
            out.append(_norm(
                root, rel, cm.get("StartLine"),
                "TRIVY-CFG-" + str(m.get("ID", "config")),
                (m.get("Title") or "Configuración insegura")[:80],
                "CONFIGURACIÓN INSEGURA (IaC)",
                _SEV_MAP.get(str(m.get("Severity", "")).upper(), "medio"),
                (m.get("Message") or "")[:200], None,
                m.get("Resolution") or "Corregir la configuración según la recomendación de Trivy.",
                "trivy"))
    return out


def run_retirejs(root: str, timeout: int = 180) -> list:
    """RetireJS (npm): librerías JavaScript con vulnerabilidades conocidas.
    Estático, sin red de ejecución; se le pide salida JSON a un archivo temporal."""
    exe = _exe("retire")
    if not exe:
        return []
    rep, data = None, None
    try:
        fd, rep = tempfile.mkstemp(suffix=".json", prefix="retire_")
        os.close(fd)
        cmd = [exe, "--path", root, "--outputformat", "json",
               "--outputpath", rep, "--exitwith", "0"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        with open(rep, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        data = None
    finally:
        if rep and os.path.exists(rep):
            try:
                os.remove(rep)
            except OSError:
                pass
    if data is None:
        return []
    # Según la versión, la salida es una lista o un objeto con clave "data".
    entradas = data.get("data", []) if isinstance(data, dict) else data
    out = []
    for entry in (entradas or []):
        rel = entry.get("file") or ""
        for res in (entry.get("results") or []):
            comp = res.get("component", "lib")
            ver = res.get("version", "")
            for v in (res.get("vulnerabilities") or []):
                ids = v.get("identifiers", {}) or {}
                cves = ids.get("CVE") or []
                cve = cves[0] if cves else None
                titulo = (ids.get("summary") or f"{comp} {ver}: librería JS vulnerable")[:80]
                rid = "RETIRE-" + str(cve or ids.get("issue") or comp)
                out.append(_norm(
                    root, rel, None, rid, titulo,
                    "LIBRERÍA JS VULNERABLE (SCA)",
                    _SEV_MAP.get(str(v.get("severity", "")).upper(), "medio"),
                    f"{comp} {ver}" + (f" -> {cve}" if cve else ""), None,
                    f"Actualizar {comp} a una versión sin la vulnerabilidad reportada.",
                    "retire"))
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
    if sel.get("njsscan") and disp.get("njsscan"):
        f = run_njsscan(root); findings += f; corridos.append(("njsscan", len(f)))
    if sel.get("gitleaks") and disp.get("gitleaks"):
        f = run_gitleaks(root); findings += f; corridos.append(("gitleaks", len(f)))
    if sel.get("trivy") and disp.get("trivy"):
        f = run_trivy(root); findings += f; corridos.append(("trivy", len(f)))
    if sel.get("retire") and disp.get("retire"):
        f = run_retirejs(root); findings += f; corridos.append(("retire", len(f)))
    return {"findings": findings, "motores": corridos, "disponibles": disp}
