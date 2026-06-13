"""
Clasificador de verosimilitud de secretos (técnica de aprendizaje automático).

Implementa un modelo de REGRESIÓN LOGÍSTICA autocontenido (sin dependencias
externas obligatorias) que estima la probabilidad de que un literal detectado
sea un secreto REAL y utilizable (token, llave, contraseña) frente a un valor
de marcador de posición o ejemplo. La salida se usa en el motor de razonamiento
para:

  - subir la probabilidad de materialización cuando el literal parece un secreto
    real de alta confianza, y
  - degradar a "posible falso positivo" cuando parece un placeholder
    (p. ej. "your_api_key_here", "changeme", "xxxx", "example").

El modelo es DETERMINISTA y auditable: los coeficientes están fijados y
documentados (no requieren entrenamiento en tiempo de ejecución), de modo que
el mismo literal produce siempre el mismo puntaje. Si se desea, puede sustituirse
por un modelo entrenado con scikit-learn manteniendo la misma interfaz
`secret_probability(...) -> float`.

Las características (features) se derivan SOLO de propiedades estructurales del
literal y de su contexto léxico; nunca se transmite ni se registra el secreto.
"""

from __future__ import annotations

import math
import re

# Marcadores de posición habituales (señal fuerte de NO-secreto).
_PLACEHOLDERS = re.compile(
    r"(?i)(your[_-]?|my[_-]?|the[_-]?)?(api[_-]?key|secret|token|password|passwd|pwd|"
    r"key)([_-]?here|[_-]?goes[_-]?here)?$|^(changeme|change[_-]?me|example|sample|"
    r"placeholder|dummy|fake|test|todo|tbd|none|null|xxx+|0000+|1234+|abcd+|"
    r"\.\.\.|<.*>|\{\{.*\}\}|\$\{.*\}|%[a-z_]+%)$")

# Prefijos de proveedores conocidos (señal fuerte de secreto real).
_VENDOR_PREFIX = re.compile(
    r"^(sk_live_|sk_test_|pk_live_|rk_live_|AKIA|ASIA|AIza|ya29\.|ghp_|gho_|github_pat_|"
    r"xox[baprs]-|glpat-|eyJ[A-Za-z0-9_\-]+\.)")  # Stripe, AWS, Google, GitHub, Slack, GitLab, JWT


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_features(value: str, contexto: str = "") -> dict:
    """Deriva las características estructurales del literal candidato."""
    v = value or ""
    n = max(len(v), 1)
    ent = _shannon(v)
    clases = sum(bool(re.search(p, v)) for p in
                 (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return {
        "entropia": ent,                                   # 0..~6
        "longitud": len(v),                                # nº de caracteres
        "diversidad_clases": clases,                       # 1..4
        "prop_digitos": sum(c.isdigit() for c in v) / n,
        "es_base64": 1.0 if re.fullmatch(r"[A-Za-z0-9+/]{16,}={0,2}", v) else 0.0,
        "es_hex": 1.0 if re.fullmatch(r"[0-9a-fA-F]{16,}", v) else 0.0,
        "prefijo_proveedor": 1.0 if _VENDOR_PREFIX.search(v) else 0.0,
        "es_placeholder": 1.0 if _PLACEHOLDERS.search(v.strip()) else 0.0,
        "contexto_sensible": 1.0 if re.search(
            r"(?i)(api[_-]?key|secret|token|password|passwd|credential|auth)", contexto) else 0.0,
    }


# Coeficientes de la regresión logística (calibrados manualmente y documentados).
# logit = b0 + Σ wi·xi ;  P = sigmoide(logit).
_BIAS = -4.2
_W = {
    "entropia": 1.05,           # más entropía → más probable secreto real
    "longitud": 0.045,          # literales largos pesan, con tope (ver _cap)
    "diversidad_clases": 0.55,  # mezcla may/min/díg/símb → secreto real
    "prop_digitos": 0.4,
    "es_base64": 0.9,
    "es_hex": 0.7,
    "prefijo_proveedor": 4.5,   # prefijo de proveedor: casi certeza
    "es_placeholder": -5.0,     # placeholder: casi certeza de NO-secreto
    "contexto_sensible": 0.8,   # la variable se llama api_key/secret/token...
}


def _sigmoide(x: float) -> float:
    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def secret_probability(value: str, contexto: str = "") -> float:
    """Probabilidad [0,1] de que el literal sea un secreto real y utilizable."""
    f = extract_features(value, contexto)
    f["longitud"] = min(f["longitud"], 40)   # _cap: evita que literales enormes saturen
    logit = _BIAS + sum(_W[k] * f.get(k, 0.0) for k in _W)
    return round(_sigmoide(logit), 3)


def clasificar(value: str, contexto: str = "") -> dict:
    """Devuelve probabilidad + etiqueta + características (para trazabilidad)."""
    p = secret_probability(value, contexto)
    if p >= 0.75:
        etiqueta = "secreto probable (alta confianza)"
    elif p >= 0.45:
        etiqueta = "secreto posible (confianza media)"
    elif p >= 0.2:
        etiqueta = "indeterminado"
    else:
        etiqueta = "probable marcador de posición / falso positivo"
    return {"probabilidad": p, "etiqueta": etiqueta,
            "features": extract_features(value, contexto)}


def extraer_literal(evidencia: str) -> str:
    """Recupera el literal entre comillas más largo de un extracto de evidencia
    (la evidencia puede venir parcialmente enmascarada; se usa lo disponible)."""
    cands = re.findall(r"""["']([^"']{4,})["']""", evidencia or "")
    if cands:
        return max(cands, key=len)
    m = re.search(r"[A-Za-z0-9+/_\-]{8,}", evidencia or "")
    return m.group(0) if m else ""
