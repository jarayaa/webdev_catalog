"""
Análisis estático de código fuente de aplicaciones (móviles u otras) contra:

  1) Guía Técnica "Lineamientos para el Desarrollo de Software" — División de
     Gobierno Digital, SEGPRES (v2.0, mayo 2021).
  2) Marco legal y normativo chileno aplicable:
       - Ley 19.628 sobre protección de la vida privada (datos personales).
       - Ley 21.096 (consagra constitucionalmente la protección de datos).
       - Ley 21.180 de Transformación Digital del Estado, y sus normas técnicas:
           · Decreto 7/2023  — Seguridad de la Información y Ciberseguridad.
           · Decreto 9/2023  — Autenticación (OIDC/OAuth2, cifrado de factores).
           · Decreto 10/2023 — Documentos y Expedientes Electrónicos.
           · Decreto 11/2023 — Calidad y Funcionamiento de Plataformas.
       - DS 83/2004 — Seguridad y Confidencialidad del Documento Electrónico.
       - Ley 21.459 de delitos informáticos.
  3) Buenas prácticas transversales (OWASP MASVS para móviles, OWASP ASVS).

Cada regla declara, además de la cláusula de la Guía y la norma legal, el
conjunto de CONTROLES normativos (ver regulatory.py) que su presencia incumple,
de modo que el motor de cumplimiento pueda construir la matriz de conformidad.

Es análisis ESTÁTICO basado en patrones (SAST ligero): detecta indicios, no
certeza absoluta. Cada hallazgo trae severidad, evidencia acotada, la cláusula
de la Guía y/o la norma legal que se incumpliría, y una mitigación sugerida.

Principio de mínima exposición (compartimentaje / necesidad de saber): el motor
solo reporta un EXTRACTO corto de evidencia (no vuelca archivos completos ni el
valor de los secretos), y redacta los posibles secretos antes de mostrarlos.

Rendimiento: el escaneo combina todos los patrones en UNA sola pasada por
archivo (regex unión con grupos nombrados) en lugar de recorrer el texto una vez
por regla, reduciendo el costo de O(reglas × longitud) a O(longitud).
"""

from __future__ import annotations

import math
import os
import re

# ----------------------------------------------------------------------------
# Catálogo de reglas. Cada regla:
#   id, titulo, categoria, severidad, patron (regex compilada), file_globs,
#   guia (cláusula de la Guía SEGPRES), legal (norma), mitigacion.
# Las categorías mapean a los 4 ejes pedidos:
#   COMPARTIMENTAJE  → principio de mínima exposición / necesidad de saber
#   DATOS_SENSIBLES  → manejo de información personal o sensible
#   NORMATIVO        → cumplimiento de la Guía Técnica (ámbito del desarrollo)
#   LEGAL            → cumplimiento legal (leyes citadas)
# ----------------------------------------------------------------------------

SEVERITY_RANK = {"crítico": 4, "alto": 3, "medio": 2, "bajo": 1, "info": 0}

# Extensiones de texto que se inspeccionan (evita binarios).
_TEXT_EXT = {
    ".java", ".kt", ".kts", ".xml", ".gradle", ".properties", ".json", ".js",
    ".ts", ".jsx", ".tsx", ".py", ".rb", ".php", ".go", ".cs", ".swift", ".m",
    ".h", ".c", ".cpp", ".yml", ".yaml", ".env", ".txt", ".md", ".cfg", ".ini",
    ".pro", ".smali", ".sql", ".sh", ".toml",
}

# Archivos cuyo nombre completo es relevante aunque no tengan extensión de texto.
_NAME_HINTS = ("dockerfile", "license", "copying", "proguard-rules.pro",
               "androidmanifest.xml", "google-services.json", ".env",
               "local.properties", "gradle.properties")


def _rx(p):
    return re.compile(p, re.IGNORECASE)


RULES = [
    # ---- SECRETOS EN CÓDIGO (Guía §14 manejo de secretos; §19 seeding) -------
    {
        "id": "SEC-API-KEY", "titulo": "Posible API key / token embebido en el código",
        "categoria": "COMPARTIMENTAJE", "severidad": "crítico",
        "patron": _rx(r"""(?:api[_-]?key|apikey|secret|token|client[_-]?secret|"""
                      r"""access[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']"""),
        "guia": "§14 Manejo de secretos: credenciales y llaves deben ir en variables "
                "de entorno, NUNCA en el control de versiones.",
        "legal": "Ley 21.459 Art. 2 (acceso ilícito) — un secreto filtrado facilita "
                 "el acceso no autorizado a sistemas.",
        "controles": ["D7-A8-CONTROL-ACCESO", "DS83-A28-ROBUSTEZ-CRED",
                      "DS83-A31-ACCESO-NO-AUTORIZADO"],
        "cwe": "CWE-798 (uso de credenciales embebidas)",
        "mitigacion": "Mover el secreto a variables de entorno / gestor de secretos; "
                      "rotar la credencial expuesta; excluir del repositorio (.gitignore).",
    },
    {
        "id": "SEC-GOOGLE-KEY", "titulo": "Google API key embebida",
        "categoria": "COMPARTIMENTAJE", "severidad": "alto",
        "patron": _rx(r"AIza[0-9A-Za-z_\-]{35}"),
        "guia": "§14 Manejo de secretos.",
        "legal": "Ley 19.628 (si la key da acceso a datos personales) · Ley 21.459 Art. 2.",
        "controles": ["D7-A8-CONTROL-ACCESO"],
        "cwe": "CWE-798",
        "mitigacion": "Restringir la key por aplicación/SHA y paquete; moverla a "
                      "configuración remota; rotarla.",
    },
    {
        "id": "SEC-PRIVATE-KEY", "titulo": "Llave privada / certificado en el repositorio",
        "categoria": "COMPARTIMENTAJE", "severidad": "crítico",
        "patron": _rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "guia": "§14 Manejo de secretos: certificados y llaves no deben versionarse.",
        "legal": "Ley 21.459 Art. 2 y 7 (interceptación/acceso); Ley 19.628 si protege datos.",
        "controles": ["D7-A8-CONTROL-ACCESO", "DS83-A28-ROBUSTEZ-CRED"],
        "cwe": "CWE-321 (clave criptográfica embebida)",
        "mitigacion": "Eliminar del repositorio e historial; rotar la llave; "
                      "almacenar en KMS/HSM o variable de entorno.",
    },
    {
        "id": "SEC-PASSWORD", "titulo": "Contraseña en texto plano en el código",
        "categoria": "COMPARTIMENTAJE", "severidad": "alto",
        "patron": _rx(r"""(?:password|passwd|pwd|contrasena|clave)\s*[:=]\s*["'][^"'\s]{4,}["']"""),
        "guia": "§14 Manejo de secretos; §19 Seeding (credenciales fuera del versionado).",
        "legal": "Ley 19.628 (seguridad de datos); Ley 21.459 Art. 2.",
        "controles": ["D9-A6-CIFRADO-FACTOR", "D7-A8-CONTROL-ACCESO", "DS83-A28-ROBUSTEZ-CRED"],
        "cwe": "CWE-259 (contraseña embebida)",
        "mitigacion": "Externalizar a variables de entorno; nunca hardcodear credenciales.",
    },
    {
        "id": "SEC-DB-URL", "titulo": "Cadena de conexión con credenciales",
        "categoria": "COMPARTIMENTAJE", "severidad": "alto",
        "patron": _rx(r"(?:jdbc:|mongodb(?:\+srv)?://|postgres(?:ql)?://|mysql://)[^\s\"']*:[^\s\"'@]+@"),
        "guia": "§14 Manejo de secretos.",
        "legal": "Ley 19.628; Ley 21.459 Art. 2.",
        "controles": ["D7-A8-CONTROL-ACCESO", "DS83-A28-ROBUSTEZ-CRED",
                      "DS83-A31-ACCESO-NO-AUTORIZADO"],
        "cwe": "CWE-798",
        "mitigacion": "Parametrizar el connection string; credenciales por entorno.",
    },

    # ---- CRIPTOGRAFÍA / DATOS (Guía §11-13 datos; §5 contraseñas) ------------
    {
        "id": "CRY-WEAK-HASH", "titulo": "Hash débil para datos sensibles (MD5/SHA-1)",
        "categoria": "DATOS_SENSIBLES", "severidad": "medio",
        "patron": _rx(r"""(?:MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-1)["']|"""
                      r"""\bMD5\b|hashlib\.(?:md5|sha1)\()"""),
        "guia": "§5 Para almacenar contraseñas usar bcrypt/PBKDF2/Argon2; evitar MD5/SHA-1/SHA-2 'a secas'.",
        "legal": "Ley 19.628 (deber de seguridad sobre datos personales).",
        "controles": ["D9-A6-CIFRADO-FACTOR", "D7-A8-PROTECCION-DATOS", "DS83-A6-ATRIBUTOS",
                      "DS83-A26-ANTIMALWARE-CIFRADO", "D10-INTEGRIDAD-DOC"],
        "cwe": "CWE-327 (algoritmo criptográfico débil)",
        "mitigacion": "Usar bcrypt/PBKDF2/Argon2 para contraseñas; SHA-256+ con sal donde aplique.",
    },
    {
        "id": "CRY-ECB", "titulo": "Cifrado en modo ECB (inseguro)",
        "categoria": "DATOS_SENSIBLES", "severidad": "alto",
        "patron": _rx(r"""Cipher\.getInstance\(\s*["'][A-Z]+/ECB"""),
        "guia": "§13 Datos en reposo: proteger con cifrado correcto.",
        "legal": "Ley 19.628.",
        "controles": ["D7-A8-PROTECCION-DATOS", "DS83-A6-ATRIBUTOS",
                      "DS83-A26-ANTIMALWARE-CIFRADO", "D10-INTEGRIDAD-DOC"],
        "cwe": "CWE-327",
        "mitigacion": "Usar AES-GCM (modo autenticado) con IV aleatorio por mensaje.",
    },
    {
        "id": "NET-CLEARTEXT", "titulo": "Tráfico en texto claro (HTTP) permitido",
        "categoria": "DATOS_SENSIBLES", "severidad": "alto",
        "patron": _rx(r"(?:cleartextTrafficPermitted\s*=\s*\"true\"|usesCleartextTraffic\s*=\s*\"true\"|http://(?!localhost|127\.0\.0\.1|schemas\.android))"),
        "guia": "§12 Datos en tránsito: siempre TLS (idealmente 1.3).",
        "legal": "Ley 19.628 (datos en tránsito); Ley 21.459 Art. 7 (interceptación).",
        "controles": ["D9-A6-TLS", "D7-A8-PROTECCION-DATOS", "DS83-A6-ATRIBUTOS",
                      "DS83-A29-CRED-TEXTO-CLARO"],
        "cwe": "CWE-319 (transmisión en texto claro de datos sensibles)",
        "mitigacion": "Forzar HTTPS/TLS; android:usesCleartextTraffic=false; network-security-config restrictivo.",
    },
    {
        "id": "NET-TRUST-ALL", "titulo": "Validación TLS deshabilitada (acepta cualquier certificado)",
        "categoria": "DATOS_SENSIBLES", "severidad": "crítico",
        "patron": _rx(r"(?:TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|HostnameVerifier[^;]*return\s+true)"),
        "guia": "§12 Datos en tránsito: configurar el cifrado más fuerte; validar certificados.",
        "legal": "Ley 21.459 Art. 7 (interceptación de datos); Ley 19.628.",
        "controles": ["D9-A6-TLS", "D7-A8-PROTECCION-DATOS", "DS83-A6-ATRIBUTOS"],
        "cwe": "CWE-295 (validación incorrecta de certificado)",
        "mitigacion": "No deshabilitar la validación TLS; usar certificate pinning si corresponde.",
    },

    # ---- MANEJO DE ERRORES / DEBUG (Guía §21 fallar seguro) -----------------
    {
        "id": "DBG-ENABLED", "titulo": "Modo debug habilitado",
        "categoria": "NORMATIVO", "severidad": "medio",
        "patron": _rx(r"(?:android:debuggable\s*=\s*\"true\"|DEBUG\s*=\s*[Tt]rue|debug\s*:\s*true)"),
        "guia": "§21 Manejo seguro de errores: desactivar el modo debug al pasar a producción.",
        "legal": "Ley 19.628 (exposición de datos por trazas/depuración).",
        "controles": ["D7-A8-REGISTRO-EVENTOS"],
        "cwe": "CWE-489 (código de depuración activo)",
        "mitigacion": "Desactivar debug en builds de producción (release).",
    },
    {
        "id": "LOG-SENSITIVE", "titulo": "Posible registro (log) de información sensible",
        "categoria": "DATOS_SENSIBLES", "severidad": "medio",
        "patron": _rx(r"""(?:Log\.[dvwie]|console\.log|print(?:ln)?|System\.out\.print)\s*\([^)]*"""
                      r"""(?:password|token|secret|rut|email|tarjeta|card|cvv|pin)\b"""),
        "guia": "§20 Logs: nunca registrar información sensible en los logs.",
        "legal": "Ley 19.628 (tratamiento y seguridad de datos personales).",
        "controles": ["D9-A13-TRAZABILIDAD", "D9-A14-DATOS-PERSONALES",
                      "D7-A8-REGISTRO-EVENTOS", "D10-INTEGRIDAD-DOC"],
        "cwe": "CWE-532 (inserción de información sensible en logs)",
        "mitigacion": "Eliminar/ofuscar datos sensibles de los logs; usar niveles de log adecuados.",
    },

    # ---- DATOS PERSONALES (Ley 19.628) — detección de tratamiento -----------
    {
        "id": "PII-RUT", "titulo": "Tratamiento de RUT (dato personal identificador)",
        "categoria": "LEGAL", "severidad": "info",
        "patron": _rx(r"\b(?:rut|run)\b"),
        "guia": "§11 Identificación de datos: los datos sensibles deben identificarse y protegerse.",
        "legal": "Ley 19.628 Art. 4 (consentimiento) y Art. 11 (seguridad). El RUT es dato personal.",
        "controles": ["D9-A14-DATOS-PERSONALES", "D10-INTEGRIDAD-DOC"],
        "cwe": "CWE-359 (exposición de información personal privada)",
        "mitigacion": "Verificar base de licitud, finalidad informada y cifrado en reposo/tránsito del RUT.",
    },
    {
        "id": "PERM-DANGEROUS", "titulo": "Permiso Android sensible declarado",
        "categoria": "DATOS_SENSIBLES", "severidad": "medio",
        "patron": _rx(r"android\.permission\.(?:ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|"
                      r"READ_CONTACTS|READ_SMS|RECORD_AUDIO|CAMERA|READ_PHONE_STATE|"
                      r"READ_EXTERNAL_STORAGE|READ_CALL_LOG|BODY_SENSORS)"),
        "guia": "§11 Identificación de datos; principio de minimización.",
        "legal": "Ley 19.628 Art. 4 y 9 (finalidad y proporcionalidad del tratamiento).",
        "controles": ["DS83-A31-ACCESO-NO-AUTORIZADO"],
        "cwe": "CWE-250 (ejecución con privilegios innecesarios)",
        "mitigacion": "Aplicar minimización: declarar solo permisos imprescindibles para la finalidad; "
                      "justificar cada uno y solicitarlos en tiempo de ejecución.",
    },

    # ---- INYECCIÓN (Guía §2 consultas seguras) ------------------------------
    {
        "id": "SQL-CONCAT", "titulo": "Posible SQL construido por concatenación (riesgo de inyección)",
        "categoria": "NORMATIVO", "severidad": "alto",
        "patron": _rx(r"""(?:rawQuery|execSQL|executeQuery|db\.query)\s*\([^)]*\+[^)]*"""
                      r"""|["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+"""),
        "guia": "§2 Consultas seguras: usar ORM probado o prepared statements; no concatenar SQL.",
        "legal": "Ley 21.459 Art. 1 y 4 (acceso/alteración indebida vía inyección); Ley 19.628.",
        "controles": ["DS83-A31-ACCESO-NO-AUTORIZADO"],
        "cwe": "CWE-89 (inyección SQL)",
        "mitigacion": "Usar consultas parametrizadas / prepared statements / ORM.",
    },

    # ---- WEBVIEW INSEGURO (Guía §2/§13; OWASP MASVS) ------------------------
    {
        "id": "WEB-JS-BRIDGE", "titulo": "WebView con JavaScript o bridge nativo habilitado",
        "categoria": "DATOS_SENSIBLES", "severidad": "medio",
        "patron": _rx(r"(?:setJavaScriptEnabled\s*\(\s*true\s*\)|addJavascriptInterface\s*\(|"
                      r"setAllowFileAccess\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\))"),
        "guia": "§2 Consultas seguras / §13 datos: limitar la superficie de ejecución de contenido remoto.",
        "legal": "Ley 21.459 Art. 1 (afectación de integridad del sistema vía contenido remoto).",
        "controles": ["D7-A8-PROTECCION-DATOS", "DS83-A31-ACCESO-NO-AUTORIZADO"],
        "cwe": "CWE-749 (método peligroso expuesto) / CWE-79",
        "mitigacion": "Deshabilitar JavaScript salvo necesidad; no exponer interfaces nativas a "
                      "contenido no confiable; restringir acceso a archivos.",
    },

    # ---- COPIA DE SEGURIDAD / EXPORTACIÓN DE DATOS (Ley 19.628; DS 83) -------
    {
        "id": "DATA-BACKUP-ON", "titulo": "Copia de seguridad de la app habilitada (allowBackup)",
        "categoria": "DATOS_SENSIBLES", "severidad": "medio",
        "patron": _rx(r"android:allowBackup\s*=\s*\"true\""),
        "guia": "§13 Datos en reposo: evitar respaldos no controlados que extraigan datos del sandbox.",
        "legal": "Ley 19.628 (seguridad del dato personal en reposo).",
        "controles": ["D7-A8-PROTECCION-DATOS", "DS83-A6-ATRIBUTOS"],
        "cwe": "CWE-530 (exposición de datos por respaldo)",
        "mitigacion": "Establecer android:allowBackup=false o definir reglas de respaldo que "
                      "excluyan datos sensibles.",
    },
    {
        "id": "COMP-EXPORTED", "titulo": "Componente Android exportado sin protección",
        "categoria": "DATOS_SENSIBLES", "severidad": "medio",
        "patron": _rx(r"android:exported\s*=\s*\"true\""),
        "guia": "§2 Consultas seguras / minimización de superficie expuesta.",
        "legal": "Ley 21.459 Art. 2 (acceso ilícito a componentes expuestos).",
        "controles": ["DS83-A31-ACCESO-NO-AUTORIZADO", "D7-A8-CONTROL-ACCESO"],
        "cwe": "CWE-926 (exportación indebida de componentes)",
        "mitigacion": "Exportar solo lo imprescindible; proteger con permisos de firma; "
                      "validar el origen de los Intents recibidos.",
    },

    # ---- LICENCIAMIENTO (Guía §IX) ------------------------------------------
    {
        "id": "LIC-MISSING", "titulo": "Sin archivo de licencia (LICENSE/COPYING)",
        "categoria": "LEGAL", "severidad": "bajo", "patron": None,  # se evalúa aparte
        "guia": "§IX Licencias: todo desarrollo del Estado debe estar licenciado (LICENSE/COPYING).",
        "legal": "Marco de software público del Estado (Guía SEGPRES §IX).",
        "controles": ["D11-LICENCIAMIENTO"],
        "cwe": None,
        "mitigacion": "Agregar archivo LICENSE con el texto íntegro de la licencia (p. ej. GPLv3).",
    },
]


# ----------------------------------------------------------------------------
def _redact(snippet: str) -> str:
    """Compartimentaje: nunca exponer el valor del secreto. Mantiene contexto,
    enmascara el literal."""
    def mask(m):
        s = m.group(0)
        # conserva primeros 3 y últimos 2 caracteres del valor
        body = re.sub(r"""(["'])([^"']{6,})(["'])""",
                      lambda mm: mm.group(1) + mm.group(2)[:3] + "…[REDACTADO]…"
                      + mm.group(2)[-2:] + mm.group(3), s)
        return body
    return re.sub(r"""["'][A-Za-z0-9_\-]{12,}["']""", mask, snippet)[:200]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Patrones que delatan uso de OpenID Connect / OAuth 2.0 (control de presencia D9).
_OIDC_HINT = re.compile(
    r"(openid|oauth2?|claveunica|clave[\s_-]?única|id_token|authorization_code|"
    r"AppAuth|net\.openid|/oauth/authorize|response_type=code|code_challenge)", re.I)


# Inferencia del ROL funcional del archivo a partir de su nombre/ruta. Es parte de
# la "inteligencia local": permite explicar la observación en el contexto real de
# uso del código (qué hace ese archivo dentro de la aplicación).
_FILE_ROLE_RULES = [
    (re.compile(r"(token|auth|login|credential|session|sesi[oó]n|secret|keystore|"
                r"oauth|claveunica)", re.I),
     "gestión de credenciales y sesión de usuario"),
    (re.compile(r"google-services|firebase|\.env|secrets?\.|config\.(?:json|properties)|"
                r"local\.properties", re.I),
     "configuración de servicios externos / parámetros sensibles"),
    (re.compile(r"androidmanifest\.xml$", re.I),
     "manifiesto de la aplicación (configuración global de seguridad y componentes)"),
    (re.compile(r"\.gradle(\.kts)?$|gradle-wrapper|libs\.versions\.toml$", re.I),
     "definición de build y dependencias del proyecto"),
    (re.compile(r"(dao|repository|repositorio|database|\bdb\b|room|datastore|sql|"
                r"entity|persistence)", re.I),
     "acceso y persistencia de datos"),
    (re.compile(r"(network|networking|http|api|retrofit|okhttp|client|service|ws|"
                r"socket|conexi[oó]n)", re.I),
     "comunicación de red con servicios remotos"),
    (re.compile(r"(activity|fragment|screen|compose|view\b|ui|adapter|viewmodel)", re.I),
     "capa de interfaz de usuario"),
    (re.compile(r"(model|entity|dto|domain|dominio|pojo|bean)", re.I),
     "modelo de dominio / estructuras de datos"),
    (re.compile(r"(util|helper|common|core|base)", re.I),
     "utilidades transversales del proyecto"),
]

# Firmas de declaración (clase / función / método) para localizar el constructo
# que contiene un hallazgo. Cubre Kotlin/Java, Python, JS/TS y XML.
_DECL_RE = re.compile(
    r"^\s*(?:@\w+\s+)*"
    r"(?:public|private|protected|internal|open|final|abstract|suspend|static|"
    r"override|export|default|async|fun|def|class|interface|object|void|val|var)"
    r"[\w\s<>,\.\[\]]*?"
    r"(?:class|interface|object|fun|def)?\s*"
    r"([A-Za-z_]\w*)\s*[\(:{<]")


def _infer_file_role(rel: str) -> str:
    base = (rel or "").split("/")[-1]
    for rx, role in _FILE_ROLE_RULES:
        if rx.search(rel) or rx.search(base):
            return role
    return "componente de la aplicación"


def _enclosing_construct(lines: list, idx0: int) -> str:
    """Busca hacia arriba la declaración (clase/función/método) que contiene la
    línea idx0 (0-based). Devuelve una etiqueta legible o '' si no aplica."""
    for j in range(idx0, max(idx0 - 60, -1), -1):
        ln = lines[j]
        m = _DECL_RE.match(ln)
        if m:
            kind = "función/método"
            low = ln.lower()
            if "class " in low or "interface " in low or "object " in low:
                kind = "clase/objeto"
            return f"{kind} «{m.group(1)}»"
    return ""


def _context_window(lines: list, idx0: int, before: int = 2, after: int = 2) -> list:
    """Devuelve un fragmento redactado alrededor de la línea (para evidencia
    contextual). Cada elemento es (nº_línea, texto_redactado, es_la_línea)."""
    lo = max(idx0 - before, 0)
    hi = min(idx0 + after, len(lines) - 1)
    out = []
    for k in range(lo, hi + 1):
        out.append((k + 1, _redact(lines[k].rstrip())[:160], k == idx0))
    return out


def scan_file(path: str, rel: str, max_findings_per_rule: int = 50) -> list[dict]:
    """Escanea un archivo de texto contra las reglas basadas en patrón.

    Optimización: en lugar de recorrer el texto una vez por regla (O(reglas×n)),
    se hace UNA pasada por las líneas y, dentro de cada línea, se prueban los
    patrones. Para archivos grandes esto reduce notablemente el costo de CPU.

    Cada hallazgo incorpora CONTEXTO local (rol del archivo, constructo que lo
    contiene y un fragmento de código alrededor) para sustentar un análisis no
    genérico, situado en el uso real del código.
    """
    findings = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(1_500_000)  # cota de memoria por archivo
    except Exception:
        return findings
    lines = text.splitlines()
    pii_seen = set()       # dedup de PII por (regla, archivo): basta una observación
    per_rule_count = {}    # rule_id -> nº hallazgos en este archivo

    _patterned = [r for r in RULES if r["patron"] is not None]
    file_role = _infer_file_role(rel)

    for ln, line_text in enumerate(lines, start=1):
        stripped = line_text.strip()
        if not stripped:
            continue
        # Ignorar líneas de comentario (menos ruido) una sola vez por línea.
        is_comment = stripped.startswith(("#", "//", "*", "/*", "<!--"))
        if is_comment:
            continue
        for rule in _patterned:
            rid = rule["id"]
            if per_rule_count.get(rid, 0) >= max_findings_per_rule:
                continue
            if not rule["patron"].search(line_text):
                continue
            # PII informativa: una sola observación por archivo (evita inundar).
            if rule["severidad"] == "info":
                key = (rid, rel)
                if key in pii_seen:
                    continue
                pii_seen.add(key)
            idx0 = ln - 1
            findings.append({
                "rule_id": rid, "titulo": rule["titulo"],
                "categoria": rule["categoria"], "severidad": rule["severidad"],
                "archivo": rel, "linea": ln, "evidencia": _redact(stripped),
                "guia": rule["guia"], "legal": rule["legal"],
                "controles": rule.get("controles", []),
                "cwe": rule.get("cwe"),
                "mitigacion": rule["mitigacion"],
                "contexto": {
                    "rol_archivo": file_role,
                    "constructo": _enclosing_construct(lines, idx0),
                    "fragmento": _context_window(lines, idx0),
                },
            })
            per_rule_count[rid] = per_rule_count.get(rid, 0) + 1
    return findings


def _taint_ctx(root: str, rel: str, linea: int) -> dict:
    """Contexto (rol, constructo, fragmento) para un hallazgo de flujo de datos."""
    rol = _infer_file_role(rel)
    constructo, fragmento = "", []
    full = os.path.join(root, rel)
    if linea and os.path.exists(full):
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                lines = f.read(1_500_000).splitlines()
            idx0 = max(0, min(linea - 1, len(lines) - 1))
            constructo = _enclosing_construct(lines, idx0)
            fragmento = _context_window(lines, idx0)
        except Exception:
            pass
    return {"rol_archivo": rol, "constructo": constructo, "fragmento": fragmento}


def scan_tree(root: str, max_files: int = 5000, run_external: bool = False,
              engines: dict | None = None) -> dict:
    """Recorre el árbol extraído y agrega hallazgos + análisis funcional.
    También recolecta los manifiestos de dependencias (build.gradle, package.json,
    libs.versions.toml) para que los componentes se integren al inventario.

    Si run_external es True, complementa el motor propio con: (a) análisis de
    flujo de datos (taint) intra-archivo y (b) motores SAST OSS disponibles
    (Semgrep, detect-secrets, Bandit). Todo es opcional y se degrada con
    elegancia si las herramientas no están instaladas."""
    findings = []
    file_count = 0
    ext_count = {}
    has_license = False
    manifest_perms = set()
    languages = {}
    skipped = 0
    auth_oidc = False      # indicio de OpenID Connect / OAuth2 (control D9 de presencia)
    build_manifests = []   # (tipo, ruta_relativa, contenido) para el inventario
    _gradle_main = {"build": None, "toml": None}
    taint_paths = []       # rutas de flujo fuente→sumidero (análisis "dinámico")
    _CODE_EXT = {".kt", ".java", ".js", ".ts", ".py", ".swift", ".dart"}

    for dirpath, dirnames, filenames in os.walk(root):
        # No descender en dependencias/binarios voluminosos.
        dirnames[:] = [d for d in dirnames if d.lower() not in (
            "node_modules", ".git", "build", ".gradle", "pods", "dist")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            low = fn.lower()
            if low in ("license", "copying", "license.txt", "copying.txt"):
                has_license = True
            ext = os.path.splitext(fn)[1].lower()
            ext_count[ext or "(sin)"] = ext_count.get(ext or "(sin)", 0) + 1
            # mapa de lenguaje (análisis funcional)
            lang = {".kt": "Kotlin", ".java": "Java", ".swift": "Swift",
                    ".js": "JavaScript", ".ts": "TypeScript", ".dart": "Dart",
                    ".py": "Python"}.get(ext)
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            if file_count >= max_files:
                skipped += 1
                continue
            if ext in _TEXT_EXT or low in _NAME_HINTS:
                file_count += 1
                findings.extend(scan_file(full, rel))
                # Análisis de flujo de datos (taint) para archivos de código.
                if run_external and ext in _CODE_EXT:
                    try:
                        import taint as _T
                        with open(full, encoding="utf-8", errors="replace") as f:
                            taint_paths.extend(_T.analyze_text(rel, f.read(1_500_000)))
                    except Exception:
                        pass
                # Indicio de OpenID Connect / OAuth2 en código/config (control D9).
                if not auth_oidc and ext in (".kt", ".java", ".xml", ".gradle",
                                             ".kts", ".json", ".properties", ".toml"):
                    try:
                        with open(full, encoding="utf-8", errors="replace") as f:
                            head = f.read(200_000)
                        if _OIDC_HINT.search(head):
                            auth_oidc = True
                    except Exception:
                        pass
                if low == "androidmanifest.xml":
                    try:
                        with open(full, encoding="utf-8", errors="replace") as f:
                            mf = f.read(500_000)
                        manifest_perms.update(re.findall(r"android\.permission\.[A-Z_]+", mf))
                    except Exception:
                        pass
                # Recolección de manifiestos de dependencias (para el inventario).
                try:
                    if low == "package.json" and "/test" not in rel.lower():
                        with open(full, encoding="utf-8", errors="replace") as f:
                            build_manifests.append(("npm", rel, f.read(400_000)))
                    elif low in ("build.gradle", "build.gradle.kts"):
                        with open(full, encoding="utf-8", errors="replace") as f:
                            c = f.read(400_000)
                        build_manifests.append(("gradle", rel, c))
                        # El módulo con más 'implementation' suele ser el principal.
                        n_impl = c.count("implementation")
                        if _gradle_main["build"] is None or n_impl > _gradle_main["build"][1]:
                            _gradle_main["build"] = (c, n_impl)
                    elif low == "libs.versions.toml":
                        with open(full, encoding="utf-8", errors="replace") as f:
                            _gradle_main["toml"] = f.read(400_000)
                except Exception:
                    pass

    # Regla de licencia ausente (a nivel de proyecto)
    if not has_license:
        lic = next(r for r in RULES if r["id"] == "LIC-MISSING")
        findings.append({
            "rule_id": lic["id"], "titulo": lic["titulo"], "categoria": lic["categoria"],
            "severidad": lic["severidad"], "archivo": "(raíz del proyecto)", "linea": None,
            "evidencia": "No se encontró LICENSE/COPYING en el árbol del proyecto.",
            "guia": lic["guia"], "legal": lic["legal"],
            "controles": lic.get("controles", []), "cwe": lic.get("cwe"),
            "mitigacion": lic["mitigacion"],
            "contexto": {"rol_archivo": "raíz del repositorio del proyecto",
                         "constructo": "", "fragmento": []},
        })

    # Marca de motor propio en cada hallazgo (provenance).
    for f in findings:
        f.setdefault("motor", "interno")

    motores_ext = []
    engines_disp = {}
    if run_external:
        # (a) Motores SAST OSS externos (opcionales).
        try:
            import sast_external as _SE
            ext = _SE.run_all(root, engines)
            engines_disp = ext.get("disponibles", {})
            motores_ext = ext.get("motores", [])
            # Fusión con deduplicación: si un hallazgo externo coincide con uno
            # propio en (archivo, línea, cwe/categoría), se anota corroboración en
            # lugar de duplicar; si no, se agrega como hallazgo nuevo.
            def _clave(x):
                import re as _re
                cwe = x.get("cwe") or ""
                mm = _re.search(r"CWE-\d+", str(cwe))
                cwe_norm = mm.group(0) if mm else (x.get("categoria") or "")
                linea = x.get("linea")
                if linea is None:
                    # Hallazgos sin línea (SCA de dependencias, licencia, etc.): si se
                    # dedujeran por (archivo, None, CWE) se fusionarían CVEs DISTINTOS de
                    # un mismo paquete con igual CWE. Se discrimina por CVE (corrobora el
                    # mismo CVE entre motores) o, en su defecto, por rule_id.
                    cve = _re.search(r"CVE-\d{4}-\d+",
                                     f"{x.get('rule_id','')} {x.get('evidencia','')}")
                    disc = cve.group(0) if cve else (x.get("rule_id") or cwe_norm)
                    return (x.get("archivo"), None, disc)
                return (x.get("archivo"), linea, cwe_norm)
            idx = {}
            for f in findings:
                idx.setdefault(_clave(f), f)
            for ef in ext.get("findings", []):
                k = _clave(ef)
                if k in idx:
                    base = idx[k]
                    corr = set(base.get("corroborado_por", []))
                    corr.add(ef.get("motor", "externo"))
                    base["corroborado_por"] = sorted(corr)
                else:
                    findings.append(ef)
                    idx[k] = ef
        except Exception:
            pass

    # (b) Marca de explotabilidad por flujo de datos (taint): si un hallazgo cae
    #     sobre la línea de un sumidero alcanzado por una fuente, se adjunta la
    #     ruta y se marca como alcanzable por entrada externa.
    _TAINT_SEV = {"CWE-89": "alto", "CWE-78": "crítico", "CWE-749": "alto",
                  "CWE-95": "alto", "CWE-532": "medio", "CWE-22": "medio"}
    _TAINT_CTRL = {"CWE-89": ["DS83-A31-ACCESO-NO-AUTORIZADO"],
                   "CWE-78": ["DS83-A31-ACCESO-NO-AUTORIZADO"],
                   "CWE-749": ["D7-A8-PROTECCION-DATOS"],
                   "CWE-95": ["D7-A8-PROTECCION-DATOS"],
                   "CWE-532": ["D9-A13-TRAZABILIDAD", "D7-A8-REGISTRO-EVENTOS"],
                   "CWE-22": ["DS83-A31-ACCESO-NO-AUTORIZADO"]}
    if taint_paths:
        sink_idx = {}
        for tp in taint_paths:
            sink_idx.setdefault((tp["archivo"], tp["sumidero_linea"]), tp)
        existentes = {(f.get("archivo"), f.get("linea")) for f in findings}
        for f in findings:
            tp = sink_idx.get((f.get("archivo"), f.get("linea")))
            if tp:
                f["alcanzable_taint"] = True
                f["ruta_flujo"] = tp
        # Rutas de flujo que no coinciden con un hallazgo previo: son observaciones
        # propias (entrada de usuario alcanza una operación sensible).
        for (arch, sink_ln), tp in sink_idx.items():
            if (arch, sink_ln) in existentes:
                continue
            cwe = tp.get("cwe")
            findings.append({
                "rule_id": "TAINT-" + (cwe or "FLUJO"),
                "titulo": f"Flujo de datos no confiable hacia {tp['sumidero']}",
                "categoria": "FLUJO DE DATOS", "severidad": _TAINT_SEV.get(cwe, "medio"),
                "archivo": arch, "linea": sink_ln,
                "evidencia": f"{tp['fuente']} (línea {tp['fuente_linea']}) alcanza el sumidero "
                             f"de {tp['sumidero']} a través de «{tp['var']}».",
                "guia": "El análisis de flujo de datos detectó una ruta potencialmente explotable; "
                        "validar y sanear la entrada antes del sumidero.",
                "legal": "A verificar contra el marco aplicable (no es asesoría legal).",
                "controles": _TAINT_CTRL.get(cwe, []), "cwe": cwe,
                "mitigacion": "Sanear/validar la entrada y usar API seguras "
                              "(consultas parametrizadas, escape, listas de permitidos) en el sumidero.",
                "motor": "taint", "alcanzable_taint": True, "ruta_flujo": tp,
                "contexto": _taint_ctx(root, arch, sink_ln),
            })

    # Resumen por severidad y categoría
    by_sev, by_cat = {}, {}
    for f in findings:
        by_sev[f["severidad"]] = by_sev.get(f["severidad"], 0) + 1
        by_cat[f["categoria"]] = by_cat.get(f["categoria"], 0) + 1

    # Conteo por motor (defensa en profundidad).
    by_motor = {}
    for f in findings:
        by_motor[f.get("motor", "interno")] = by_motor.get(f.get("motor", "interno"), 0) + 1

    return {
        "findings": findings,
        "stats": {
            "archivos_escaneados": file_count, "archivos_omitidos": skipped,
            "por_extension": dict(sorted(ext_count.items(), key=lambda x: -x[1])[:15]),
            "lenguajes": languages, "tiene_licencia": has_license,
            "permisos_android": sorted(manifest_perms),
        },
        "resumen": {"por_severidad": by_sev, "por_categoria": by_cat,
                    "por_motor": by_motor, "total": len(findings)},
        # Motores externos y rutas de flujo (análisis avanzado).
        "motores": {"externos_corridos": motores_ext, "disponibles": engines_disp,
                    "por_motor": by_motor},
        "_taint": taint_paths,
        # Indicio de uso de OIDC/OAuth2 para el motor de cumplimiento (Decreto 9).
        "_auth_oidc": auth_oidc,
        # Manifiestos para integrar los componentes al inventario de software.
        "_componentes": {
            "gradle_build": _gradle_main["build"][0] if _gradle_main["build"] else None,
            "gradle_toml": _gradle_main["toml"],
            "npm": [(rel, c) for (t, rel, c) in build_manifests if t == "npm"],
        },
    }
