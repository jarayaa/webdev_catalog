"""
regulatory.py — Motor de cumplimiento normativo (marco legal chileno de
Transformación Digital del Estado y seguridad del documento electrónico).

OBJETIVO
========
Transformar los hallazgos del análisis estático de código (SAST, en code_scan)
y los metadatos del artefacto en una EVALUACIÓN DE CUMPLIMIENTO contra un
catálogo de controles auditables derivados —artículo por artículo— de:

  · Decreto 7/2023  SEGPRES — Norma Técnica de Seguridad de la Información y
                    Ciberseguridad (Ley 21.180). Estructura por 5 funciones:
                    Identificar, Proteger, Detectar, Responder, Recuperar.
  · Decreto 9/2023  SEGPRES — Norma Técnica de Autenticación (OpenID Connect /
                    OAuth 2.0; cifrado de factores; TLS 1.2+; trazabilidad UTC).
  · Decreto 10/2023 SEGPRES — Documentos y Expedientes Electrónicos.
  · Decreto 11/2023 SEGPRES — Calidad y Funcionamiento de Plataformas.
  · DS 83/2004      SEGPRES — Seguridad y Confidencialidad del Documento
                    Electrónico (control de acceso, cifrado, antimalware, logs).

Cada control:
  id, instrumento, referencia (artículo), funcion/dominio, titulo, exigencia
  (texto normativo resumido), tipo de evaluación y el conjunto de reglas SAST
  (rule_id de code_scan) que lo SATISFACEN o lo INCUMPLEN. El motor cruza los
  hallazgos y emite un estado por control:

     CUMPLE          — sin evidencia de incumplimiento y, si el control es
                       verificable por presencia, hay evidencia de cumplimiento.
     NO_CUMPLE       — hay al menos un hallazgo que viola el control.
     OBSERVADO       — indicios parciales / requiere revisión humana.
     NO_EVALUABLE    — el control es organizacional/procedimental y no se puede
                       determinar por análisis estático de código.

IMPORTANTE (alcance y rigor de auditor)
---------------------------------------
El análisis estático SOLO observa el código fuente; muchos controles de estas
normas son organizacionales (políticas, roles, diagnósticos, planes). Esos se
reportan honestamente como NO_EVALUABLE con la indicación de qué evidencia
documental los acreditaría. Esto es un INSUMO para la evaluación de QA y la
auditoría de cumplimiento; no es un dictamen jurídico ni una certificación.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Estados de control (orden de gravedad para agregación).
CUMPLE = "cumple"
NO_CUMPLE = "no_cumple"
OBSERVADO = "observado"
NO_EVALUABLE = "no_evaluable"

_ESTADO_RANK = {NO_CUMPLE: 3, OBSERVADO: 2, NO_EVALUABLE: 1, CUMPLE: 0}

# Las 5 funciones del Decreto 7 (marco tipo NIST CSF adoptado por la norma).
FUNCIONES_D7 = ["Identificar", "Proteger", "Detectar", "Responder", "Recuperar"]

# Metadatos de los instrumentos, para el encabezado del informe.
INSTRUMENTOS = [
    {"id": "Decreto 7/2023", "titulo": "Norma Técnica de Seguridad de la Información "
     "y Ciberseguridad", "ley": "Ley 21.180", "fecha": "17-AGO-2023",
     "url": "https://bcn.cl/3hri8"},
    {"id": "Decreto 9/2023", "titulo": "Norma Técnica de Autenticación",
     "ley": "Ley 21.180 · Ley 19.628", "fecha": "17-AGO-2023", "url": "https://bcn.cl/3h75f"},
    {"id": "Decreto 10/2023", "titulo": "Norma Técnica de Documentos y Expedientes "
     "Electrónicos", "ley": "Ley 21.180 · Ley 19.628", "fecha": "17-AGO-2023",
     "url": "https://bcn.cl/3hh4y"},
    {"id": "Decreto 11/2023", "titulo": "Norma Técnica de Calidad y Funcionamiento "
     "de las Plataformas Electrónicas", "ley": "Ley 21.180", "fecha": "17-AGO-2023",
     "url": "https://bcn.cl/3m2os"},
    {"id": "DS 83/2004", "titulo": "Norma Técnica sobre Seguridad y Confidencialidad "
     "del Documento Electrónico", "ley": "Ley 19.799", "fecha": "12-ENE-2005",
     "url": "https://bcn.cl/3l02i"},
]


@dataclass
class Control:
    """Un control auditable derivado de un artículo de la normativa."""
    id: str
    instrumento: str          # p.ej. "Decreto 9/2023"
    referencia: str           # p.ej. "Art. 6 inc. 2"
    dominio: str              # función D7 o dominio temático
    titulo: str
    exigencia: str            # qué exige la norma (resumen fiel)
    # rule_ids de code_scan cuya PRESENCIA implica incumplimiento del control:
    incumple_si: list = field(default_factory=list)
    # rule_ids cuya presencia es EVIDENCIA de cumplimiento (controles "de presencia"):
    cumple_si: list = field(default_factory=list)
    # ¿es evaluable por análisis estático? Si False → NO_EVALUABLE siempre.
    evaluable: bool = True
    # Qué evidencia documental acreditaría un control no evaluable por código.
    evidencia_documental: Optional[str] = None
    # Severidad del incumplimiento (hereda al estado del control si NO_CUMPLE).
    severidad_incumplimiento: str = "alto"


# ===========================================================================
# CATÁLOGO DE CONTROLES
# Derivado del articulado de cada instrumento. Las referencias citan el artículo
# concreto; la "exigencia" es un resumen fiel (no cita textual extensa).
# ===========================================================================

CONTROLES: list[Control] = [

    # ----------------------------------------------------------------------
    # DECRETO 9/2023 — Norma Técnica de Autenticación
    # Es el instrumento con exigencias técnicas más directamente verificables
    # en código (cifrado de factores, TLS, OAuth/OIDC, anti fuerza bruta).
    # ----------------------------------------------------------------------
    Control(
        id="D9-A6-CIFRADO-FACTOR",
        instrumento="Decreto 9/2023",
        referencia="Art. 6 inc. 2",
        dominio="Proteger",
        titulo="Almacenamiento cifrado de los factores de autenticación",
        exigencia=("Los datos de identificación asociados a los factores de "
                   "autenticación deben almacenarse cifrados mediante algoritmos "
                   "tales como Bcrypt, PBKDF2, SHA-3 o Argon2, o superiores."),
        incumple_si=["CRY-WEAK-HASH", "SEC-PASSWORD"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="D9-A6-TLS",
        instrumento="Decreto 9/2023",
        referencia="Art. 6 inc. 3",
        dominio="Proteger",
        titulo="Transmisión cifrada en el proceso de autenticación (TLS 1.2+)",
        exigencia=("La transmisión de datos durante la autenticación debe usar "
                   "protocolos de comunicación cifrados, tales como TLSv1.2 o "
                   "superiores; no se admite tráfico en texto claro ni la "
                   "desactivación de la validación de certificados."),
        incumple_si=["NET-CLEARTEXT", "NET-TRUST-ALL"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="D9-A6-OIDC-OAUTH",
        instrumento="Decreto 9/2023",
        referencia="Art. 6 inc. 1",
        dominio="Proteger",
        titulo="Mecanismos oficiales basados en OpenID Connect / OAuth 2.0",
        exigencia=("Los mecanismos oficiales de autenticación (ClaveÚnica, Clave "
                   "Tributaria) deben basarse en los estándares OpenID Connect y "
                   "OAuth 2.0 o superiores."),
        cumple_si=["AUTH-OIDC-PRESENTE"],
        evaluable=True,
        evidencia_documental=("Configuración de cliente OIDC/OAuth2 hacia el proveedor "
                              "oficial; constancia de certificación de la integración "
                              "(Art. 10 N°3)."),
        severidad_incumplimiento="medio",
    ),
    Control(
        id="D9-A7-FUERZA-BRUTA",
        instrumento="Decreto 9/2023",
        referencia="Art. 7",
        dominio="Proteger",
        titulo="Prevención de accesos no autorizados (límite de intentos / Captcha)",
        exigencia=("Deben implementarse pruebas tipo Captcha y limitar el número "
                   "máximo de intentos fallidos de autenticación, con bloqueo y un "
                   "procedimiento de desbloqueo."),
        evaluable=False,
        evidencia_documental=("Política de bloqueo por intentos fallidos; configuración "
                              "del proveedor de autenticación; pruebas de control de "
                              "fuerza bruta."),
        severidad_incumplimiento="medio",
    ),
    Control(
        id="D9-A13-TRAZABILIDAD",
        instrumento="Decreto 9/2023",
        referencia="Art. 13",
        dominio="Detectar",
        titulo="Registro de trazabilidad de accesos (identificador + fecha/hora UTC)",
        exigencia=("Debe mantenerse un registro de accesos que almacene, al menos, "
                   "el identificador del usuario y la fecha y hora del acceso en UTC, "
                   "sincronizada con el SHOA. El registro NO debe contener datos "
                   "sensibles en claro."),
        incumple_si=["LOG-SENSITIVE"],
        evidencia_documental=("Esquema del registro de accesos; sincronización horaria "
                              "(NTP/UTC); política de retención de logs."),
        severidad_incumplimiento="medio",
    ),
    Control(
        id="D9-A14-DATOS-PERSONALES",
        instrumento="Decreto 9/2023",
        referencia="Art. 14",
        dominio="Proteger",
        titulo="Protección de datos personales de quienes se autentican",
        exigencia=("Debe respetarse la Ley 19.628: reserva y protección de los datos "
                   "personales, y garantía de los derechos de acceso, rectificación, "
                   "cancelación y oposición (ARCO), usándolos solo para la finalidad "
                   "prevista."),
        incumple_si=["PII-RUT", "LOG-SENSITIVE"],
        evidencia_documental=("Registro de actividades de tratamiento; base de licitud "
                              "y finalidad; mecanismos ARCO; cifrado del dato en reposo."),
        severidad_incumplimiento="medio",
    ),

    # ----------------------------------------------------------------------
    # DECRETO 7/2023 — Seguridad de la Información y Ciberseguridad (Ley 21.180)
    # Estructura por las 5 funciones. Buena parte es de gobernanza (no evaluable
    # por código); lo evaluable se ancla a la función de Protección y Detección.
    # ----------------------------------------------------------------------
    Control(
        id="D7-A4-DIAGNOSTICO",
        instrumento="Decreto 7/2023",
        referencia="Art. 4",
        dominio="Identificar",
        titulo="Diagnóstico inicial de ciberseguridad de la plataforma",
        exigencia=("Cada órgano debe realizar un diagnóstico inicial del estado de "
                   "ciberseguridad de sus plataformas e incorporarlo al Catálogo de "
                   "Plataformas."),
        evaluable=False,
        evidencia_documental=("Informe de diagnóstico inicial; inscripción en el "
                              "Catálogo de Plataformas (Art. 57 del Reglamento)."),
        severidad_incumplimiento="medio",
    ),
    Control(
        id="D7-A5-POLITICA",
        instrumento="Decreto 7/2023",
        referencia="Art. 5",
        dominio="Identificar",
        titulo="Política de Seguridad de la Información y Ciberseguridad",
        exigencia=("Debe existir una Política aprobada por acto administrativo del "
                   "Jefe Superior de Servicio, que vele por la seguridad de software, "
                   "hardware, sistemas y datos."),
        evaluable=False,
        evidencia_documental=("Resolución que aprueba la Política; evidencia de "
                              "difusión y revisión periódica."),
        severidad_incumplimiento="bajo",
    ),
    Control(
        id="D7-A8-PROTECCION-DATOS",
        instrumento="Decreto 7/2023",
        referencia="Art. 8",
        dominio="Proteger",
        titulo="Seguridad de los datos (función de protección)",
        exigencia=("La función de protección comprende la seguridad de los datos: "
                   "deben implementarse medidas que protejan la confidencialidad e "
                   "integridad de la información, incluido el cifrado correcto en "
                   "reposo y en tránsito."),
        incumple_si=["CRY-ECB", "CRY-WEAK-HASH", "NET-CLEARTEXT", "NET-TRUST-ALL"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="D7-A8-CONTROL-ACCESO",
        instrumento="Decreto 7/2023",
        referencia="Art. 8",
        dominio="Proteger",
        titulo="Gestión de autenticación y control de acceso",
        exigencia=("La función de protección incluye la gestión de autenticación y "
                   "control de acceso a las plataformas: las credenciales y secretos "
                   "no deben quedar expuestos ni embebidos en el código."),
        incumple_si=["SEC-API-KEY", "SEC-GOOGLE-KEY", "SEC-PRIVATE-KEY",
                     "SEC-PASSWORD", "SEC-DB-URL"],
        severidad_incumplimiento="crítico",
    ),
    Control(
        id="D7-A9-CODIGO-MALICIOSO",
        instrumento="Decreto 7/2023",
        referencia="Art. 9",
        dominio="Detectar",
        titulo="Protección y detección frente a código malicioso",
        exigencia=("La función de detección exige que los servidores y plataformas "
                   "cuenten con medidas adecuadas de protección contra código "
                   "malicioso y un proceso de detección de eventos anómalos."),
        incumple_si=["DEP-MALWARE"],
        severidad_incumplimiento="crítico",
    ),
    Control(
        id="D7-A8-REGISTRO-EVENTOS",
        instrumento="Decreto 7/2023",
        referencia="Art. 8",
        dominio="Detectar",
        titulo="Registro de eventos (logging) sin exposición de datos sensibles",
        exigencia=("La función de protección incluye el registro de eventos; dicho "
                   "registro debe evitar dejar datos personales o secretos en claro "
                   "en los logs."),
        incumple_si=["LOG-SENSITIVE", "DBG-ENABLED"],
        severidad_incumplimiento="medio",
    ),

    # ----------------------------------------------------------------------
    # DS 83/2004 — Seguridad y Confidencialidad del Documento Electrónico
    # Norma base (estilo ISO 17799). Controles de cifrado, antimalware,
    # control de acceso y robustez de identificadores son verificables.
    # ----------------------------------------------------------------------
    Control(
        id="DS83-A6-ATRIBUTOS",
        instrumento="DS 83/2004",
        referencia="Art. 6",
        dominio="Proteger",
        titulo="Atributos esenciales: confidencialidad e integridad del documento",
        exigencia=("La seguridad del documento electrónico se logra garantizando "
                   "confidencialidad, integridad, factibilidad de autenticación y "
                   "disponibilidad; el cifrado debe ser correcto y la transmisión "
                   "protegida."),
        incumple_si=["CRY-ECB", "CRY-WEAK-HASH", "NET-CLEARTEXT", "NET-TRUST-ALL"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="DS83-A26-ANTIMALWARE-CIFRADO",
        instrumento="DS 83/2004",
        referencia="Art. 26 letras a) y b)",
        dominio="Detectar",
        titulo="Antimalware y cifrado de la confidencialidad e integridad",
        exigencia=("Los organismos deben instalar antivirus frente a software "
                   "malicioso y proveer mecanismos de cifrado que protejan la "
                   "confidencialidad e integridad de los documentos electrónicos."),
        incumple_si=["DEP-MALWARE", "CRY-ECB", "CRY-WEAK-HASH"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="DS83-A28-ROBUSTEZ-CRED",
        instrumento="DS 83/2004",
        referencia="Art. 28",
        dominio="Proteger",
        titulo="Gestión y robustez de identificadores (credenciales)",
        exigencia=("La asignación de identificadores debe controlarse formalmente: "
                   "no almacenarlos desprotegidos en un computador, no incluirlos en "
                   "procesos de inicio de sesión automatizado (p. ej. embebidos), y "
                   "exigir contraseñas robustas (≥8 caracteres, mezcla, no obvias)."),
        incumple_si=["SEC-PASSWORD", "SEC-API-KEY", "SEC-PRIVATE-KEY", "SEC-DB-URL"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="DS83-A29-CRED-TEXTO-CLARO",
        instrumento="DS 83/2004",
        referencia="Art. 29",
        dominio="Proteger",
        titulo="No comunicar identificadores por canales en texto claro",
        exigencia=("Debe evitarse el uso de mensajes no protegidos (texto en claro) "
                   "para comunicar identificadores/credenciales."),
        incumple_si=["NET-CLEARTEXT"],
        severidad_incumplimiento="medio",
    ),
    Control(
        id="DS83-A31-ACCESO-NO-AUTORIZADO",
        instrumento="DS 83/2004",
        referencia="Art. 31-32",
        dominio="Proteger",
        titulo="Reducción del riesgo de acceso no autorizado a sistemas y datos",
        exigencia=("Deben promoverse buenas prácticas y controlarse el acceso a los "
                   "sistemas informáticos; la concatenación de SQL o secretos "
                   "embebidos facilitan el acceso no autorizado."),
        incumple_si=["SQL-CONCAT", "SEC-API-KEY", "SEC-DB-URL", "PERM-DANGEROUS"],
        severidad_incumplimiento="alto",
    ),
    Control(
        id="DS83-A11-POLITICA",
        instrumento="DS 83/2004",
        referencia="Art. 11-12",
        dominio="Identificar",
        titulo="Política de seguridad y encargado de seguridad",
        exigencia=("Debe establecerse una política de seguridad documentada, revisada "
                   "al menos cada 3 años, y designarse un encargado de seguridad."),
        evaluable=False,
        evidencia_documental=("Política de seguridad vigente; resolución de designación "
                              "del encargado de seguridad."),
        severidad_incumplimiento="bajo",
    ),

    # ----------------------------------------------------------------------
    # DECRETO 10/2023 — Documentos y Expedientes Electrónicos
    # Mayormente procedimental; lo evaluable se relaciona con integridad y
    # protección de los datos personales tratados en los documentos.
    # ----------------------------------------------------------------------
    Control(
        id="D10-INTEGRIDAD-DOC",
        instrumento="Decreto 10/2023",
        referencia="Norma Técnica de Documentos y Expedientes Electrónicos",
        dominio="Proteger",
        titulo="Integridad y protección de los documentos y datos del expediente",
        exigencia=("La gestión de documentos y expedientes electrónicos debe preservar "
                   "su integridad y la protección de los datos personales contenidos "
                   "(Ley 19.628), evitando cifrado débil o exposición en logs."),
        incumple_si=["CRY-WEAK-HASH", "CRY-ECB", "LOG-SENSITIVE", "PII-RUT"],
        evidencia_documental=("Mecanismos de firma/sellado de integridad del documento; "
                              "metadatos de trazabilidad del expediente."),
        severidad_incumplimiento="medio",
    ),

    # ----------------------------------------------------------------------
    # DECRETO 11/2023 — Calidad y Funcionamiento de las Plataformas
    # Ciclo de gestión de la calidad y mejora continua; procedimental, pero
    # la presencia de licencia y la ausencia de defectos críticos son señales
    # objetivas de la "línea de base" de calidad.
    # ----------------------------------------------------------------------
    Control(
        id="D11-LINEA-BASE",
        instrumento="Decreto 11/2023",
        referencia="Art. 3-5",
        dominio="Identificar",
        titulo="Línea de base de calidad y mejora continua de la plataforma",
        exigencia=("La plataforma debe incorporarse al catálogo con una línea de base "
                   "de calidad y un Ciclo de Gestión de la Calidad; los defectos "
                   "críticos/altos detectados deben gestionarse en un Plan de Mejora "
                   "Continua antes de su promoción."),
        # No 'incumple' por una regla puntual; su estado se deriva del panorama
        # global de riesgo en evaluate(). Aquí queda como ancla del dominio.
        evaluable=True,
        evidencia_documental=("Catálogo de plataformas; Plan de Mejora Continua; "
                              "métricas de calidad del Ciclo de Gestión."),
        severidad_incumplimiento="medio",
    ),
    Control(
        id="D11-LICENCIAMIENTO",
        instrumento="Decreto 11/2023",
        referencia="Art. 4 (gestión de calidad) · concordante Guía SEGPRES §IX",
        dominio="Identificar",
        titulo="Trazabilidad y licenciamiento del software de la plataforma",
        exigencia=("La gestión de calidad de la plataforma requiere trazabilidad de "
                   "sus componentes y un marco de licenciamiento definido para el "
                   "software del Estado."),
        incumple_si=["LIC-MISSING"],
        severidad_incumplimiento="bajo",
    ),
]


# Índice rápido: rule_id -> lista de controles que incumple.
_INCUMPLE_INDEX: dict[str, list[Control]] = {}
_CUMPLE_INDEX: dict[str, list[Control]] = {}
for _c in CONTROLES:
    for _r in _c.incumple_si:
        _INCUMPLE_INDEX.setdefault(_r, []).append(_c)
    for _r in _c.cumple_si:
        _CUMPLE_INDEX.setdefault(_r, []).append(_c)


def _rule_ids_present(findings) -> dict[str, list[dict]]:
    """Agrupa los hallazgos presentes por rule_id."""
    by_rule: dict[str, list[dict]] = {}
    for f in findings or []:
        by_rule.setdefault(f.get("rule_id"), []).append(f)
    return by_rule


def evaluate(scan: dict, reasoned: Optional[dict] = None) -> dict:
    """Evalúa el catálogo de controles contra los hallazgos del análisis.

    Parámetros
    ----------
    scan : dict        resultado de code_scan.scan_tree (con 'findings', 'stats').
    reasoned : dict    salida de code_reason.reason (nivel_global, etc.), opcional.

    Devuelve un dict con: lista de controles evaluados, matriz por instrumento y
    por función, conteos y un veredicto de cumplimiento global.
    """
    findings = (reasoned or {}).get("enriched") or scan.get("findings") or []
    by_rule = _rule_ids_present(findings)
    stats = scan.get("stats", {})
    nivel_global = (reasoned or {}).get("nivel_global", "—")

    # Señales de PRESENCIA detectadas fuera del catálogo de reglas SAST:
    #   - AUTH-OIDC-PRESENTE: indicios de uso de OIDC/OAuth2 en el árbol.
    #   - DEP-MALWARE: hallazgo de cumplimiento de dependencias (malware) si vino.
    presencias = set()
    if scan.get("_auth_oidc"):
        presencias.add("AUTH-OIDC-PRESENTE")
    # Cumplimiento de dependencias (compliance.py) puede marcar malware.
    for dep_finding in scan.get("_dep_compliance", []) or []:
        if (dep_finding or {}).get("categoria") == "paquete_malicioso":
            by_rule.setdefault("DEP-MALWARE", []).append({
                "rule_id": "DEP-MALWARE", "archivo": "(manifiesto de dependencias)",
                "titulo": f"Dependencia con aviso de malware: {dep_finding.get('package')}",
            })

    evaluados = []
    for c in CONTROLES:
        evidencia_hallazgos = []
        estado = NO_EVALUABLE

        if not c.evaluable:
            estado = NO_EVALUABLE
        else:
            # ¿Hay hallazgos que lo incumplen?
            hits = []
            for rid in c.incumple_si:
                hits.extend(by_rule.get(rid, []))
            if hits:
                estado = NO_CUMPLE
                evidencia_hallazgos = hits
            elif c.cumple_si:
                # Control "de presencia": cumple si se observa la evidencia.
                if any(rid in presencias or by_rule.get(rid) for rid in c.cumple_si):
                    estado = CUMPLE
                else:
                    estado = OBSERVADO  # no se observó la evidencia esperada
            elif c.incumple_si:
                # Tiene reglas de incumplimiento y ninguna disparó → cumple.
                estado = CUMPLE
            else:
                # Control evaluable sin reglas directas (p. ej. línea de base D11):
                # se deriva del panorama global de riesgo.
                if c.id == "D11-LINEA-BASE":
                    estado = (NO_CUMPLE if nivel_global == "crítico"
                              else OBSERVADO if nivel_global in ("alto", "medio")
                              else CUMPLE)
                else:
                    estado = OBSERVADO

        evaluados.append({
            "id": c.id,
            "instrumento": c.instrumento,
            "referencia": c.referencia,
            "dominio": c.dominio,
            "titulo": c.titulo,
            "exigencia": c.exigencia,
            "estado": estado,
            "severidad": c.severidad_incumplimiento if estado == NO_CUMPLE else None,
            "evidencia_documental": c.evidencia_documental,
            "hallazgos": [
                {"rule_id": h.get("rule_id"), "archivo": h.get("archivo"),
                 "linea": h.get("linea"), "titulo": h.get("titulo")}
                for h in evidencia_hallazgos[:8]
            ],
            "n_hallazgos": len(evidencia_hallazgos),
        })

    # Ordenar: primero los NO_CUMPLE, luego OBSERVADO, NO_EVALUABLE, CUMPLE.
    evaluados.sort(key=lambda e: (-_ESTADO_RANK[e["estado"]], e["instrumento"], e["referencia"]))

    # Conteos globales.
    conteos = {CUMPLE: 0, NO_CUMPLE: 0, OBSERVADO: 0, NO_EVALUABLE: 0}
    for e in evaluados:
        conteos[e["estado"]] += 1

    # Matriz por instrumento.
    por_instrumento: dict[str, dict] = {}
    for e in evaluados:
        d = por_instrumento.setdefault(
            e["instrumento"],
            {CUMPLE: 0, NO_CUMPLE: 0, OBSERVADO: 0, NO_EVALUABLE: 0})
        d[e["estado"]] += 1

    # Matriz por función del Decreto 7 (solo controles con dominio = función).
    por_funcion: dict[str, dict] = {fn: {CUMPLE: 0, NO_CUMPLE: 0, OBSERVADO: 0, NO_EVALUABLE: 0}
                                    for fn in FUNCIONES_D7}
    for e in evaluados:
        if e["dominio"] in por_funcion:
            por_funcion[e["dominio"]][e["estado"]] += 1

    # Veredicto de cumplimiento global.
    evaluables = conteos[CUMPLE] + conteos[NO_CUMPLE] + conteos[OBSERVADO]
    pct_cumplimiento = round(100 * conteos[CUMPLE] / evaluables, 1) if evaluables else 0.0
    if conteos[NO_CUMPLE] == 0 and conteos[OBSERVADO] == 0:
        veredicto = "CONFORME"
        veredicto_detalle = ("No se detectaron incumplimientos verificables por análisis "
                             "estático. Persisten controles organizacionales por acreditar "
                             "documentalmente.")
    elif any(e["estado"] == NO_CUMPLE and e["severidad"] in ("crítico", "alto")
             for e in evaluados):
        veredicto = "NO CONFORME"
        veredicto_detalle = ("Existen incumplimientos de severidad alta o crítica que deben "
                             "remediarse antes de promover la plataforma a producción.")
    elif conteos[NO_CUMPLE] > 0:
        veredicto = "CONFORME CON OBSERVACIONES"
        veredicto_detalle = ("Hay incumplimientos de severidad media o baja a subsanar dentro "
                             "del Plan de Mejora Continua (Decreto 11).")
    else:
        veredicto = "CONFORME CON OBSERVACIONES"
        veredicto_detalle = ("Sin incumplimientos directos, pero existen controles observados "
                             "que requieren verificación humana.")

    return {
        "controles": evaluados,
        "conteos": conteos,
        "por_instrumento": por_instrumento,
        "por_funcion": por_funcion,
        "pct_cumplimiento": pct_cumplimiento,
        "veredicto": veredicto,
        "veredicto_detalle": veredicto_detalle,
        "instrumentos": INSTRUMENTOS,
        "total_controles": len(evaluados),
        "disclaimer": ("Evaluación automatizada de cumplimiento como INSUMO para la auditoría "
                       "y el aseguramiento de calidad. No constituye certificación de "
                       "cumplimiento ni asesoría legal; los controles organizacionales "
                       "(políticas, roles, diagnósticos, planes) requieren verificación "
                       "documental independiente."),
    }
