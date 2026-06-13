"""
Análisis de cumplimiento legal de dependencias, con foco en la legislación
chilena: Ley 21.459 (delitos informáticos, adecúa al Convenio de Budapest) y,
de forma complementaria, la Ley 19.628 (protección de la vida privada / datos
personales).

OBJETIVO: detectar, entre las dependencias de un proyecto, paquetes cuyo uso
implique un riesgo de cumplimiento por el tratamiento de datos personales de
ciudadanos (especialmente identificadores nacionales como el RUT) o por código
malicioso, y graduar ese riesgo según la EVIDENCIA disponible.

CALIBRACIÓN (clave para no emitir acusaciones infundadas):
  - "medio"  → el paquete implementa un ALGORITMO sobre identificadores
               (validar/formatear/generar RUT). No contiene datos reales ni los
               obtiene; el riesgo es de cumplimiento en cómo la APLICACIÓN trata
               esos datos (Ley 19.628). NO constituye delito por sí mismo.
  - "alto"   → el paquete sugiere CONSULTA/LOOKUP de datos personales a partir de
               un identificador ("rutificador": RUT → nombre/dirección). En Chile
               estos servicios suelen sustentarse en bases obtenidas o filtradas
               ilícitamente; podría configurarse receptación de datos (Art. 6).
  - "crítico"→ existe EVIDENCIA de que el paquete es malicioso (advisory de OSV
               tipo malware), lo que implica posible exfiltración/fraude.

Esto es un apoyo automatizado a la revisión; NO es asesoría legal ni una
determinación de responsabilidad penal, la que requiere análisis jurídico del
caso concreto.
"""

import re

LEY = "Ley 21.459 (delitos informáticos)"
LEY_DATOS = "Ley 19.628 (protección de datos personales)"

# Validadores/formateadores algorítmicos de identificadores chilenos: el paquete
# NO contiene ni consulta datos de personas; aplica el algoritmo público.
_ALGORITMICOS_ID = {
    "chilean-rutify", "rut.js", "rutjs", "validar-rut", "rut-validator",
    "rut-helpers", "@fdograph/rut-helpers", "chilean-rut", "rut-chile",
    "@validatecl/rut", "rutlib", "cl-rut", "dni-validator", "validator-rut",
}

# Términos que sugieren CONSULTA de datos personales por identificador
# (mucho más sensible que un validador).
_LOOKUP_TERMS = re.compile(
    r"rutificad|consulta.*(rut|cedula|c[eé]dula|persona|padr[oó]n)|"
    r"(rut|cedula|dni).*(nombre|direcci[oó]n|datos\s+personales|lookup|consulta)|"
    r"scrap.*(rut|persona|sii|registro\s*civil)|padr[oó]n\s*electoral", re.I)

# Identificadores nacionales / datos personales en el nombre del paquete.
_ID_NOMBRE = re.compile(r"(^|[-_/@])(rut|dni|cedula|c[eé]dula|rfc|curp|nss|ssn|"
                        r"padron|padr[oó]n|rutificad)([-_/]|$)", re.I)


def _detect_malicious(vuln_details):
    """Evidencia de paquete malicioso a partir de los advisories de OSV
    (los advisories de malware usan IDs/aliases 'MAL-...' o mencionan malware)."""
    for d in vuln_details or []:
        ident = " ".join([str(d.get("id") or ""), str(d.get("osv_id") or "")]
                         + [str(a) for a in (d.get("aliases") or [])])
        if "MAL-" in ident.upper():
            return True, d.get("id") or d.get("osv_id")
        txt = (str(d.get("summary") or "") + " " + str(d.get("details") or "")).lower()
        if any(k in txt for k in ("malicious package", "malware", "data exfiltration",
                                  "credential steal", "backdoor", "supply chain attack")):
            return True, d.get("id") or d.get("osv_id")
    return False, None


def assess(pkg, description=None, vuln_details=None):
    """Devuelve un hallazgo de cumplimiento {nivel, categoria, ...} o None."""
    name = (pkg or "").lower()
    desc = (description or "").lower()

    # 1) Evidencia de malware (máxima gravedad).
    mal, mal_id = _detect_malicious(vuln_details)
    if mal:
        return _finding(
            pkg, "crítico", "paquete_malicioso",
            rationale=(f"Existe un aviso de seguridad que clasifica a «{pkg}» como "
                       f"paquete potencialmente malicioso ({mal_id}). El código de un "
                       "paquete malicioso puede acceder, alterar o exfiltrar datos del "
                       "sistema y de los usuarios sin autorización."),
            articulos=[
                ("Art. 1", "Ataque a la integridad de un sistema informático."),
                ("Art. 2", "Acceso ilícito a un sistema informático."),
                ("Art. 4", "Ataque a la integridad de los datos informáticos."),
                ("Art. 7", "Fraude informático (manipulación con perjuicio y ánimo de lucro)."),
                ("Art. 8", "Abuso de los dispositivos (programas creados para perpetrar los delitos)."),
            ],
            recomendacion=("Eliminar de inmediato la dependencia, rotar credenciales que "
                           "hayan podido quedar expuestas y revisar los builds que la "
                           "incluyeron. No promover a producción."),
            ley_datos=False)

    # 2) Consulta/lookup de datos personales por identificador ("rutificador").
    if _LOOKUP_TERMS.search(name) or _LOOKUP_TERMS.search(desc) or re.search(r"rutificad", name):
        return _finding(
            pkg, "alto", "consulta_datos_personales",
            rationale=(f"«{pkg}» aparenta permitir la CONSULTA de datos personales a "
                       "partir de un identificador (p. ej. obtener nombre/dirección desde "
                       "un RUT). En Chile estos servicios suelen sustentarse en bases de "
                       "datos personales obtenidas, filtradas o comercializadas sin "
                       "fuente lícita. Si los datos provienen de un acceso ilícito o "
                       "filtración, su almacenamiento o uso podría configurar receptación "
                       "de datos informáticos."),
            articulos=[
                ("Art. 6", "Receptación de datos informáticos: almacenar, transferir o "
                           "comercializar datos provenientes de los delitos de los Arts. 2°, "
                           "3° y 5°, conociendo o no pudiendo menos que conocer su origen."),
                ("Art. 2", "Acceso ilícito (si la base de datos se obtuvo accediendo sin "
                           "autorización a un sistema informático)."),
            ],
            recomendacion=("Verificar con el proveedor/área legal la FUENTE de los datos que "
                           "entrega el paquete. Si no hay licencia o fuente lícita verificable, "
                           "no utilizarlo. Confirmar cumplimiento de la Ley 19.628 y, de existir "
                           "tratamiento de datos sensibles, evaluar autorización del titular."),
            ley_datos=True)

    # 3) Validador/formateador algorítmico de identificadores → revisión de cumplimiento.
    if name in _ALGORITMICOS_ID or _ID_NOMBRE.search(name) or \
       (("rut" in desc or "cédula" in desc or "cedula" in desc) and
        ("valida" in desc or "format" in desc or "validating" in desc or "formating" in desc)):
        return _finding(
            pkg, "medio", "tratamiento_identificadores",
            rationale=(f"«{pkg}» opera sobre identificadores nacionales (p. ej. RUT). Según su "
                       "naturaleza habitual, implementa el ALGORITMO público de validación/"
                       "formato y NO contiene ni obtiene datos reales de personas, por lo que su "
                       "sola inclusión no constituye delito. El riesgo es de CUMPLIMIENTO: depende "
                       "de cómo la aplicación recolecta y trata esos identificadores."),
            articulos=[
                ("Art. 6", "Aplicable SOLO si los identificadores/datos asociados que procesa la "
                           "aplicación provinieran de fuentes ilícitas (receptación). El paquete en "
                           "sí —validador algorítmico— no incurre en este tipo."),
            ],
            recomendacion=("Confirmar que los RUT/datos tratados por la aplicación se obtienen del "
                           "propio titular o de fuentes lícitas, y que el tratamiento cumple la "
                           "Ley 19.628 (finalidad, consentimiento y seguridad de los datos). "
                           "No requiere remover el paquete."),
            ley_datos=True)

    return None


def _finding(pkg, nivel, categoria, rationale, articulos, recomendacion, ley_datos):
    leyes = [LEY] + ([LEY_DATOS] if ley_datos else [])
    return {
        "package": pkg,
        "nivel": nivel,
        "categoria": categoria,
        "rationale": rationale,
        "ley": LEY,
        "leyes": leyes,
        "articulos": [{"art": a, "texto": t} for a, t in articulos],
        "recomendacion": recomendacion,
        "disclaimer": ("Hallazgo automatizado de apoyo a la revisión de cumplimiento. No "
                       "constituye asesoría legal ni una determinación de responsabilidad "
                       "penal; la calificación de un delito requiere análisis jurídico del "
                       "caso concreto."),
    }


def summarize(deps):
    """Resumen de hallazgos de cumplimiento sobre una lista de dependencias
    auditadas (cada una puede traer entry['compliance'])."""
    findings = [d.get("compliance") for d in deps if d.get("compliance")]
    by_level = {"crítico": 0, "alto": 0, "medio": 0}
    for f in findings:
        by_level[f["nivel"]] = by_level.get(f["nivel"], 0) + 1
    return {"total": len(findings), "by_level": by_level,
            "packages": [f["package"] for f in findings]}
