"""
Razonamiento profundo sobre los hallazgos del análisis estático de código.

Combina dos capas:

  1) ML LOCAL (sin red, siempre disponible): heurísticas cuantitativas que
     priorizan y enriquecen cada hallazgo —puntaje de riesgo, entropía del
     secreto, factor de exposición, correlación entre hallazgos del mismo
     archivo/módulo— y derivan el riesgo concreto de NO corregir.

  2) IA (Claude vía API, opcional): a partir EXCLUSIVAMENTE de la evidencia
     local ya estructurada, redacta el análisis profesional, profundo y sin
     redundancias por observación, con el riesgo de obviar la corrección.
     Si no hay API key o falla la red, se degrada con elegancia al texto
     determinista del análisis local (la app nunca queda sin informe).

El módulo NO ejecuta el código analizado ni envía secretos: la evidencia ya
viene redactada desde code_scan; aquí solo se razona sobre metadatos y extractos.
"""

from __future__ import annotations

import json
import math
import re

import net

ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-6"

_SEV_WEIGHT = {"crítico": 100, "alto": 70, "medio": 40, "bajo": 15, "info": 5}

# Escala 1-5 para impacto y probabilidad (etiquetas legibles para alta dirección).
_NIVEL_1_5 = {1: "Muy bajo", 2: "Bajo", 3: "Medio", 4: "Alto", 5: "Muy alto"}
_IMPACTO_BASE = {"crítico": 5, "alto": 4, "medio": 3, "bajo": 2, "info": 1}

# Reglas cuyo defecto es ALCANZABLE por un actor externo o afecta la postura
# global de la app (sube la probabilidad de materialización del riesgo).
_ALCANZABLE_EXTERNO = {"NET-CLEARTEXT", "NET-TRUST-ALL", "COMP-EXPORTED",
                       "WEB-JS-BRIDGE", "DATA-BACKUP-ON", "SQL-CONCAT", "SEC-GOOGLE-KEY"}
# Reglas que NO son una vía de explotación activa, sino una brecha de gobernanza,
# configuración o señal para revisión (acotan la probabilidad).
_GOBERNANZA = {"LIC-MISSING"}
_FLAG_REVISION = {"PII-RUT"}

# Causa técnica concreta por familia de regla (qué es y por qué ocurre).
_QUE_ES = {
    "SEC-API-KEY": "una clave de API o token de acceso quedó escrito directamente (hardcodeado) "
                   "en el código fuente en lugar de inyectarse desde una fuente segura en tiempo de ejecución",
    "SEC-GOOGLE-KEY": "una clave de servicios de Google quedó incrustada en un archivo del proyecto, "
                      "quedando disponible para cualquiera que acceda al binario o al repositorio",
    "SEC-PRIVATE-KEY": "una llave privada o certificado quedó versionado dentro del proyecto, cuando "
                       "debería custodiarse fuera del código (KMS/HSM o variable de entorno)",
    "SEC-PASSWORD": "una contraseña quedó escrita en texto plano en el código, en lugar de resolverse "
                    "desde un gestor de secretos o variable de entorno",
    "SEC-DB-URL": "una cadena de conexión incluye usuario y contraseña embebidos, exponiendo el acceso "
                  "directo al motor de base de datos",
    "CRY-WEAK-HASH": "se emplea un algoritmo de hash débil (MD5/SHA-1) que hoy se considera quebrado para "
                     "proteger datos sensibles o contraseñas",
    "CRY-ECB": "se cifra en modo ECB, que no oculta patrones del contenido y permite inferir información "
               "del texto cifrado",
    "NET-CLEARTEXT": "se permite tráfico HTTP sin cifrar, de modo que los datos viajan en texto claro por "
                     "la red",
    "NET-TRUST-ALL": "la validación del certificado TLS está deshabilitada, por lo que la app aceptaría "
                     "cualquier certificado, incluso uno falso",
    "SQL-CONCAT": "una consulta SQL se construye concatenando texto con datos variables, abriendo la puerta "
                  "a inyección SQL si esos datos provienen del usuario",
    "WEB-JS-BRIDGE": "un componente WebView habilita JavaScript o expone una interfaz nativa al contenido "
                     "web cargado, ampliando la superficie de ejecución",
    "DATA-BACKUP-ON": "la app permite que el sistema operativo respalde sus datos, lo que puede extraer "
                      "información del área protegida de la aplicación",
    "COMP-EXPORTED": "un componente de la app queda accesible (exportado) a otras aplicaciones del "
                     "dispositivo sin una protección explícita",
    "DBG-ENABLED": "la aplicación queda marcada como depurable, una condición propia del desarrollo que no "
                   "debe llegar a producción",
    "LOG-SENSITIVE": "se escriben en los registros (logs) datos que parecen sensibles (credenciales, "
                     "identificadores o datos personales)",
    "PII-RUT": "el código trata el RUT, un dato personal identificador de las personas en Chile",
    "PERM-DANGEROUS": "la app declara permisos sensibles (ubicación, cámara, micrófono u otros) que amplían "
                      "el acceso a datos del usuario",
    "LIC-MISSING": "el proyecto no incluye un archivo de licencia que defina las condiciones de uso y "
                   "redistribución del software",
    "TAINT-CWE-89": "un dato proveniente de una entrada no confiable llega, sin saneamiento, hasta una "
                    "consulta SQL (flujo de la fuente hacia el sumidero)",
    "TAINT-CWE-532": "un dato proveniente de una entrada no confiable llega hasta una operación de "
                     "registro/log (flujo de la fuente hacia el sumidero)",
    "TAINT-CWE-78": "un dato proveniente de una entrada no confiable llega hasta la ejecución de un "
                    "comando del sistema (flujo de la fuente hacia el sumidero)",
    "TAINT-CWE-749": "un dato proveniente de una entrada no confiable llega hasta la carga de un WebView "
                     "(flujo de la fuente hacia el sumidero)",
    "TAINT-CWE-95": "un dato proveniente de una entrada no confiable llega hasta una evaluación dinámica "
                    "de código (flujo de la fuente hacia el sumidero)",
    "TAINT-CWE-22": "un dato proveniente de una entrada no confiable llega hasta una ruta de archivo "
                    "(flujo de la fuente hacia el sumidero)",
}

# Explicación en lenguaje llano, orientada a alta dirección (sin tecnicismos).
_EXPLICACION_NO_TECNICA = {
    "SEC-API-KEY": "Es como dejar la llave de la casa pegada en la puerta: cualquiera que tenga una copia "
                   "de la aplicación puede encontrarla y usarla para entrar a los servicios en nombre de la "
                   "institución, hasta que esa llave se cambie.",
    "SEC-GOOGLE-KEY": "Equivale a dejar anotada la clave de una cuenta corporativa dentro de un archivo que "
                      "se reparte con la aplicación: un tercero podría usar y facturar esos servicios a la "
                      "institución.",
    "SEC-PRIVATE-KEY": "Es la llave maestra que acredita la identidad del sistema. Si se filtra, alguien "
                       "podría hacerse pasar por la institución o leer comunicaciones que deberían ser secretas.",
    "SEC-PASSWORD": "Es una contraseña escrita a la vista dentro del programa. Quien lea el código la "
                    "obtiene tal cual, sin necesidad de adivinarla.",
    "SEC-DB-URL": "Es como publicar la dirección de la bóveda junto con su combinación: deja el acceso a la "
                  "base de datos al alcance de quien lea el código.",
    "CRY-WEAK-HASH": "Se está usando un candado que ya se sabe cómo forzar. Aunque parezca que protege, hoy "
                     "se puede romper con herramientas disponibles públicamente.",
    "CRY-ECB": "Es un método de cifrado que deja entrever el contenido: aunque la información esté 'cerrada', "
               "se notan sus patrones, como un texto tapado con vidrio esmerilado.",
    "NET-CLEARTEXT": "Los datos viajan por la red como una postal en lugar de una carta cerrada: cualquiera "
                     "en el camino puede leerlos o alterarlos.",
    "NET-TRUST-ALL": "La aplicación acepta a cualquiera que diga ser el servidor, sin verificar su identidad. "
                     "Es como entregar documentos a alguien solo porque afirma ser el destinatario.",
    "SQL-CONCAT": "Se arma una orden a la base de datos mezclando texto fijo con lo que escribe el usuario. "
                  "Un usuario malintencionado puede colar instrucciones propias y manipular la información.",
    "WEB-JS-BRIDGE": "Se le da a una página web embebida la capacidad de ejecutar acciones dentro de la app. "
                     "Si esa página no es totalmente confiable, puede hacer cosas no previstas.",
    "DATA-BACKUP-ON": "El teléfono puede sacar una copia de los datos de la app hacia afuera de su zona "
                      "protegida, donde quedan más expuestos.",
    "COMP-EXPORTED": "Una pieza de la aplicación queda abierta para que otras apps del teléfono la usen, sin "
                     "un control que verifique quién la invoca.",
    "DBG-ENABLED": "La aplicación quedó en 'modo taller', pensado para desarrollar y no para el público. En "
                   "ese modo entrega más información interna de la necesaria.",
    "LOG-SENSITIVE": "Se están anotando en la 'bitácora' del sistema datos delicados. Esa bitácora puede ser "
                     "leída o filtrada, ampliando la exposición.",
    "PII-RUT": "La aplicación maneja el RUT de las personas. No es un error por sí mismo, pero obliga a "
               "verificar que ese dato se trate con la debida protección y para un fin informado.",
    "PERM-DANGEROUS": "La app pide acceso a información personal del usuario (por ejemplo ubicación o "
                      "micrófono). Hay que confirmar que cada permiso sea realmente necesario.",
    "LIC-MISSING": "Falta el documento que dice cómo puede usarse y compartirse el software. Sin él, el "
                   "marco de uso queda indefinido para otras instituciones.",
    "TAINT-CWE-89": "Un dato escrito por el usuario llega hasta una consulta a la base de datos sin "
                    "control. Es como dejar que un cliente escriba parte de la orden que ejecuta la bóveda: "
                    "podría pedir más de lo que le corresponde.",
    "TAINT-CWE-532": "Un dato del usuario termina escrito en la bitácora del sistema. Si ese dato es "
                     "sensible, queda guardado donde no debería y puede filtrarse.",
    "TAINT-CWE-78": "Un dato del usuario llega a una orden que ejecuta el sistema operativo. Es como dejar "
                    "que un extraño dicte instrucciones directas al servidor.",
    "TAINT-CWE-749": "Un dato del usuario llega a una vista web embebida que puede ejecutar acciones; si no "
                     "es confiable, podría realizar operaciones no previstas.",
    "TAINT-CWE-95": "Un dato del usuario llega a una función que ejecuta código; permitiría correr "
                    "instrucciones ajenas dentro de la aplicación.",
    "TAINT-CWE-22": "Un dato del usuario llega a una ruta de archivo; podría usarse para leer o escribir "
                    "archivos fuera de lo previsto.",
}


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _exposure_factor(archivo: str) -> float:
    """Factor de exposición: el mismo defecto pesa más en código de producción
    que en archivos de prueba o ejemplos."""
    a = (archivo or "").lower()
    if "/test/" in a or "test" in a.split("/")[-1] or "/androidtest/" in a:
        return 0.5     # en pruebas: menor exposición real
    if "example" in a or "sample" in a or "mock" in a:
        return 0.4
    if a.endswith(".md") or "/docs/" in a:
        return 0.3
    return 1.0         # código de producción


def _nivel_riesgo(valor: int) -> str:
    """Mapa de la matriz impacto×probabilidad (1..25) a nivel de riesgo."""
    if valor >= 15:
        return "Crítico"
    if valor >= 9:
        return "Alto"
    if valor >= 5:
        return "Medio"
    if valor >= 3:
        return "Bajo"
    return "Informativo"


def _calcular_impacto(item: dict, rol: str, exposicion: str):
    """Impacto (1-5) con justificación, situado en el rol del archivo."""
    base = _IMPACTO_BASE.get(item["severidad"], 2)
    just = [f"severidad intrínseca de la regla: {item['severidad']}"]
    cat = item.get("categoria")
    rid = item["rule_id"]
    if cat == "COMPARTIMENTAJE" and any(k in rol for k in
                                        ("credenciales", "servicios externos", "manifiesto")):
        just.append(f"el archivo cumple un rol de {rol}, donde exponer un secreto compromete "
                    "directamente el acceso a la plataforma")
    if rid == "SQL-CONCAT" and "persistencia" in rol:
        just.append("se ubica en la capa de acceso a datos, por lo que una inyección alcanzaría "
                    "directamente el repositorio de información")
    if rid in ("NET-CLEARTEXT", "NET-TRUST-ALL") and "red" in rol:
        just.append("afecta la capa de comunicación con servicios remotos, exponiendo los datos "
                    "en tránsito")
    if exposicion == "prueba/ejemplo":
        base = max(base - 1, 1)
        just.append("al residir en código de prueba/ejemplo, el impacto sobre el sistema "
                    "productivo es menor")
    base = max(1, min(base, 5))
    return base, just


def _calcular_probabilidad(item: dict, entropy: float, exposicion: str, en_hotspot: bool,
                           secret_p: float | None = None):
    """Probabilidad de materialización (1-5) con justificación. Integra el
    clasificador ML de secretos y la alcanzabilidad por flujo de datos (taint)."""
    rid = item["rule_id"]
    if exposicion == "producción":
        p = 3
        just = ["el hallazgo reside en código de producción, alcanzable en operación real"]
    else:
        p = 1
        just = ["el hallazgo reside en código de prueba/ejemplo, lo que reduce la probabilidad "
                "de un impacto real en producción"]
    # Clasificador ML de secretos: ajusta la probabilidad según verosimilitud.
    if item.get("categoria") == "COMPARTIMENTAJE" and secret_p is not None:
        if secret_p >= 0.75:
            p += 1
            just.append(f"el clasificador de secretos estima alta verosimilitud ({secret_p:.0%}) "
                        "de que el literal sea un secreto real y utilizable")
        elif secret_p < 0.2:
            p -= 1
            just.append(f"el clasificador de secretos estima baja verosimilitud ({secret_p:.0%}): "
                        "parece un marcador de posición o valor de ejemplo (posible falso positivo)")
    elif item.get("categoria") == "COMPARTIMENTAJE" and entropy >= 4.0:
        p += 1
        just.append(f"la alta entropía del literal ({entropy:.1f} bits) sugiere un secreto real")
    # Alcanzabilidad por flujo de datos (taint): sube la probabilidad.
    if item.get("alcanzable_taint"):
        p += 1
        rf = item.get("ruta_flujo") or {}
        just.append(f"el análisis de flujo de datos detectó una ruta explotable: una {rf.get('fuente','entrada externa')} "
                    f"(línea {rf.get('fuente_linea','?')}) alcanza el sumidero de {rf.get('sumidero','operación sensible')} "
                    f"(línea {rf.get('sumidero_linea','?')})")
    if rid in _ALCANZABLE_EXTERNO:
        p += 1
        just.append("el defecto es alcanzable desde fuera de la aplicación o afecta su "
                    "configuración global, por lo que un tercero podría desencadenarlo sin "
                    "acceso privilegiado")
    if en_hotspot:
        just.append("el archivo concentra múltiples hallazgos (punto caliente), lo que aumenta la "
                    "probabilidad de que al menos uno sea explotable y facilita el encadenamiento")
    if rid in _GOBERNANZA:
        p = min(p, 1)
        just.append("no constituye una vía de explotación activa, sino una brecha de gobernanza "
                    "del proyecto")
    if rid in _FLAG_REVISION:
        p = min(p, 2)
        just.append("no es una vulnerabilidad explotable en sí, sino una señal que obliga a "
                    "revisar el tratamiento del dato")
    p = max(1, min(p, 5))
    return p, just


def _descripcion_contextual(item: dict) -> str:
    ctx = item.get("contexto") or {}
    rol = ctx.get("rol_archivo", "componente de la aplicación")
    constructo = ctx.get("constructo")
    rid = item["rule_id"]
    que = _QUE_ES.get(rid, item["titulo"].lower())
    donde = item["archivo"] + (f", línea {item['linea']}" if item.get("linea") else "")
    ubic = f"en {donde}"
    if constructo:
        ubic += f", dentro de {constructo}"
    return (f"En este artefacto, {que}. Se detectó {ubic}, archivo cuyo rol es la "
            f"{rol}. La evidencia capturada en contexto confirma el patrón sobre la línea señalada.")


def _impacto_en_contexto(item: dict) -> str:
    ctx = item.get("contexto") or {}
    rol = ctx.get("rol_archivo", "componente de la aplicación")
    base = _RIESGO_OMISION.get(item["rule_id"],
                               "Puede derivar en incumplimiento o vulnerabilidad si no se corrige.")
    return (f"Dado que el archivo participa en la {rol}, {base}")


def _mitigacion_puntual(item: dict) -> str:
    arch = item["archivo"].split("/")[-1]
    linea = f" (línea {item['linea']})" if item.get("linea") else ""
    return f"En «{arch}»{linea}: {item['mitigacion']}"


def analyze_local(scan: dict) -> dict:
    """Capa ML local (determinista, sin red). Enriquece cada hallazgo con un
    modelo explícito de IMPACTO × PROBABILIDAD (con justificación), descripción
    contextual situada en el rol del archivo, explicación para no técnicos y
    mitigación puntual; produce además métricas agregadas y puntos calientes."""
    findings = scan.get("findings", [])
    by_file = {}
    for f in findings:
        by_file.setdefault(f.get("archivo", "(n/d)"), []).append(f["rule_id"])
    hotspot_files = {a for a, ids in by_file.items() if len(ids) >= 2}

    enriched = []
    for f in findings:
        exp = _exposure_factor(f.get("archivo", ""))
        exposicion = "producción" if exp >= 1.0 else "prueba/ejemplo"
        ev = f.get("evidencia", "")
        m = re.search(r"[A-Za-z0-9+/_\-]{12,}", ev)
        entropy = _shannon(m.group(0)) if m else 0.0
        rol = (f.get("contexto") or {}).get("rol_archivo", "componente de la aplicación")
        en_hotspot = f.get("archivo") in hotspot_files

        # Clasificador ML de secretos (solo para hallazgos de secretos).
        secret_p = None
        if f.get("categoria") == "COMPARTIMENTAJE":
            try:
                import ml_secrets as _ML
                lit = _ML.extraer_literal(ev)
                secret_p = _ML.secret_probability(lit, ev)
            except Exception:
                secret_p = None

        impacto, impacto_just = _calcular_impacto(f, rol, exposicion)
        prob, prob_just = _calcular_probabilidad(f, entropy, exposicion, en_hotspot, secret_p)
        riesgo_valor = impacto * prob
        nivel_riesgo = _nivel_riesgo(riesgo_valor)

        item = dict(f)
        if secret_p is not None:
            item["secreto_prob"] = secret_p
            item["posible_falso_positivo"] = secret_p < 0.2
        # Puntaje continuo (compat. con ordenamiento/agregación previos).
        ent_factor = 1.0 + min(entropy / 6.0, 0.6) if f["categoria"] == "COMPARTIMENTAJE" else 1.0
        item["score"] = round(_SEV_WEIGHT.get(f["severidad"], 5) * exp * ent_factor, 1)
        item["exposicion"] = exposicion
        item["entropia"] = round(entropy, 2)
        item["en_hotspot"] = en_hotspot
        # Modelo de riesgo explícito.
        item["impacto"] = impacto
        item["impacto_nivel"] = _NIVEL_1_5[impacto]
        item["impacto_just"] = "; ".join(impacto_just) + "."
        item["probabilidad"] = prob
        item["probabilidad_nivel"] = _NIVEL_1_5[prob]
        item["probabilidad_just"] = "; ".join(prob_just) + "."
        item["riesgo_valor"] = riesgo_valor
        item["nivel_riesgo"] = nivel_riesgo
        # Narrativa contextual determinista (la IA puede enriquecerla luego).
        item["descripcion_contextual"] = _descripcion_contextual(f)
        item["explicacion_no_tecnica"] = _EXPLICACION_NO_TECNICA.get(
            f["rule_id"], "Es una observación técnica que conviene revisar con el equipo de desarrollo.")
        item["impacto_contexto"] = _impacto_en_contexto(f)
        item["mitigacion_puntual"] = _mitigacion_puntual(f)
        item["riesgo_omision"] = _RIESGO_OMISION.get(
            f["rule_id"], "Puede derivar en incumplimiento o vulnerabilidad si no se corrige.")
        # 'analisis' se mantiene por compatibilidad: concentra la descripción.
        item["analisis"] = item["descripcion_contextual"]
        enriched.append(item)

    # Orden: primero por nivel de riesgo contextual, luego por puntaje.
    _ord = {"Crítico": 5, "Alto": 4, "Medio": 3, "Bajo": 2, "Informativo": 1}
    enriched.sort(key=lambda x: (-_ord.get(x["nivel_riesgo"], 0), -x["score"]))

    hotspots = sorted(((a, ids) for a, ids in by_file.items() if len(ids) >= 2),
                      key=lambda x: -len(x[1]))[:8]
    riesgo_global = round(sum(x["score"] for x in enriched), 1)
    nivel_global = ("crítico" if any(x["nivel_riesgo"] == "Crítico" for x in enriched)
                    else "alto" if any(x["nivel_riesgo"] == "Alto" for x in enriched)
                    else "medio" if any(x["nivel_riesgo"] == "Medio" for x in enriched)
                    else "bajo")
    return {
        "enriched": enriched,
        "hotspots": [{"archivo": a, "reglas": ids} for a, ids in hotspots],
        "riesgo_global": riesgo_global, "nivel_global": nivel_global,
    }


def _fallback_text(item: dict) -> str:
    """Texto determinista por hallazgo cuando no hay IA disponible (compat.)."""
    return item.get("descripcion_contextual") or (
        f"{item['titulo']}. Ubicado en {item['archivo']}"
        + (f", línea {item['linea']}" if item.get("linea") else "")
        + f" (exposición: {item['exposicion']}).")


# Riesgo concreto de NO corregir, por familia de regla (impacto si se obvia).
_RIESGO_OMISION = {
    "SEC-API-KEY": "un tercero que obtenga el binario o el repositorio puede extraer el token y "
                   "suplantar al usuario o consumir la API en su nombre mientras el token sea válido; "
                   "si no rota, la exposición es permanente.",
    "SEC-GOOGLE-KEY": "la llave puede usarse para consumir cuota de servicios Google facturados a la "
                      "institución o acceder a servicios habilitados, generando costos y posible fuga de datos.",
    "SEC-PRIVATE-KEY": "la llave privada permite descifrar tráfico, firmar artefactos maliciosos o "
                       "suplantar la identidad del servicio; su filtración compromete toda la cadena de confianza.",
    "SEC-PASSWORD": "una credencial embebida puede usarse para acceso no autorizado; si es real, el acceso "
                    "queda disponible para cualquiera con el código.",
    "SEC-DB-URL": "la cadena con credenciales expone directamente la base de datos a acceso no autorizado, "
                  "con riesgo de exfiltración o alteración masiva de datos.",
    "NET-CLEARTEXT": "el tráfico en texto claro puede ser interceptado o manipulado en redes no confiables "
                     "(ataques de intermediario), exponiendo credenciales y datos personales en tránsito.",
    "NET-TRUST-ALL": "aceptar cualquier certificado anula la protección de TLS: un atacante puede interponerse "
                     "con un certificado falso y leer o alterar toda la comunicación.",
    "CRY-WEAK-HASH": "los hashes débiles permiten recuperar contraseñas mediante tablas precomputadas o "
                     "colisiones, comprometiendo las credenciales almacenadas.",
    "CRY-ECB": "el modo ECB filtra patrones del texto cifrado, permitiendo inferir contenido sin descifrar.",
    "DBG-ENABLED": "el modo depuración en producción puede exponer trazas, datos internos y vectores de "
                   "depuración aprovechables por un atacante.",
    "LOG-SENSITIVE": "registrar datos sensibles deja información personal o secretos en archivos de log que "
                     "pueden ser accedidos o exfiltrados, ampliando la superficie de fuga.",
    "PII-RUT": "el tratamiento de RUT sin base de licitud, finalidad informada ni cifrado expone a la "
               "institución a infracciones de la Ley 19.628 y a daño a los titulares de los datos.",
    "PERM-DANGEROUS": "los permisos excesivos amplían la superficie de ataque y el impacto a la privacidad; "
                      "un compromiso de la app accedería a ubicación, cámara o micrófono del usuario.",
    "SQL-CONCAT": "la concatenación de SQL habilita inyección: extracción, alteración o borrado de datos, e "
                  "incluso el control del motor de base de datos.",
    "WEB-JS-BRIDGE": "un WebView con JavaScript o interfaz nativa expuesta a contenido remoto no confiable "
                     "permite ejecutar código en el contexto de la app, con riesgo de robo de datos o de la sesión.",
    "DATA-BACKUP-ON": "con allowBackup habilitado, los datos del área protegida de la app pueden extraerse "
                      "vía adb o respaldos en la nube, exponiendo información sensible fuera de su control.",
    "COMP-EXPORTED": "un componente exportado sin protección puede ser invocado por otras apps del dispositivo, "
                     "abriendo una vía de acceso no autorizado o de manipulación de la lógica de la aplicación.",
    "LIC-MISSING": "sin licencia, el marco de uso y redistribución queda indefinido, dificultando la "
                   "colaboración entre instituciones y el cumplimiento del lineamiento de software público.",
    "TAINT-CWE-89": "un atacante podría inyectar SQL a través de la entrada, leyendo, alterando o "
                    "borrando datos, o eludiendo la autenticación.",
    "TAINT-CWE-532": "datos del usuario podrían quedar registrados en los logs, ampliando la superficie "
                     "de fuga de información.",
    "TAINT-CWE-78": "un atacante podría ejecutar comandos arbitrarios en el sistema operativo a través "
                    "de la entrada no saneada.",
    "TAINT-CWE-749": "contenido no confiable podría ejecutar acciones dentro del WebView con los "
                     "privilegios de la aplicación.",
    "TAINT-CWE-95": "un atacante podría ejecutar código arbitrario evaluado dinámicamente por la "
                    "aplicación.",
    "TAINT-CWE-22": "un atacante podría leer o escribir archivos fuera de la ruta prevista (traversal).",
}


def reason(scan: dict, api_key: str | None = None, model: str | None = None,
           use_ai: bool = True) -> dict:
    """Orquesta ML local + IA. Devuelve el scan enriquecido con análisis por
    hallazgo y un análisis ejecutivo. Degrada a texto local si no hay IA."""
    local = analyze_local(scan)
    enriched = local["enriched"]
    ai_used = False
    ai_error = None

    if use_ai and api_key:
        narr, ai_error = _ai_reason(scan, local, api_key, model or DEFAULT_MODEL)
        if narr:
            ai_used = True
            ana_by_id = {a["ref"]: a for a in narr.get("analisis", [])}
            for i, item in enumerate(enriched):
                a = ana_by_id.get(i)
                if a:
                    # La IA enriquece la PROSA; el modelo de riesgo (impacto×
                    # probabilidad) se mantiene determinista y auditable.
                    if a.get("descripcion_contextual"):
                        item["descripcion_contextual"] = a["descripcion_contextual"]
                        item["analisis"] = a["descripcion_contextual"]
                    if a.get("explicacion_no_tecnica"):
                        item["explicacion_no_tecnica"] = a["explicacion_no_tecnica"]
                    if a.get("impacto_contexto"):
                        item["impacto_contexto"] = a["impacto_contexto"]
                    if a.get("mitigacion_puntual"):
                        item["mitigacion_puntual"] = a["mitigacion_puntual"]
                    if a.get("riesgo_omision"):
                        item["riesgo_omision"] = a["riesgo_omision"]
            if narr.get("resumen_ejecutivo"):
                local["resumen_ejecutivo"] = narr["resumen_ejecutivo"]
            else:
                local["resumen_ejecutivo"] = _exec_fallback(scan, local)
    if not ai_used:
        local["resumen_ejecutivo"] = _exec_fallback(scan, local)

    local["ai_used"] = ai_used
    local["ai_error"] = ai_error
    return local


def _exec_fallback(scan, local) -> str:
    rs = scan.get("resumen", {})
    sev = rs.get("por_severidad", {})
    enr = local.get("enriched", [])
    partes = ", ".join(f"{k}: {v}" for k, v in sev.items())
    # Conteo por nivel de riesgo CONTEXTUAL (no solo por severidad de la regla).
    porr = {}
    for x in enr:
        porr[x["nivel_riesgo"]] = porr.get(x["nivel_riesgo"], 0) + 1
    cuenta_r = ", ".join(f"{k.lower()}: {v}" for k, v in
                         sorted(porr.items(), key=lambda kv: -{"Crítico": 5, "Alto": 4,
                                "Medio": 3, "Bajo": 2, "Informativo": 1}.get(kv[0], 0)))
    top = enr[0] if enr else None
    foco = ""
    if top:
        foco = (f" La observación de mayor prioridad es «{top['titulo']}» en "
                f"{top['archivo'].split('/')[-1]}, con nivel de riesgo {top['nivel_riesgo'].lower()} "
                f"(impacto {top['impacto_nivel'].lower()} × probabilidad "
                f"{top['probabilidad_nivel'].lower()}).")
    n_hot = len(local.get("hotspots", []))
    hot = (f" Se identificaron {n_hot} punto(s) caliente(s) (archivos que concentran varios "
           f"hallazgos), que deben revisarse de forma integral." if n_hot else "")
    return (f"El análisis estático identificó {rs.get('total', 0)} observaciones ({partes}). "
            f"Ponderadas por contexto (impacto × probabilidad), el riesgo se distribuye en "
            f"{cuenta_r}. El nivel de riesgo agregado de la plataforma es {local['nivel_global']}."
            f"{foco}{hot} Se recomienda remediar primero las observaciones de nivel crítico y "
            "alto antes de promover la plataforma a producción. Este es un insumo técnico de "
            "aseguramiento de calidad; el detalle de impacto, probabilidad y justificación de "
            "cada punto se presenta en la sección de análisis técnico.")


def _ai_reason(scan, local, api_key, model):
    """Pide a Claude un análisis profundo por hallazgo + resumen ejecutivo, a
    partir EXCLUSIVAMENTE de la evidencia local (no inventa)."""
    payload = {
        "proyecto": scan.get("archive", {}).get("nombre"),
        "stats": scan.get("stats", {}),
        "resumen": scan.get("resumen", {}),
        "nivel_global_local": local["nivel_global"],
        "hotspots": local["hotspots"],
        "hallazgos": [
            {"ref": i, "rule_id": x["rule_id"], "titulo": x["titulo"],
             "severidad": x["severidad"], "categoria": x["categoria"],
             "archivo": x["archivo"], "linea": x.get("linea"),
             "evidencia": x["evidencia"], "exposicion": x["exposicion"],
             "rol_archivo": (x.get("contexto") or {}).get("rol_archivo"),
             "constructo": (x.get("contexto") or {}).get("constructo"),
             "impacto_nivel": x["impacto_nivel"], "probabilidad_nivel": x["probabilidad_nivel"],
             "nivel_riesgo": x["nivel_riesgo"], "cwe": x.get("cwe"),
             "guia": x["guia"], "legal": x["legal"], "score": x["score"]}
            for i, x in enumerate(local["enriched"])
        ],
    }
    prompt = (
        "Actúa como Analista QA Senior y ingeniero de seguridad de software / DevSecOps en "
        "Chile, responsable de validar procesos críticos. Usa SIEMPRE español de Chile, "
        "profesional y directo (sin anglicismos innecesarios ni modismos de España). "
        "A partir EXCLUSIVAMENTE del JSON de hallazgos del análisis estático (NO inventes "
        "archivos, líneas, CVEs ni artículos que no estén; respeta 'rol_archivo' y 'constructo' "
        "como el contexto real de uso del código), entrega un análisis TÉCNICO profundo, "
        "situado y SIN redundancias. El análisis técnico debe estar SEPARADO del cumplimiento "
        "normativo/legal (de eso se encarga otra sección): aquí céntrate en lo técnico.\n"
        "Para CADA hallazgo (identificado por 'ref') redacta en JSON estos campos:\n"
        " - 'descripcion_contextual': 2 a 4 frases que expliquen la causa técnica concreta y por "
        "   qué es un riesgo EN ESTE archivo y constructo (cita el rol del archivo; si "
        "   'exposicion' es prueba/ejemplo, dilo y modera el tono). No repitas el título.\n"
        " - 'explicacion_no_tecnica': 1 a 2 frases para alta dirección, en lenguaje llano y sin "
        "   tecnicismos, sobre qué significa el problema y por qué importa.\n"
        " - 'impacto_contexto': 1 a 2 frases sobre cómo impacta dado lo que hace ese código.\n"
        " - 'mitigacion_puntual': 1 a 2 frases con la corrección concreta para ESTE archivo "
        "   (no genérica), accionable por el equipo de desarrollo.\n"
        " - 'riesgo_omision': 1 frase con la consecuencia de NO corregir.\n"
        "NO redefinas el nivel de riesgo, impacto ni probabilidad: esos valores ya están "
        "calculados y son fijos; solo explícalos en prosa si ayuda.\n"
        "Además entrega 'resumen_ejecutivo' (4-6 frases) para alta dirección: panorama global, "
        "distribución de riesgo, puntos calientes y prioridad de remediación. Enmarca todo como "
        "INSUMO para la evaluación de QA, no como dictamen jurídico.\n"
        "Responde ÚNICAMENTE con JSON válido, sin markdown:\n"
        '{"resumen_ejecutivo":"...","analisis":[{"ref":0,"descripcion_contextual":"...",'
        '"explicacion_no_tecnica":"...","impacto_contexto":"...","mitigacion_puntual":"...",'
        '"riesgo_omision":"..."}]}\n\n'
        "HALLAZGOS:\n" + json.dumps(payload, ensure_ascii=False, default=str)
    )
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    body = {"model": model, "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}]}
    try:
        r = net.post(ANTHROPIC_ENDPOINT, headers=headers, json=body, timeout=90)
    except net.NetworkError as e:
        return None, f"sin conexión a la API ({e})"
    if r.status_code == 401:
        return None, "API key inválida (401)"
    if r.status_code != 200:
        return None, f"la API respondió HTTP {r.status_code}"
    try:
        data = r.json()
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text").strip()
        text = text.replace("```json", "").replace("```", "").strip()
        return json.loads(text), None
    except Exception as e:
        return None, f"respuesta de IA no parseable ({e})"
