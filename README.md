# WebDev Software Catalog

Dashboard **independiente** que inventaría productos y versiones de software
existentes en internet, orientado al desarrollo de sitios web: lenguajes y
runtimes, servidores web, bases de datos, frameworks backend/frontend, CMS,
etc. — con sus ciclos de versión, fechas de fin de soporte (EOL) y CVEs
conocidos.

Fuentes (en vivo, con caché local en SQLite):
- **endoflife.date** — productos, versiones, fechas de release/EOL/soporte, LTS.
- **OSV.dev** — CVEs por producto/versión, donde existe mapeo de ecosistema.

Es un proyecto autónomo: no depende de ninguna otra aplicación.

## Requisitos
- Python 3.10 o superior.

## Instalación
```bash
pip install -r requirements.txt
# (en red corporativa con proxy:)
# pip install --proxy http://HOST:PUERTO -r requirements.txt
```

## Uso
```bash
python app.py
```
Abre http://127.0.0.1:5001

En el primer arranque descarga el catálogo automáticamente. Botón
**"↻ actualizar catálogo"** para refrescar desde internet cuando quieras.

## Proxy / CA corporativa
- Usa el almacén de certificados del SISTEMA OPERATIVO (vía `truststore`), así
  que las CA de inspección TLS (Zscaler, etc.) ya confiadas por Windows
  funcionan sin configuración extra.
- Si necesitas un proxy, ponlo en el panel **"// conexión"** de la página
  (se guarda en `config.json`), o exporta `HTTPS_PROXY` antes de arrancar.
- Botón **"probar conexión"** para diagnosticar (SSL/CA, proxy, timeout).

## Archivos generados
- `catalog.db` — caché local del catálogo (SQLite). Borrable; se regenera.
- `config.json` — proxy guardado.

## Personalizar qué productos aparecen
Edita `catalog_data.py`:
- `WEBDEV_CATEGORIES`: slug de endoflife.date → categoría.
- `OSV_MAP`: slug → (ecosistema, paquete) para habilitar la búsqueda de CVEs.


## Fuentes de datos

Este catálogo combina **dos fuentes** para cubrir todo el stack web:

1. **endoflife.date** — lenguajes, runtimes, servidores, bases de datos, CMS y
   frameworks con ciclos de vida y fechas de fin de soporte (EOL).
2. **registro npm** (registry.npmjs.org) — librerías JavaScript que endoflife.date
   no cataloga (jQuery, jQuery UI, D3, Three.js, Plotly, Moment.js, SweetAlert2,
   OWL Carousel, Swiper, FancyBox, GSAP, DataTables, Bootstrap Icons, Font Awesome,
   Turf.js, MapTiler, Firebase, RxJS, Zone.js, etc.). Se agrupan por versión mayor
   con su fecha de publicación; la mayor más reciente queda como "ok" y las
   anteriores como "obsoleto" (superada). Las librerías no tienen EOL formal.

En ambos casos los CVEs se consultan en **OSV.dev** (ecosistema npm/PyPI/Packagist
según corresponda).

Para agregar más librerías, edita `NPM_LIBRARIES` en `catalog_data.py`
(paquete npm → nombre y categoría). Para productos con EOL, edita
`WEBDEV_CATEGORIES`.


## Auditar un package.json (QA)

En el panel **"// QA · auditar package.json"** puedes pegar o subir el
`package.json` de un desarrollo. Por cada dependencia (prod, dev, peer, opcional)
muestra:

- versión **declarada** (el rango, ej. `^19.2.21`),
- versión **instalada** que resuelve ese rango,
- última versión en **npm** (con su fecha),
- **desfase**: al día / patch / minor / **major**,
- **CVEs** conocidos para la versión instalada (vía OSV).

Arriba entrega un **veredicto** y conteos (desactualizadas, major atrás, con CVE),
y puedes exportar el detalle a CSV. Pensado para revisar builds que pasan por QA.


## Reporte de riesgo con IA (Claude)

Tras auditar un `package.json`, el botón **"📄 generar reporte IA"** produce un
reporte con esta estructura:

- **Análisis General**
- **Análisis Técnico** (por aplicativo):
  - aplicativo con su versión y grado de severidad de riesgo,
  - riesgos conocidos (CVE/severidad, atraso de versión, EOL),
  - precisión técnica (confianza del hallazgo y fuente de datos),
  - medidas de mitigación recomendadas;
- **Conclusión General** (veredicto QA + acciones prioritarias).

Cómo funciona, en dos capas:

1. **Modelo de riesgo local (determinista)**: calcula el nivel de riesgo por
   dependencia y el veredicto a partir de datos duros (CVEs y severidad CVSS de
   OSV, atraso de versión de npm). Siempre disponible, sin IA.
2. **Redacción con IA (Claude)**: si configuras una API key de Anthropic en
   **⚙ configurar IA**, el Análisis General y la Conclusión se redactan con
   Claude, anclados en los hallazgos del paso 1 (con instrucción de NO inventar
   CVEs ni versiones). Sin key, se usa una redacción por plantilla con los mismos
   datos.

La key se guarda localmente en `config.json` y se usa a través de tu proxy/CA;
requiere acceso a `api.anthropic.com`. El modelo es configurable (por defecto
`claude-sonnet-4-6`). El reporte se puede descargar en Markdown.


## Exportar el reporte (DOCX / PDF / MD / TXT)

Una vez generado el reporte, los botones **DOCX · PDF · MD · TXT** lo descargan
en ese formato. Todos comparten la misma estructura (Análisis General, Técnico,
Conclusión) e incluyen:

- estilos, colores por nivel de riesgo, tablas y tipografías (DOCX y PDF);
- **detalle expandido de cada CVE** (resumen, severidad, fechas, enlaces);
- **URL oficial del desarrollador** (sitio, repositorio, página npm);
- **referencia de EOL / ciclo de vida** (enlace a endoflife.date cuando aplica);
- precisión técnica y medidas de mitigación por dependencia.

La generación es 100% server-side en Python (python-docx, reportlab), sin
dependencias del sistema, así que funciona en Windows tal cual.


## Historial de auditorías

La pestaña **"historial de auditorías"** registra cada `package.json` del que se
generó un reporte, con columnas: fecha, nombre de archivo, **hash SHA-256**,
nombre de la aplicación, versión (si venía en el JSON), veredicto, acceso a la
**auditoría en ventana emergente** (botón 👁 ver) y **descarga del reporte** en
PDF, DOCX, MD, TXT o CSV. Los registros se guardan en la base local
(`catalog.db`, tabla `audits`) y pueden eliminarse individualmente.


## Cumplimiento legal (Ley 21.459 / Ley 19.628)

La auditoría cruza cada dependencia con la legislación chilena de delitos
informáticos. Gradúa el riesgo legal según la evidencia:

- **Medio (revisión):** validadores/formateadores de identificadores (p. ej.
  `chilean-rutify`) — algoritmo público, no contienen datos; se revisa el
  tratamiento de datos personales por la aplicación (Ley 19.628).
- **Grave (alto):** paquetes de *consulta* de datos por identificador
  ("rutificadores") — posibles fuentes ilícitas; se cita el Art. 6 (receptación
  de datos informáticos).
- **Gravísimo (crítico):** paquetes con evidencia de ser maliciosos (advisories
  de malware en OSV) — Arts. 1, 2, 4, 7 y 8.

Los hallazgos de nivel grave/gravísimo fuerzan el veredicto a RECHAZADO, se
detallan en una sección "Análisis de Cumplimiento Legal" del reporte (en todos
los formatos) aludiendo a los artículos correspondientes, y siempre en
condicional con la advertencia de que no constituyen asesoría legal.


## Análisis estático de código (SAST) y motor de cumplimiento normativo

Sube el código fuente de una aplicación comprimido (`.zip`, `.7z` o `.rar`) en
el panel **"análisis de código"**. La herramienta:

1. **Extrae** el archivo en un directorio temporal aislado, con defensas contra
   *zip-slip* y *zip-bomb* (límites de tamaño, número de archivos y ratio de
   compresión). Nunca ejecuta el código.
2. **Escanea** (SAST ligero por patrones, en una sola pasada por archivo) en
   busca de secretos embebidos, criptografía débil, tráfico en texto claro,
   validación TLS deshabilitada, SQL por concatenación, WebView inseguro,
   permisos sensibles, logging de datos personales, modo debug, respaldo y
   componentes exportados, licencia ausente, etc. Cada hallazgo trae severidad,
   evidencia enmascarada, la cláusula de la Guía SEGPRES, la norma legal, el
   identificador **CWE** y la lista de **controles normativos** afectados.
3. **Razona** sobre la evidencia (aprendizaje automático local y, si hay clave
   configurada, modelo de lenguaje) para producir el resumen ejecutivo, el
   nivel de riesgo agregado y los puntos calientes.
4. **Evalúa el cumplimiento** contra un catálogo de **controles auditables**
   (`regulatory.py`) derivados artículo por artículo de la normativa chilena de
   Transformación Digital del Estado y seguridad del documento electrónico.

### Marco normativo integrado

El catálogo mapea los hallazgos del código a los siguientes instrumentos:

- **Decreto 7/2023** — Norma Técnica de Seguridad de la Información y
  Ciberseguridad (Ley 21.180). Estructura por las 5 funciones del marco
  (Identificar, Proteger, Detectar, Responder, Recuperar).
- **Decreto 9/2023** — Norma Técnica de Autenticación: OpenID Connect / OAuth
  2.0 (Art. 6), cifrado de factores con Bcrypt/PBKDF2/SHA-3/Argon2 (Art. 6),
  TLS 1.2+ (Art. 6), prevención de fuerza bruta (Art. 7), trazabilidad de
  accesos en UTC (Art. 13) y protección de datos personales (Art. 14).
- **Decreto 10/2023** — Documentos y Expedientes Electrónicos (integridad y
  protección de los datos del expediente).
- **Decreto 11/2023** — Calidad y Funcionamiento de las Plataformas (línea de
  base de calidad, Plan de Mejora Continua, licenciamiento).
- **DS 83/2004** — Seguridad y Confidencialidad del Documento Electrónico:
  atributos esenciales (Art. 6), antimalware y cifrado (Art. 26), robustez de
  identificadores (Art. 28), credenciales no en texto claro (Art. 29) y control
  de acceso (Arts. 31-32).

### Estados de los controles y veredicto

Cada control recibe uno de cuatro estados: **cumple**, **no cumple**,
**observado** o **no evaluable**. Los controles organizacionales (políticas,
roles, diagnósticos, planes) que el análisis estático no puede verificar se
reportan honestamente como *no evaluables*, indicando qué evidencia documental
los acreditaría. El motor entrega una **matriz de conformidad por instrumento**,
una **cobertura por función** del Decreto 7, el porcentaje de controles
evaluables conformes y un **veredicto global** (CONFORME / CONFORME CON
OBSERVACIONES / NO CONFORME).

### Análisis técnico contextual y modelo de riesgo

El informe separa el **análisis técnico** del **cumplimiento normativo/legal**.
Cada observación técnica se desarrolla en el **contexto real de uso del código**
(inteligencia local): se infiere el rol del archivo (gestión de credenciales,
acceso a datos, manifiesto, comunicación de red, etc.), se localiza el constructo
que contiene el hallazgo (clase/objeto o función/método) y se incluye un
fragmento de código alrededor de la línea afectada (con los secretos
enmascarados). Para cada observación se entrega: una descripción situada, una
explicación en lenguaje llano para alta dirección, la ubicación con su rol y
exposición, la evidencia en contexto, el **cálculo del nivel de riesgo** y una
mitigación puntual referida a ese archivo.

El nivel de riesgo se calcula como **impacto × probabilidad**, ambos en escala
1-5 y con su justificación explícita:

- **Impacto**: parte de la severidad intrínseca de la regla y se ajusta por el
  rol del archivo (por ejemplo, un secreto en un gestor de credenciales pesa más
  que en código de prueba).
- **Probabilidad**: parte de la exposición (producción vs. prueba/ejemplo) y se
  ajusta por la entropía del literal (un secreto de alta entropía es más
  probablemente real), por si el defecto es alcanzable por un actor externo o
  afecta la configuración global, y por la concentración de hallazgos en el
  archivo (punto caliente).

El producto (1-25) se mapea a **Crítico / Alto / Medio / Bajo / Informativo**.
Así, una misma regla puede arrojar distinto nivel de riesgo según el contexto,
lo que evita observaciones genéricas y hace auditable la justificación.

El informe profesional exportable (DOCX / PDF / MD) incluye portada, resumen
ejecutivo con veredicto, sección de conformidad normativa, panorama técnico,
análisis técnico detallado por observación, marco normativo de referencia y
anexo metodológico. El documento usa interlineado 1.0 sin espacio entre párrafos.

### Análisis avanzado: multi-motor, flujo de datos y ML (opcional)

El análisis propio se robustece con tres técnicas complementarias. Todas son
**opcionales y se autodetectan**: si las herramientas no están instaladas, la
aplicación funciona igual con su motor interno.

1. **Motores SAST de código abierto.** Si están instalados, se ejecutan y sus
   hallazgos se normalizan e integran al mismo esquema (con contexto y CWE):
   - **Semgrep** (multi-lenguaje) con un **ruleset local** (`semgrep_rules.yml`)
     que corre **sin red**, alineado a los controles normativos.
   - **detect-secrets** (Yelp) para secretos por entropía/plugins.
   - **Bandit** para código Python.
   Cuando dos motores coinciden en el mismo punto, el hallazgo se marca como
   **corroborado** (mayor confianza) en vez de duplicarse. Instálalos con:
   `pip install -r requirements-advanced.txt`.
2. **Análisis de flujo de datos (taint), intra-archivo.** Rastrea datos que
   provienen de **fuentes** no confiables (entrada de usuario, intents,
   parámetros de red) hasta **sumideros** peligrosos (consultas SQL, ejecución
   de comandos, WebView, logs, rutas de archivo), con un salto de propagación
   por asignaciones. Las rutas detectadas se reportan como observaciones de
   primera clase (`TAINT-…`) y elevan la probabilidad/explotabilidad del
   hallazgo. Aproxima el razonamiento de ejecución **sin ejecutar** el código.
3. **Clasificador de verosimilitud de secretos (ML).** Una regresión logística
   autocontenida estima la probabilidad de que un literal sea un secreto real
   frente a un marcador de posición, ajustando la probabilidad del riesgo y
   reduciendo falsos positivos.

**Sobre pruebas dinámicas (DAST).** Por seguridad, la herramienta **nunca
ejecuta** el código auditado. No se realiza DAST en sentido estricto (ejecución
del sistema en marcha); el componente «dinámico» se cubre con el análisis de
flujo de datos y el razonamiento de rutas de ataque asistido por IA. Para
pruebas dinámicas completas se recomienda un proceso DAST dedicado, con la
aplicación desplegada en un entorno controlado.

El endpoint `POST /api/codescan` acepta `?ext=0` para desactivar el análisis
avanzado (por defecto está activo) y `?ai=0` para desactivar el razonamiento por IA.

> Es un **insumo** para la evaluación de QA y la auditoría de cumplimiento; no
> constituye certificación de conformidad ni asesoría legal.


## Encabezado del informe descargable

El informe exportable (PDF/DOCX/MD/TXT/CSV) incluye en el título la fecha y hora
de generación y una línea "Generado por:" con el nombre de la persona, que se
solicita al presionar cualquier botón de exportación. El resultado se redacta
como una RECOMENDACIÓN sobre el inventario de software (no "aprobado/rechazado"),
entendido como un insumo para la evaluación final de QA.


## Auditoría de proyectos Android/Gradle

Además de `package.json` (npm), la herramienta audita `build.gradle.kts`,
`build.gradle` y `settings.gradle.kts`. Detecta automáticamente el tipo de
manifiesto. Para Gradle:

- Extrae las dependencias `group:artifact:version` (DSL Kotlin o Groovy),
  resuelve versiones interpoladas por variables y, opcionalmente, por
  `libs.versions.toml` (puedes subirlo junto al archivo).
- Resuelve la última versión publicada en **Maven Central** y **Google Maven**
  (androidx / com.google.android.*).
- Consulta CVEs en **OSV** (ecosistema Maven) y aplica el mismo análisis de
  cumplimiento legal (Ley 21.459 / 19.628).
- Las dependencias Maven detectadas se **incorporan al inventario** (catálogo) y
  se actualizan en cada "actualizar catálogo".

Requiere acceso de red a `repo1.maven.org`, `dl.google.com` y `api.osv.dev`
(a través del proxy corporativo si corresponde). Sin conexión, igual reporta las
dependencias y versiones declaradas.


## Plataforma Android (SDK / AGP / Gradle)

Al auditar un proyecto Gradle, la herramienta detecta y evalúa también:
- **compileSdk / targetSdk / minSdk** contra los API levels de Android (referencia
  al 2026: API 36 = Android 16). targetSdk por debajo del mínimo de Google Play se
  marca como riesgo alto; compileSdk atrasado, medio; minSdk es informativo.
- **Android Gradle Plugin (AGP)** y **Gradle** (este último desde
  `gradle-wrapper.properties`, que puedes subir en el campo opcional), comparados
  con la última versión conocida.

Estos componentes aparecen en el reporte (sección plataforma) y se incorporan al
inventario bajo la categoría "Android / Plataforma".


## Plugins de Gradle

Se detectan los plugins declarados en `build.gradle.kts`/`settings.gradle.kts`,
tanto con versión explícita (`id("...") version "x"`) como por alias del catálogo
(`alias(libs.plugins.x)`); estos últimos se resuelven si se sube
`libs.versions.toml`. Aparecen en el reporte y en el inventario bajo
"Android / Gradle (plugins)".


## Rendimiento

- Auditoría **paralela** (ThreadPoolExecutor, configurable con WEBDEV_MAX_WORKERS, por
  defecto 8) en vez de secuencial: ~8× más rápida tras un proxy con latencia.
- **OSV en lote** (`/v1/querybatch`): una sola petición para todas las dependencias,
  más detalle solo de los CVE presentes (cacheado).
- Metadata npm **liviana** (`/{pkg}/latest`, KB) en vez del documento completo (MB).
- **Caché en memoria** (TTL) de metadata npm/Maven y detalle OSV; proxy/config
  cacheados (sin leer disco por petición); pool de conexiones ampliado + reintentos.
- Refresh del catálogo con descargas en paralelo (escritura SQLite serializada).
- Frontend: filtros con *debounce* y `<select>` de categorías reconstruido solo si cambia.

## Endurecimiento (DevSecOps)

- **Límite de tamaño de petición** (`WEBDEV_MAX_UPLOAD_BYTES`, 2 MB) → 413 ante uploads enormes.
- **Tope de dependencias por auditoría** (`WEBDEV_MAX_DEPS`, 2000) y de respuestas
  de red (`WEBDEV_MAX_JSON_BYTES`, 8 MB) → previenen agotamiento de memoria.
- **Cabeceras de seguridad**: CSP estricta, X-Frame-Options DENY, X-Content-Type-Options
  nosniff, Referrer-Policy, Permissions-Policy.
- **Manejo de errores** sin fuga de trazas (500/413 en JSON).
- **TLS** verificado contra el almacén del SO (truststore) — compatible con CA corporativa.
- **OSV en lotes acotados** (256) y regex de Gradle con tope de entrada (anti-ReDoS).
- **SECRET_KEY** por entorno; dependencias con versión acotada.
- Servir en producción tras proxy con `waitress-serve` (no el server de desarrollo).
