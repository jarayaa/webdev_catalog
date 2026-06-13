"""
Auditoría de dependencias para proyectos Android/Gradle.

Parsea `build.gradle.kts` / `build.gradle` (Groovy o Kotlin DSL) y
`settings.gradle.kts`, extrae las dependencias declaradas (group:artifact:version),
resuelve la última versión publicada consultando Maven Central y Google Maven
(androidx / com.google.android.*) y consulta CVEs en OSV (ecosistema Maven).

El ecosistema es Maven, NO npm: las coordenadas son `grupo:artefacto:version`.
Soporta:
  - implementation("com.squareup.okhttp3:okhttp:4.12.0")            (Kotlin DSL)
  - implementation 'androidx.core:core-ktx:1.13.1'                  (Groovy)
  - def/val versión en variable simple y catálogos de versiones (libs.*) básicos
  - version catalogs en settings.gradle / libs.versions.toml (parser simple)

Todas las llamadas de red usan net.* y degradan con gracia si no hay conexión
(igual que la auditoría npm): si Maven/OSV no responden, igual se reporta la
dependencia y su versión declarada.
"""

import re
import xml.etree.ElementTree as ET

import net

MAVEN_CENTRAL_META = "https://repo1.maven.org/maven2/{path}/maven-metadata.xml"
GOOGLE_MAVEN_META = "https://dl.google.com/android/maven2/{path}/maven-metadata.xml"
OSV_QUERY = "https://api.osv.dev/v1/query"

# Configuraciones que cuentan como dependencias "de aplicación" vs solo build/test.
_CONFIG_RE = (r"(?:implementation|api|compileOnly|runtimeOnly|"
              r"testImplementation|androidTestImplementation|debugImplementation|"
              r"releaseImplementation|kapt|ksp|annotationProcessor|classpath)")

# implementation("group:artifact:version")  /  implementation 'group:artifact:version'
# La versión puede ser interpolada ($var, ${var}); se resuelve luego.
_DEP_STR = re.compile(
    _CONFIG_RE + r"\s*\(?\s*[\"']([\w.\-]+):([\w.\-]+):([\w.\-${}]+)[\"']", re.I)
# implementation("group:artifact")  (sin versión: viene de un BOM/catálogo)
_DEP_NOVER = re.compile(
    _CONFIG_RE + r"\s*\(?\s*[\"']([\w.\-]+):([\w.\-]+)[\"']\s*\)?", re.I)
# Kotlin DSL nombrado: group = "x", name = "y", version = "z"
_DEP_NAMED = re.compile(
    r"group\s*[:=]\s*[\"']([\w.\-]+)[\"']\s*,\s*name\s*[:=]\s*[\"']([\w.\-]+)[\"']"
    r"(?:\s*,\s*version\s*[:=]\s*[\"']([\w.\-]+)[\"'])?", re.I)

# Variables de versión: val okhttp = "4.12.0"  /  def okhttp = '4.12.0'  / okhttpVersion = "..."
_VAR_DEF = re.compile(r"(?:val|def|var)?\s*([A-Za-z_][\w]*)\s*=\s*[\"']([\w.\-]+)[\"']")
# Interpolación: "$okhttp" / "${okhttp}" / ${libs.versions.okhttp}
_INTERP = re.compile(r"\$\{?([\w.]+)\}?")

# Referencia a librería del catálogo: implementation(libs.androidx.core.ktx),
# ksp(libs.hilt.compiler), coreLibraryDesugaring(libs.x), platform(libs.compose.bom)…
_DEP_ALIAS = re.compile(
    _CONFIG_RE + r"\s*\(\s*(?:platform\s*\(\s*)?libs\.([\w.]+)", re.I)

# [versions] de libs.versions.toml:  okhttp = "4.12.0"
_TOML_VER = re.compile(r"^\s*([\w\-]+)\s*=\s*[\"']([\w.\-]+)[\"']", re.M)


# --- Plataforma: compileSdk / targetSdk / minSdk, AGP, Gradle ---
_SDK_RE = {
    "compileSdk": re.compile(r"compileSdk(?:Version)?\s*[=\s]\s*[\"']?(\d{1,2})[\"']?", re.I),
    "targetSdk": re.compile(r"targetSdk(?:Version)?\s*[=\s]\s*[\"']?(\d{1,2})[\"']?", re.I),
    "minSdk": re.compile(r"minSdk(?:Version)?\s*[=\s]\s*[\"']?(\d{1,2})[\"']?", re.I),
}
# AGP: plugins { id("com.android.application") version "8.5.0" }  /  classpath("com.android.tools.build:gradle:8.5.0")
_AGP_RE = [
    re.compile(r"com\.android\.(?:application|library)[\"']\s*\)?\s*version\s*[\"']([\w.\-]+)[\"']", re.I),
    re.compile(r"com\.android\.tools\.build:gradle:([\w.\-]+)", re.I),
]
# Gradle desde distributionUrl de gradle-wrapper.properties
_GRADLE_RE = re.compile(r"distributionUrl=.*?gradle-([\d.]+)-(?:bin|all)\.zip", re.I)


def parse_platform(content, extra=None, versions=None):
    """Extrae versiones de plataforma del build.gradle (+ extra: toml/properties)."""
    versions = versions or {}
    blob = "\n".join(filter(None, [content or "", extra or ""]))
    out = {}
    for kind, rx in _SDK_RE.items():
        m = rx.search(blob)
        if m:
            out[kind] = m.group(1)
    # AGP
    agp = None
    for rx in _AGP_RE:
        m = rx.search(blob)
        if m:
            agp = m.group(1); break
    if not agp:
        # agp = "8.5.0" en libs.versions.toml [versions]
        for key in ("agp", "androidGradlePlugin", "android-gradle-plugin", "libs.versions.agp"):
            if key in versions:
                agp = versions[key]; break
    out["AGP"] = agp
    # Gradle (distributionUrl)
    mg = _GRADLE_RE.search(blob)
    out["Gradle"] = mg.group(1) if mg else None
    return out


def platform_entries(content, extra=None, versions=None):
    """Devuelve la lista de entradas de plataforma evaluadas."""
    import android_platform as ap
    detected = parse_platform(content, extra=extra, versions=versions)
    entries = []
    for kind in ("compileSdk", "targetSdk", "minSdk"):
        if detected.get(kind):
            entries.append(ap.assess_sdk(kind, detected[kind]))
    for kind in ("AGP", "Gradle"):
        if detected.get(kind):
            entries.append(ap.assess_tool(kind, detected[kind]))
    return entries


# Gradle plugins:  id("com.x.y") version "1.2.3"   /   alias(libs.plugins.foo)
_PLUGIN_ID_VER = re.compile(r"""id\s*\(\s*["']([\w.\-]+)["']\s*\)\s*version\s*["']([\w.\-]+)["']""", re.I)
_PLUGIN_KOTLIN = re.compile(r"""kotlin\s*\(\s*["']([\w.\-]+)["']\s*\)\s*version\s*["']([\w.\-]+)["']""", re.I)
_PLUGIN_ALIAS = re.compile(r"""alias\s*\(\s*libs\.plugins\.([\w.\-]+)\s*\)""", re.I)


def parse_plugins(content, extra=None, toml=None):
    """Detecta plugins de Gradle declarados con versión explícita o por alias del
    catálogo de versiones (resueltos si se entrega libs.versions.toml)."""
    blob = "\n".join(filter(None, [content or "", extra or ""]))
    found = {}  # plugin_id -> version|None

    for m in _PLUGIN_ID_VER.finditer(blob):
        found[m.group(1)] = m.group(2)
    for m in _PLUGIN_KOTLIN.finditer(blob):
        found["org.jetbrains.kotlin." + m.group(1)] = m.group(2)

    # alias(libs.plugins.NAME) → resolver con [plugins] y [versions] del toml.
    alias_names = [m.group(1) for m in _PLUGIN_ALIAS.finditer(blob)]
    toml_plugins, toml_versions = {}, {}
    if toml:
        section = None
        for line in toml.splitlines():
            s = line.strip()
            if s.startswith("["):
                section = s.lower(); continue
            if section == "[versions]":
                mm = re.match(r'\s*([\w\-]+)\s*=\s*["\']([\w.\-]+)["\']', line)
                if mm:
                    toml_versions[mm.group(1)] = mm.group(2)
            elif section == "[plugins]":
                mm = re.match(r'\s*([\w\-]+)\s*=\s*(.+)', line)
                if mm:
                    key, rhs = mm.group(1), mm.group(2)
                    idm = re.search(r'id\s*=\s*["\']([\w.\-]+)["\']', rhs)
                    vrefm = re.search(r'version\.ref\s*=\s*["\']([\w\-]+)["\']', rhs)
                    vlitm = re.search(r'version\s*=\s*["\']([\w.\-]+)["\']', rhs)
                    toml_plugins[key] = {
                        "id": idm.group(1) if idm else None,
                        "vref": vrefm.group(1) if vrefm else None,
                        "vlit": vlitm.group(1) if vlitm else None,
                    }
    for name in alias_names:
        # el alias en código usa puntos; en el toml suele usar guiones
        key_variants = [name, name.replace(".", "-")]
        info = None
        for k in key_variants:
            if k in toml_plugins:
                info = toml_plugins[k]; break
        if info and info.get("id"):
            ver = info.get("vlit") or (toml_versions.get(info["vref"]) if info.get("vref") else None)
            found[info["id"]] = ver
        else:
            # alias no resoluble sin el toml
            found.setdefault("libs.plugins." + name, None)
    return found


def plugin_entries(content, extra=None, toml=None):
    """Entradas de inventario/reporte para los plugins de Gradle detectados."""
    out = []
    for pid, ver in parse_plugins(content, extra=extra, toml=toml).items():
        unresolved = pid.startswith("libs.plugins.") or not ver
        note = None
        level = "ok"
        if pid.startswith("libs.plugins."):
            note = ("Plugin declarado por alias del catálogo de versiones; sube "
                    "libs.versions.toml para resolver su id y versión.")
            level = "desconocido"
        elif not ver:
            note = "Plugin declarado sin versión explícita (heredada del catálogo o del classpath)."
        out.append({
            "package": pid, "section": "plugin", "range": ver or "(sin versión)",
            "installed": ver, "pinned": bool(ver),
            "latest": None, "latest_label": None, "latest_release": None,
            "outdated": None, "gap": None,
            "vuln_status": None, "vuln_count": 0, "vuln_ids": [], "vuln_details": [],
            "note": None, "ecosystem": "Gradle Plugin",
            "npm_url": f"https://plugins.gradle.org/plugin/{pid}" if not unresolved else "https://plugins.gradle.org/",
            "homepage": None, "repository": None, "description": None,
            "eol_url": None, "eol_info": "Plugin de Gradle: sin EOL formal (regir por releases).",
            "compliance": None,
            "platform_kind": "Plugin", "platform_level": level,
            "platform_note": note or f"Plugin de Gradle declarado en versión {ver}.",
            "platform_reco": ("Resolver vía libs.versions.toml para auditar su versión."
                              if unresolved else "Mantener el plugin al día con su proveedor."),
        })
    return out


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)   # bloque
    text = re.sub(r"//[^\n]*", "", text)                 # línea
    return text


def _parse_toml_libraries(toml, versions):
    """Parsea la tabla [libraries] de libs.versions.toml.

    Devuelve {alias_normalizado: (group, artifact, version|None)} donde el alias
    se normaliza con '.' (en el código se referencia como libs.<puntos>).
    Soporta:
      foo = { group = "g", name = "a", version.ref = "x" }
      foo = { module = "g:a", version.ref = "x" }
      foo = { module = "g:a" }                      (versión heredada de un BOM)
    """
    out = {}
    section = None
    for line in (toml or "").splitlines():
        s = line.strip()
        if s.startswith("["):
            section = s.lower()
            continue
        if section != "[libraries]" or "=" not in s or s.startswith("#"):
            continue
        key, rhs = s.split("=", 1)
        key = key.strip().strip('"')
        rhs = rhs.strip()
        group = artifact = None
        mmod = re.search(r'module\s*=\s*["\']([\w.\-]+):([\w.\-]+)["\']', rhs)
        if mmod:
            group, artifact = mmod.group(1), mmod.group(2)
        else:
            mg = re.search(r'group\s*=\s*["\']([\w.\-]+)["\']', rhs)
            ma = re.search(r'name\s*=\s*["\']([\w.\-]+)["\']', rhs)
            if mg and ma:
                group, artifact = mg.group(1), ma.group(1)
        if not group:
            # forma corta:  foo = "g:a:v"
            mshort = re.match(r'["\']([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?["\']', rhs)
            if mshort:
                group, artifact = mshort.group(1), mshort.group(2)
        if not group or not artifact:
            continue
        # versión: version.ref -> [versions]; version literal; o None (BOM)
        ver = None
        vref = re.search(r'version\.ref\s*=\s*["\']([\w\-]+)["\']', rhs)
        vlit = re.search(r'version\s*=\s*["\']([\w.\-]+)["\']', rhs)
        if vref:
            ver = versions.get(vref.group(1)) or versions.get("libs.versions." + vref.group(1))
        elif vlit:
            ver = vlit.group(1)
        norm = key.replace("-", ".").replace("_", ".").lower()
        out[norm] = (group, artifact, ver)
    return out


def parse_gradle(content, toml=None, return_versions=False):
    """Extrae dependencias de un build.gradle(.kts). `toml` opcional con el
    contenido de libs.versions.toml para resolver libs.* y [versions].
    Devuelve (project_name, [deps], notas) o, si return_versions, también el dict
    de versiones detectadas."""
    notes = []
    # Defensa: acotar el tamaño del contenido procesado por las regex (mitiga
    # ReDoS y uso de memoria ante manifiestos manipulados muy grandes).
    if content and len(content) > 1_000_000:
        content = content[:1_000_000]
        notes.append("Manifiesto muy grande: se analizó solo el primer ~1 MB.")
    raw = _strip_comments(content or "")

    # Variables de versión locales (nombre -> valor).
    versions = {}
    for m in _VAR_DEF.finditer(raw):
        name, val = m.group(1), m.group(2)
        # Heurística: solo tomar como versión si parece un número/semver.
        if re.match(r"^\d[\w.\-]*$", val):
            versions[name] = val
    # Versiones desde libs.versions.toml [versions]
    if toml:
        in_versions = False
        for line in toml.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_versions = s.lower().startswith("[versions]")
                continue
            if in_versions:
                mm = _TOML_VER.match(line)
                if mm:
                    versions["libs.versions." + mm.group(1)] = mm.group(2)
                    versions[mm.group(1)] = mm.group(2)

    def resolve_ver(v):
        """Resuelve interpolaciones simples de versión a partir de variables."""
        if not v:
            return None, False
        m = _INTERP.search(v)
        if not m:
            return v, False
        key = m.group(1)
        # libs.versions.foo  → tomar último segmento o clave completa
        for cand in (key, key.split(".")[-1], "libs.versions." + key.split(".")[-1]):
            if cand in versions:
                return versions[cand], True
        return None, True  # interpolada pero no resuelta

    deps = {}

    def add(group, artifact, version, section, interp=False):
        key = f"{group}:{artifact}"
        if key in deps:
            return
        deps[key] = {"group": group, "artifact": artifact, "version": version,
                     "section": section, "coord": key, "interpolated": interp}

    def section_of(line_idx, text):
        # Marca test/build si la configuración lo indica (heurística por palabra).
        seg = text[max(0, line_idx - 120):line_idx + 60].lower()
        if "testimplementation" in seg or "androidtest" in seg:
            return "test"
        if "classpath" in seg:
            return "build"
        return "producción"

    # 1) group:artifact:version
    for m in _DEP_STR.finditer(raw):
        g, a, v = m.group(1), m.group(2), m.group(3)
        rv, interp = resolve_ver(v)
        add(g, a, rv, section_of(m.start(), raw), interp and not rv)
    # 2) named group/name/version
    for m in _DEP_NAMED.finditer(raw):
        g, a, v = m.group(1), m.group(2), m.group(3)
        rv, interp = resolve_ver(v) if v else (None, False)
        add(g, a, rv, section_of(m.start(), raw), bool(v) and interp and not rv)
    # 3) group:artifact sin versión (BOM/catálogo) — solo si no se agregó ya
    for m in _DEP_NOVER.finditer(raw):
        g, a = m.group(1), m.group(2)
        if f"{g}:{a}" not in deps:
            add(g, a, None, section_of(m.start(), raw))

    # 4) Referencias al catálogo de versiones:  implementation(libs.foo.bar)
    #    Resuelve contra la tabla [libraries] del libs.versions.toml.
    if toml:
        libtable = _parse_toml_libraries(toml, versions)   # alias_normalizado -> (g, a, ver)
        for m in _DEP_ALIAS.finditer(raw):
            alias = m.group(1)                              # p. ej. "androidx.core.ktx"
            norm = alias.replace("-", ".").replace("_", ".").lower()
            hit = libtable.get(norm)
            if hit:
                g, a, ver = hit
                add(g, a, ver, section_of(m.start(), raw), interp=bool(not ver))
            else:
                # alias referenciado pero ausente del catálogo (o catálogo incompleto)
                deps.setdefault("libs:" + alias, {
                    "group": "libs", "artifact": alias, "version": None,
                    "section": section_of(m.start(), raw), "coord": "libs." + alias,
                    "interpolated": True})
    else:
        # Hay referencias libs.* pero no se entregó el toml: avisar.
        if _DEP_ALIAS.search(raw):
            notes.append("El proyecto referencia dependencias del catálogo de versiones "
                         "(libs.*). Sube gradle/libs.versions.toml para resolver sus "
                         "coordenadas y versiones.")

    if not deps:
        notes.append("No se detectaron dependencias con coordenadas group:artifact:version. "
                     "Si el proyecto usa un catálogo de versiones (libs.versions.toml), súbelo "
                     "junto al build.gradle para resolver las versiones.")

    # Nombre del proyecto: rootProject.name en settings, o el dir implícito.
    name = None
    mn = re.search(r"rootProject\.name\s*=\s*[\"']([^\"']+)[\"']", content or "")
    if mn:
        name = mn.group(1)
    if return_versions:
        return name, list(deps.values()), notes, versions
    return name, list(deps.values()), notes


_maven_cache = {}            # (group, artifact) -> (expira_ts, (latest, origin, err))
_maven_cache_lock = __import__("threading").Lock()
_MAVEN_TTL = 600


def _maven_latest(group, artifact):
    """Última versión publicada: intenta Maven Central y luego Google Maven.
    Cacheado en memoria (la última versión publicada cambia lento)."""
    import time as _t
    key = (group, artifact)
    now = _t.time()
    with _maven_cache_lock:
        hit = _maven_cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    result = _maven_latest_fetch(group, artifact)
    # No cachear errores transitorios de red (para reintentar luego).
    if result[2] != "neterror":
        with _maven_cache_lock:
            _maven_cache[key] = (now + _MAVEN_TTL, result)
    return result


def _maven_latest_fetch(group, artifact):
    path = group.replace(".", "/") + "/" + artifact
    for tmpl, origin in ((MAVEN_CENTRAL_META, "Maven Central"),
                         (GOOGLE_MAVEN_META, "Google Maven")):
        url = tmpl.format(path=path)
        try:
            r = net.get(url, timeout=15)
        except net.NetworkError:
            return None, None, "neterror"
        if r.status_code != 200 or not r.content:
            continue
        try:
            root = ET.fromstring(r.content)
        except Exception:
            continue
        latest = (root.findtext("./versioning/latest")
                  or root.findtext("./versioning/release"))
        vers = [v.text for v in root.findall("./versioning/versions/version") if v.text]
        stable = [v for v in vers if not re.search(r"(?i)alpha|beta|rc|snapshot|-dev|eap", v)]
        if stable:
            latest = stable[-1]
        elif vers:
            latest = latest or vers[-1]
        if latest:
            return latest, origin, None
    return None, None, "not-found"


def _osv_maven(coord, version):
    """CVEs de un artefacto Maven en una versión dada (vía OSV)."""
    if not version:
        return {"status": "no-version", "count": None, "ids": [], "details": []}
    try:
        r = net.post(OSV_QUERY, json={"package": {"ecosystem": "Maven", "name": coord},
                                      "version": version}, timeout=20)
    except net.NetworkError:
        return {"status": "neterror", "count": None, "ids": [], "details": []}
    if r.status_code != 200:
        return {"status": "error", "count": None, "ids": [], "details": []}
    vulns = (r.json() or {}).get("vulns", []) or []
    details = []
    for v in vulns[:10]:
        sev = None
        for s in (v.get("severity") or []):
            if s.get("score"):
                sev = s["score"]; break
        details.append({
            "id": v.get("id"),
            "aliases": v.get("aliases") or [],
            "summary": (v.get("summary") or "")[:300],
            "severity": sev,
            "published": (v.get("published") or "")[:10],
            "references": [ref.get("url") for ref in (v.get("references") or []) if ref.get("url")][:5],
        })
    ids = [d["id"] for d in details]
    return {"status": "vulnerable" if vulns else "ok", "count": len(vulns),
            "ids": ids, "details": details}


def _gap(installed, latest):
    """major/minor/patch de atraso comparando dos versiones tipo x.y.z."""
    if not installed or not latest:
        return None
    def parts(v):
        nums = re.findall(r"\d+", v)
        return [int(n) for n in nums[:3]] + [0] * (3 - len(nums[:3]))
    pi, pl = parts(installed), parts(latest)
    if pi == pl:
        return None
    if pl[0] > pi[0]:
        return "major"
    if pl[0] == pi[0] and pl[1] > pi[1]:
        return "minor"
    if pl[:2] == pi[:2] and pl[2] > pi[2]:
        return "patch"
    return None


def audit_gradle(content, toml=None, with_cves=True, extra=None):
    """Audita un build.gradle(.kts). Devuelve la MISMA forma que la auditoría npm
    para que el resto de la app (reporte, exportadores, cumplimiento) lo reuse.
    `extra` puede contener gradle-wrapper.properties (para la versión de Gradle)."""
    import compliance
    name, parsed, notes, versions = parse_gradle(content, toml=toml, return_versions=True)
    project = {"name": name, "version": None, "ecosystem": "Maven/Gradle"}

    results = []
    # Entradas de plataforma (compileSdk/targetSdk/minSdk, AGP, Gradle) primero.
    try:
        results.extend(platform_entries(content, extra=(extra or toml), versions=versions))
    except Exception:
        pass
    # Plugins de Gradle declarados (con versión o por alias del catálogo).
    try:
        results.extend(plugin_entries(content, extra=extra, toml=toml))
    except Exception:
        pass
    # Construir entradas base.
    dep_entries = []
    for d in parsed:
        coord = d["coord"]
        entry = {
            "package": coord, "section": d["section"], "range": d["version"] or "(de catálogo/BOM)",
            "installed": d["version"], "pinned": bool(d["version"]) and not d.get("interpolated"),
            "latest": None, "latest_release": None, "outdated": None, "gap": None,
            "vuln_status": None, "vuln_count": None, "vuln_ids": [], "vuln_details": [],
            "note": None, "ecosystem": "Maven",
            "npm_url": f"https://central.sonatype.com/artifact/{d['group']}/{d['artifact']}",
            "homepage": None, "repository": None, "description": None,
            "eol_url": None,
            "eol_info": "Artefacto Maven/Android: sin EOL formal publicado (regir por releases).",
            "_group": d["group"], "_artifact": d["artifact"],
        }
        try:
            entry["compliance"] = compliance.assess(coord)
        except Exception:
            entry["compliance"] = None
        if d.get("interpolated") and not d["version"]:
            entry["note"] = "versión por catálogo/variable no resuelta (sube libs.versions.toml)"
        dep_entries.append(entry)

    # Resolver última versión en Maven Central / Google Maven EN PARALELO.
    if dep_entries:
        from concurrent.futures import ThreadPoolExecutor
        ga = list({(e["_group"], e["_artifact"]) for e in dep_entries})
        latest_by_ga = {}
        with ThreadPoolExecutor(max_workers=min(8, len(ga))) as ex:
            futs = {ex.submit(_maven_latest, g, a): (g, a) for g, a in ga}
            for fut in futs:
                g, a = futs[fut]
                try:
                    latest_by_ga[(g, a)] = fut.result()
                except Exception:
                    latest_by_ga[(g, a)] = (None, None, "neterror")
        for e in dep_entries:
            latest, origin, err = latest_by_ga.get((e["_group"], e["_artifact"]), (None, None, "neterror"))
            if err == "neterror":
                e["note"] = "neterror"
            elif latest:
                e["latest"] = latest; e["latest_origin"] = origin
                e["gap"] = _gap(e["installed"], latest); e["outdated"] = bool(e["gap"])
            elif err == "not-found":
                e["note"] = e["note"] or "no encontrado en Maven Central ni Google Maven"

    # CVEs de todos los artefactos Maven en UNA sola consulta batch a OSV.
    if with_cves:
        import osv
        targets = [e for e in dep_entries if e["installed"] and e["note"] != "neterror"]
        if targets:
            vres = osv.batch([("Maven", e["package"], e["installed"]) for e in targets])
            for e, v in zip(targets, vres):
                e["vuln_status"] = v["status"]; e["vuln_count"] = v["count"]
                e["vuln_ids"] = v["ids"]; e["vuln_details"] = v["details"]

    for e in dep_entries:
        try:
            e["compliance"] = compliance.assess(e["package"], e["package"], e["vuln_details"])
        except Exception:
            pass
        e.pop("_group", None); e.pop("_artifact", None)
        results.append(e)

    deps_only = [r for r in results if r.get("section") not in ("plataforma", "plugin")]
    plat = [r for r in results if r.get("section") == "plataforma"]
    plugins = [r for r in results if r.get("section") == "plugin"]
    summary = {
        "total": len(deps_only),
        "outdated": sum(1 for r in deps_only if r["outdated"]),
        "major_behind": sum(1 for r in deps_only if r["gap"] == "major"),
        "vulnerable": sum(1 for r in deps_only if (r["vuln_count"] or 0) > 0),
        "neterror": sum(1 for r in deps_only if r["note"] == "neterror"),
        "unresolved": sum(1 for r in deps_only if r["note"] and r["note"] != "neterror"),
        "compliance_flags": sum(1 for r in deps_only if r.get("compliance")),
        "compliance_critico": sum(1 for r in deps_only if (r.get("compliance") or {}).get("nivel") == "crítico"),
        "compliance_alto": sum(1 for r in deps_only if (r.get("compliance") or {}).get("nivel") == "alto"),
        "platform_items": len(plat),
        "platform_alerts": sum(1 for r in plat if r.get("platform_level") in ("alto", "medio")),
        "plugin_items": len(plugins),
    }
    return {"ok": True, "project": project, "summary": summary, "deps": results, "notes": notes}
