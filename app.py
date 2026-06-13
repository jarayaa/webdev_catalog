"""
WebDev Software Catalog — a standalone dashboard inventorying software products
and versions that exist on the internet and matter for building websites:
languages/runtimes, web servers, databases, backend/frontend frameworks, CMS,
etc. — with their release cycles, end-of-life dates and known CVEs.

Data sources (live, cached locally in SQLite):
  * endoflife.date — products, versions, release/EOL/support dates, LTS.
  * OSV.dev        — known CVEs per product/version (where an ecosystem maps).

This project is fully self-contained. It does not depend on any other app.
Run:  python app.py      then open http://127.0.0.1:5001
"""

import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

import net
import catalog_data as cd
import report as report_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "catalog.db")

ALL_ENDPOINT = "https://endoflife.date/api/all.json"
PRODUCT_ENDPOINT = "https://endoflife.date/api/{slug}.json"
OSV_ENDPOINT = "https://api.osv.dev/v1/query"
NPM_ENDPOINT = "https://registry.npmjs.org/{pkg}"

# Concurrencia de E/S para auditorías/refresh (I/O-bound; el GIL se libera en red).
MAX_WORKERS = int(os.environ.get("WEBDEV_MAX_WORKERS", "8"))

# --- Límites de seguridad (DevSecOps) ---
# Tope de tamaño de petición: un manifiesto enorme no debe poder agotar memoria.
MAX_UPLOAD_BYTES = int(os.environ.get("WEBDEV_MAX_UPLOAD_BYTES", str(2 * 1024 * 1024)))  # 2 MB
# Tope mayor SOLO para el comprimido de código fuente del análisis de código.
# Las defensas de extracción (anti zip-bomb/slip) son el guardrail real de memoria.
MAX_CODESCAN_BYTES = int(os.environ.get("WEBDEV_MAX_CODESCAN_BYTES", str(300 * 1024 * 1024)))  # 300 MB
# Tope de dependencias auditadas por petición: evita payloads/CPU desmesurados
# ante un manifiesto manipulado con decenas de miles de entradas.
MAX_DEPS_PER_AUDIT = int(os.environ.get("WEBDEV_MAX_DEPS", "2000"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()])
_log = logging.getLogger("webdev")

app = Flask(__name__)
app.json.ensure_ascii = False
# Clave de sesión desde entorno (higiene; no se usan sesiones con datos sensibles).
app.config["SECRET_KEY"] = os.environ.get("WEBDEV_SECRET_KEY", os.urandom(32).hex())
# Rechaza cuerpos de petición por encima del tope global (Flask responde 413).
# El global es el mayor (codescan); los endpoints de auditoría JSON/gradle aplican
# su propio cap menor (2 MB) por-request en su handler.
app.config["MAX_CONTENT_LENGTH"] = MAX_CODESCAN_BYTES

# ---- Rate limiting (Flask-Limiter; degrada si no está instalado) ------------
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _limiter = Limiter(get_remote_address, app=app,
                       default_limits=["200 per minute"],
                       storage_uri="memory://")
    def _limit(rate):
        return _limiter.limit(rate)
    _log.info("Rate limiting activo (flask-limiter)")
except ImportError:
    def _limit(_rate):
        return lambda f: f
    _limiter = None
    _log.warning("flask-limiter no instalado; sin rate limiting. Ejecuta: pip install flask-limiter")

# ---- Token de autenticación opcional ----------------------------------------
# Si se define WEBDEV_AUTH_TOKEN en el entorno, todos los endpoints /api/* lo
# requieren como cabecera «X-Auth-Token: <token>» o «Authorization: Bearer <token>».
_AUTH_TOKEN = os.environ.get("WEBDEV_AUTH_TOKEN", "").strip()

_db_lock = threading.Lock()

# Background refresh progress
_refresh = {"running": False, "done": 0, "total": 0, "error": None, "at": None}
_refresh_lock = threading.Lock()


# ============================================================ seguridad HTTP

# ---- Autenticación opcional (antes que CSRF para devolver 401 primero) ------
@app.before_request
def _check_auth():
    if not _AUTH_TOKEN:
        return
    # Rutas públicas (página principal + estáticos + endpoint de info de auth).
    if request.path in ("/", "/api/auth-info") or request.path.startswith("/static/"):
        return
    header = request.headers.get("Authorization", "")
    token = request.headers.get("X-Auth-Token") or (header[7:] if header.startswith("Bearer ") else "")
    if not token or not secrets.compare_digest(token.encode(), _AUTH_TOKEN.encode()):
        _log.warning("AUTH FAIL path=%s ip=%s", request.path, request.remote_addr)
        return jsonify({"ok": False, "error": "no autorizado"}), 401


# ---- CSRF: patrón double-submit cookie (NO HttpOnly → legible por JS) -------
@app.before_request
def _check_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if request.path.startswith("/static/"):
        return
    cookie = request.cookies.get("csrftoken", "")
    header = request.headers.get("X-CSRF-Token", "")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        _log.warning("CSRF FAIL path=%s ip=%s", request.path, request.remote_addr)
        return jsonify({"ok": False, "error": "CSRF token inválido o ausente"}), 403


@app.after_request
def _set_csrf_cookie(resp):
    """Emite el cookie CSRF en la primera visita (SameSite=Strict + no HttpOnly)."""
    if not request.cookies.get("csrftoken"):
        resp.set_cookie("csrftoken", secrets.token_hex(32),
                        samesite="Strict", httponly=False, path="/")
    return resp


@app.after_request
def _security_headers(resp):
    """Cabeceras de endurecimiento (clickjacking, sniffing, fuga de referrer).
    CSP estricta: la UI no usa scripts inline de terceros."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'")
    # HSTS: fuerza HTTPS en futuras conexiones (max-age=1 año).
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


@app.errorhandler(413)
def _too_large(_e):
    return jsonify({"ok": False,
                    "error": f"archivo demasiado grande (máx {MAX_UPLOAD_BYTES // 1024} KB)"}), 413


@app.errorhandler(500)
def _internal(_e):
    # Nunca filtrar trazas al cliente.
    return jsonify({"ok": False, "error": "error interno del servidor"}), 500


# ============================================================ DB
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA secure_delete=ON;")
    return conn


def init_db():
    with _db_lock, get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS products (
                slug         TEXT PRIMARY KEY,
                category     TEXT,
                display_name TEXT,
                updated_at   TEXT
            );
            CREATE TABLE IF NOT EXISTS cycles (
                slug         TEXT,
                cycle        TEXT,
                latest       TEXT,
                release_date TEXT,
                support      TEXT,
                eol          TEXT,
                lts          TEXT,
                status       TEXT,
                vuln_status  TEXT,
                vuln_count   INTEGER,
                vuln_ids     TEXT,
                vuln_details TEXT,
                updated_at   TEXT,
                PRIMARY KEY (slug, cycle)
            );
            CREATE TABLE IF NOT EXISTS audits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT,
                sha256      TEXT,
                app_name    TEXT,
                app_version TEXT,
                created_at  TEXT,
                summary     TEXT,
                verdict     TEXT,
                audit_json  TEXT,
                report_json TEXT,
                source      TEXT
            );
        """)
        # Migrate older DBs that predate display_name.
        cols = [r[1] for r in db.execute("PRAGMA table_info(products)")]
        if "display_name" not in cols:
            db.execute("ALTER TABLE products ADD COLUMN display_name TEXT")
        db.commit()


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def _now_str():
    """Fecha y hora local legible para encabezados de informe."""
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ============================================================ helpers
def _today():
    return datetime.now(timezone.utc).date()


def _parse_date(d):
    try:
        return datetime.strptime(str(d), "%Y-%m-%d").date()
    except Exception:
        return None


def _cycle_status(c):
    eol, support = c.get("eol"), c.get("support")
    if eol is True:
        return "eol"
    if isinstance(eol, str):
        d = _parse_date(eol)
        if d and d <= _today():
            return "eol"
        if support is False:
            return "obsolete"
        if isinstance(support, str):
            sd = _parse_date(support)
            if sd and sd <= _today():
                return "obsolete"
        return "ok"
    if eol is False:
        return "ok"
    return "unknown"


def _osv_query(ecosystem, pkg, version):
    """Consulta OSV puntual (delegada al cliente con caché/batch/reintentos)."""
    if not (ecosystem and pkg and version):
        return {"status": "no-map", "count": None, "ids": [], "details": []}
    import osv
    return osv.query_one(ecosystem, pkg, str(version))


def _osv_lookup(slug, version):
    """Query OSV for an endoflife.date product+version if we have a mapping."""
    mapping = cd.OSV_MAP.get(slug)
    if not mapping or not version:
        return {"status": "no-map", "count": None, "ids": [], "details": []}
    ecosystem, pkg = mapping
    return _osv_query(ecosystem, pkg, version)


def _semver_tuple(v):
    """Parse 'x.y.z' (ignoring pre-release/build) into a comparable tuple."""
    core = str(v).split("-")[0].split("+")[0]
    parts = core.split(".")
    out = []
    for p in parts[:3]:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    while len(out) < 3:
        out.append(0)
    return tuple(out)


def _fetch_npm_cycles(pkg, with_cves=True, max_majors=8):
    """Fetch a library from the npm registry and build major-version 'cycles'
    analogous to endoflife.date: one row per major, with the newest stable
    version in that major, its release date, and CVEs from OSV. Libraries have
    no formal EOL, so eol/support stay empty; the newest major is 'ok' and
    older majors are 'obsolete' (superseded)."""
    from urllib.parse import quote
    url = NPM_ENDPOINT.format(pkg=quote(pkg, safe=""))  # encodes @ and / in scopes
    try:
        r = net.get(url, timeout=20, headers={"Accept": "application/json"})
    except net.NetworkError:
        return None, "neterror"
    if r.status_code == 404:
        return [], None
    if r.status_code != 200:
        return None, "neterror"
    try:
        doc = r.json()
    except Exception:
        return None, "neterror"

    versions = list((doc.get("versions") or {}).keys())
    times = doc.get("time") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    if not versions:
        return [], None

    # Best stable version per major (skip pre-releases).
    best = {}   # major -> version string
    for v in versions:
        if any(tag in v for tag in ("-", "alpha", "beta", "rc", "next", "canary")):
            continue
        major = _semver_tuple(v)[0]
        if major not in best or _semver_tuple(v) > _semver_tuple(best[major]):
            best[major] = v
    if not best:
        # all versions are pre-release; fall back to the latest tag
        if latest:
            best[_semver_tuple(latest)[0]] = latest

    latest_major = _semver_tuple(latest)[0] if latest else max(best)
    majors = sorted(best.keys(), reverse=True)[:max_majors]

    cycles = []
    for m in majors:
        ver = best[m]
        rel = times.get(ver)
        status = "ok" if m == latest_major else "obsolete"
        vuln = {"status": None, "count": None, "ids": [], "details": []}
        if with_cves:
            vuln = _osv_query("npm", pkg, ver)
        cycles.append({
            "cycle": str(m), "latest": ver,
            "release_date": (rel or "").split("T")[0] if rel else None,
            "support": None, "eol": None, "lts": None,
            "status": status, "vuln": vuln,
        })
    return cycles, None


# ============================================================ package.json audit
def _clean_range(spec):
    """Strip an npm semver range to a comparable base version.
    '^19.2.21' -> '19.2.21', '~7.8.0' -> '7.8.0', '>=1.2.0' -> '1.2.0'.
    Returns (base_version_or_None, is_pinned)."""
    s = str(spec or "").strip()
    if not s or s in ("*", "latest", "x"):
        return None, False
    # npm aliases / urls / git / file specs — can't resolve a plain version.
    if any(s.startswith(p) for p in ("npm:", "git", "github:", "file:", "http", "link:", "workspace:")):
        return None, False
    pinned = s[0].isdigit()  # exact version like "5.0.2" (no ^ or ~)
    import re
    m = re.search(r"(\d+\.\d+\.\d+|\d+\.\d+|\d+)", s)
    return (m.group(1) if m else None), pinned


def _fetch_npm_meta(pkg):
    """Metadata npm LIVIANA: usa el endpoint `/{pkg}/latest` (unos KB) en vez de
    descargar el documento completo del registro (que puede pesar varios MB para
    paquetes con mucho historial, p. ej. @angular/*). Cacheado por URL."""
    from urllib.parse import quote
    url = NPM_ENDPOINT.format(pkg=quote(pkg, safe="")).rstrip("/") + "/latest"
    doc, err = net.get_json_cached(url, timeout=15)
    if err == "neterror":
        return None, "neterror"
    if err == "not-found":
        return {"exists": False}, None
    if err or not isinstance(doc, dict):
        return None, "neterror"
    latest = doc.get("version")
    repo = doc.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    if isinstance(repo, str):
        repo = repo.replace("git+", "").replace("git://", "https://").replace(".git", "")
    return {
        "exists": True, "latest": latest,
        # El endpoint /latest no incluye fecha por versión; se omite (no vale un
        # documento de varios MB solo por la fecha de release).
        "latest_release": None,
        "homepage": doc.get("homepage"), "repository": repo,
        "description": (doc.get("description") or "")[:200],
    }, None


def audit_package_json(content, with_cves=True):
    """Parse a package.json and report, per dependency: the requested range, the
    resolved installed version, the latest available on npm, whether it's
    outdated (patch/minor/major behind), and known CVEs for the installed
    version. Built for QA review of a delivered build."""
    try:
        data = json.loads(content)
    except Exception as e:
        return {"ok": False, "error": f"package.json inválido: {e}"}

    project = {"name": data.get("name"), "version": data.get("version")}
    sections = [("dependencies", "producción"), ("devDependencies", "desarrollo"),
                ("peerDependencies", "peer"), ("optionalDependencies", "opcional")]
    import compliance

    # 1) Construir entradas base (sin red) preservando el orden.
    entries = []
    for key, label in sections:
        for pkg, spec in (data.get(key) or {}).items():
            base, pinned = _clean_range(spec)
            entries.append({
                "package": pkg, "section": label, "range": str(spec),
                "installed": base, "pinned": pinned,
                "latest": None, "latest_release": None, "outdated": None, "gap": None,
                "vuln_status": None, "vuln_count": None, "vuln_ids": [], "vuln_details": [],
                "note": None,
                "npm_url": f"https://www.npmjs.com/package/{pkg}",
                "homepage": None, "repository": None, "description": None,
                "eol_url": (f"https://endoflife.date/{cd.NPM_EOL_MAP[pkg]}" if pkg in cd.NPM_EOL_MAP else None),
                "eol_info": ("Ver ciclo de vida en endoflife.date" if pkg in cd.NPM_EOL_MAP
                             else "Librería JS: sin EOL formal publicado (regir por releases del proyecto)."),
                "compliance": compliance.assess(pkg),
            })

    # 2) Resolver metadata npm EN PARALELO (I/O-bound). Deduplica por paquete.
    # Tope defensivo: un manifiesto manipulado no debe disparar miles de llamadas.
    truncated = False
    if len(entries) > MAX_DEPS_PER_AUDIT:
        entries = entries[:MAX_DEPS_PER_AUDIT]
        truncated = True
    uniq_pkgs = list({e["package"] for e in entries})
    meta_by_pkg = {}
    if uniq_pkgs:
        from concurrent.futures import ThreadPoolExecutor
        workers = min(MAX_WORKERS, len(uniq_pkgs))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for pkg, res in zip(uniq_pkgs, ex.map(_fetch_npm_meta, uniq_pkgs)):
                meta_by_pkg[pkg] = res

    # 3) Aplicar metadata + calcular atraso.
    for e in entries:
        meta, err = meta_by_pkg.get(e["package"], (None, "neterror"))
        if err == "neterror":
            e["note"] = "neterror"; continue
        if not meta or not meta.get("exists"):
            e["note"] = (e["installed"] is None and "spec no resoluble (git/url/alias)"
                         or "no encontrado en npm")
            continue
        e["latest"] = meta["latest"]; e["latest_release"] = meta["latest_release"]
        e["homepage"] = meta.get("homepage"); e["repository"] = meta.get("repository")
        e["description"] = meta.get("description")
        if e["installed"] and meta["latest"]:
            it, lt = _semver_tuple(e["installed"]), _semver_tuple(meta["latest"])
            if it >= lt:
                e["outdated"], e["gap"] = False, "al día"
            else:
                e["outdated"] = True
                e["gap"] = "major" if it[0] != lt[0] else "minor" if it[1] != lt[1] else "patch"

    # 4) CVEs de TODAS las dependencias en UNA sola consulta batch a OSV.
    if with_cves:
        import osv
        targets = [e for e in entries if e["installed"] and e["note"] != "neterror"]
        vres = osv.batch([("npm", e["package"], e["installed"]) for e in targets])
        for e, v in zip(targets, vres):
            e["vuln_status"] = v.get("status"); e["vuln_count"] = v.get("count")
            e["vuln_ids"] = v.get("ids") or []; e["vuln_details"] = v.get("details") or []

    # 5) Enriquecer cumplimiento con descripción + advisories.
    for e in entries:
        try:
            e["compliance"] = compliance.assess(e["package"], e.get("description"), e.get("vuln_details"))
        except Exception:
            pass

    results = entries

    # Summary counts for the QA verdict.
    summary = {
        "total": len(results),
        "outdated": sum(1 for r in results if r["outdated"]),
        "major_behind": sum(1 for r in results if r["gap"] == "major"),
        "vulnerable": sum(1 for r in results if (r["vuln_count"] or 0) > 0),
        "neterror": sum(1 for r in results if r["note"] == "neterror"),
        "unresolved": sum(1 for r in results if r["note"] and r["note"] != "neterror"),
        "compliance_flags": sum(1 for r in results if r.get("compliance")),
        "compliance_critico": sum(1 for r in results if (r.get("compliance") or {}).get("nivel") == "crítico"),
        "compliance_alto": sum(1 for r in results if (r.get("compliance") or {}).get("nivel") == "alto"),
        "truncated": truncated,
    }
    return {"ok": True, "project": project, "summary": summary, "deps": results}


def detect_manifest(content, filename=None):
    """Decide si el contenido es un package.json (npm) o un build/settings.gradle
    (Maven/Gradle). Devuelve 'npm' | 'gradle'."""
    fn = (filename or "").lower()
    if fn.endswith((".gradle", ".kts")) or fn.endswith(".gradle.kts"):
        return "gradle"
    if fn.endswith(".json"):
        return "npm"
    c = (content or "").lstrip()
    # package.json: empieza con { y suele tener "dependencies"
    if c.startswith("{") and ('"dependencies"' in c or '"devDependencies"' in c
                              or '"name"' in c and '"version"' in c):
        return "npm"
    # Gradle: bloque dependencies { ... } con implementation/api o plugins{}
    if re.search(r"\b(implementation|api|testImplementation|androidTestImplementation|classpath)\b",
                 content or "") or "plugins {" in (content or "") or "rootProject.name" in (content or ""):
        return "gradle"
    # por defecto, intentar npm (json)
    return "npm"


def audit_manifest(content, with_cves=True, filename=None, toml=None, extra=None):
    """Auditoría unificada: detecta el tipo de manifiesto y delega.
    Mantiene la misma forma de salida para reporte/exportadores/cumplimiento."""
    kind = detect_manifest(content, filename)
    if kind == "gradle":
        import gradle_audit
        res = gradle_audit.audit_gradle(content, toml=toml, with_cves=with_cves, extra=extra)
        res["manifest_type"] = "gradle"
        # Integrar dependencias Maven, plataforma y plugins al inventario.
        try:
            deps = res.get("deps") or []
            inventory_upsert_maven([d for d in deps if d.get("section") not in ("plataforma", "plugin")])
            inventory_upsert_platform([d for d in deps if d.get("section") == "plataforma"])
            inventory_upsert_plugins([d for d in deps if d.get("section") == "plugin"])
        except Exception:
            pass
        return res
    res = audit_package_json(content, with_cves=with_cves)
    res["manifest_type"] = "npm"
    return res


MAVEN_CATEGORY = "Android / Gradle (Maven)"
NPM_CATEGORY = "Node / npm (paquete)"
PLATFORM_CATEGORY = "Android / Plataforma"
PLUGIN_CATEGORY = "Android / Gradle (plugins)"


def inventory_upsert_plugins(items):
    """Inserta/actualiza en el inventario los plugins de Gradle detectados."""
    now = utcnow()
    with _db_lock, get_db() as db:
        for d in items:
            pid = d.get("package")
            if not pid:
                continue
            slug = "gradle-plugin:" + pid
            db.execute(
                "INSERT INTO products (slug, category, display_name, updated_at) "
                "VALUES (?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
                "category=excluded.category, display_name=excluded.display_name, "
                "updated_at=excluded.updated_at",
                (slug, PLUGIN_CATEGORY, pid, now))
            db.execute(
                "INSERT INTO cycles (slug, cycle, latest, release_date, support, eol, "
                "lts, status, vuln_status, vuln_count, vuln_ids, vuln_details, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(slug, cycle) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
                (slug, str(d.get("installed") or "—"), None, None, None, None, None,
                 (d.get("platform_level") or "ok"), None, 0, "[]", "[]", now))
        db.commit()


def inventory_upsert_platform(items):
    """Inserta/actualiza en el inventario los componentes de plataforma Android
    (compileSdk/targetSdk/minSdk, AGP, Gradle) detectados en una auditoría."""
    now = utcnow()
    with _db_lock, get_db() as db:
        for d in items:
            slug = "android:" + (d.get("platform_kind") or d.get("package") or "item")
            db.execute(
                "INSERT INTO products (slug, category, display_name, updated_at) "
                "VALUES (?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
                "category=excluded.category, display_name=excluded.display_name, "
                "updated_at=excluded.updated_at",
                (slug, PLATFORM_CATEGORY, d.get("package"), now))
            db.execute(
                "INSERT INTO cycles (slug, cycle, latest, release_date, support, eol, "
                "lts, status, vuln_status, vuln_count, vuln_ids, vuln_details, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(slug, cycle) DO UPDATE SET latest=excluded.latest, "
                "status=excluded.status, updated_at=excluded.updated_at",
                (slug, str(d.get("installed")), d.get("latest"), None, None, None, None,
                 (d.get("platform_level") or "ok"), None, 0, "[]", "[]", now))
        db.commit()


def inventory_upsert_maven(deps):
    """Inserta/actualiza en el inventario (products+cycles) las dependencias
    Maven descubiertas en una auditoría Gradle, para que formen parte del
    catálogo que se monitorea y actualiza en el tiempo."""
    now = utcnow()
    with _db_lock, get_db() as db:
        for d in deps:
            coord = d.get("package")
            if not coord or ":" not in coord:
                continue
            artifact = coord.split(":", 1)[1]
            db.execute(
                "INSERT INTO products (slug, category, display_name, updated_at) "
                "VALUES (?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
                "category=excluded.category, display_name=excluded.display_name, "
                "updated_at=excluded.updated_at",
                (coord, MAVEN_CATEGORY, artifact, now))
            # La "cycle" para Maven es la versión instalada detectada.
            cycle = d.get("installed") or "—"
            db.execute(
                "INSERT INTO cycles (slug, cycle, latest, release_date, support, eol, "
                "lts, status, vuln_status, vuln_count, vuln_ids, vuln_details, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(slug, cycle) DO UPDATE SET latest=excluded.latest, "
                "status=excluded.status, vuln_status=excluded.vuln_status, "
                "vuln_count=excluded.vuln_count, vuln_ids=excluded.vuln_ids, "
                "vuln_details=excluded.vuln_details, updated_at=excluded.updated_at",
                (coord, cycle, d.get("latest"), None, None, None, None,
                 ("desactualizada" if d.get("gap") else "vigente"),
                 d.get("vuln_status"), d.get("vuln_count"),
                 json.dumps(d.get("vuln_ids") or [], ensure_ascii=False),
                 json.dumps(d.get("vuln_details") or [], ensure_ascii=False, default=str),
                 now))
        db.commit()


def inventory_upsert_npm(deps):
    """Inserta/actualiza en el inventario los paquetes npm descubiertos en el
    código analizado, para que formen parte del catálogo monitoreado."""
    now = utcnow()
    with _db_lock, get_db() as db:
        for d in deps:
            pkg = d.get("package")
            if not pkg:
                continue
            db.execute(
                "INSERT INTO products (slug, category, display_name, updated_at) "
                "VALUES (?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
                "category=excluded.category, display_name=excluded.display_name, "
                "updated_at=excluded.updated_at",
                (pkg, NPM_CATEGORY, pkg, now))
            cycle = d.get("installed") or "—"
            db.execute(
                "INSERT INTO cycles (slug, cycle, latest, release_date, support, eol, "
                "lts, status, vuln_status, vuln_count, vuln_ids, vuln_details, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(slug, cycle) DO UPDATE SET latest=excluded.latest, "
                "status=excluded.status, vuln_status=excluded.vuln_status, "
                "vuln_count=excluded.vuln_count, vuln_ids=excluded.vuln_ids, "
                "vuln_details=excluded.vuln_details, updated_at=excluded.updated_at",
                (pkg, cycle, d.get("latest"), None, None, None, None,
                 ("desactualizada" if d.get("gap") else "vigente"),
                 d.get("vuln_status"), d.get("vuln_count"),
                 json.dumps(d.get("vuln_ids") or [], ensure_ascii=False),
                 json.dumps(d.get("vuln_details") or [], ensure_ascii=False, default=str),
                 now))
        db.commit()


def refresh_maven_inventory():
    """Re-resuelve la última versión y CVE de los artefactos Maven ya presentes
    en el inventario (los que tienen categoría MAVEN_CATEGORY)."""
    import gradle_audit
    with _db_lock, get_db() as db:
        slugs = [r[0] for r in db.execute(
            "SELECT slug FROM products WHERE category = ?", (MAVEN_CATEGORY,)).fetchall()]
    updated = 0
    for coord in slugs:
        try:
            group, artifact = coord.split(":", 1)
        except ValueError:
            continue
        latest, origin, err = gradle_audit._maven_latest(group, artifact)
        if not latest:
            continue
        with _db_lock, get_db() as db:
            db.execute("UPDATE cycles SET latest = ?, updated_at = ? WHERE slug = ?",
                       (latest, utcnow(), coord))
            db.commit()
        updated += 1
    return updated


# ============================================================ refresh worker
def _fetch_all_slugs():
    r = net.get(ALL_ENDPOINT, timeout=20, headers={"Accept": "application/json"})
    if r.status_code != 200:
        raise net.NetworkError(f"endoflife.date HTTP {r.status_code}")
    data = r.json()
    if not isinstance(data, list):
        raise net.NetworkError("formato inesperado de endoflife.date")
    return data


def _refresh_worker(with_cves=True):
    global _refresh
    # endoflife.date is one source; npm is the other. A failure fetching the
    # endoflife product list must NOT prevent the npm libraries from loading
    # (and vice versa) — they're independent.
    try:
        all_slugs = set(_fetch_all_slugs())
        eol_error = None
    except Exception as e:
        all_slugs = set()
        eol_error = str(e)
    slugs = [s for s in cd.WEBDEV_CATEGORIES if s in all_slugs]
    npm_pkgs = list(cd.NPM_LIBRARIES.keys())
    with _refresh_lock:
        _refresh.update(running=True, done=0, total=len(slugs) + len(npm_pkgs), error=None)

    # ---- endoflife.date products (red en paralelo, escritura serializada) ----
    def _fetch_eol(slug):
        try:
            r = net.get(PRODUCT_ENDPOINT.format(slug=slug), timeout=15,
                        headers={"Accept": "application/json"})
            cycles = r.json() if r.status_code == 200 else []
        except Exception:
            cycles = []
        rows = []
        for c in (cycles or []):
            if not isinstance(c, dict):
                continue
            status = _cycle_status(c)
            ver = c.get("latest") or c.get("cycle")
            vuln = _osv_lookup(slug, ver) if with_cves else {"status": None, "count": None, "ids": [], "details": []}
            rows.append((
                slug, str(c.get("cycle")), c.get("latest"), c.get("releaseDate"),
                _norm(c.get("support")), _norm(c.get("eol")), _norm(c.get("lts")),
                status, vuln.get("status"), vuln.get("count"),
                json.dumps(vuln.get("ids") or []),
                json.dumps(vuln.get("details") or [], default=str), utcnow(),
            ))
        return slug, rows

    def _fetch_npm(pkg):
        name, category = cd.NPM_LIBRARIES[pkg]
        cycles, err = _fetch_npm_cycles(pkg, with_cves=with_cves)
        rows = []
        for c in (cycles or []):
            vuln = c.get("vuln") or {}
            rows.append((
                pkg, c["cycle"], c["latest"], c["release_date"],
                _norm(c["support"]), _norm(c["eol"]), _norm(c["lts"]),
                c["status"], vuln.get("status"), vuln.get("count"),
                json.dumps(vuln.get("ids") or []),
                json.dumps(vuln.get("details") or [], default=str), utcnow(),
            ))
        return pkg, name, category, rows

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for slug, rows in ex.map(_fetch_eol, slugs):
            with _db_lock, get_db() as db:
                db.execute("INSERT OR REPLACE INTO products (slug, category, updated_at) VALUES (?,?,?)",
                           (slug, cd.WEBDEV_CATEGORIES.get(slug, "otros"), utcnow()))
                db.execute("DELETE FROM cycles WHERE slug = ?", (slug,))
                if rows:
                    db.executemany(
                        "INSERT OR REPLACE INTO cycles (slug, cycle, latest, release_date, "
                        "support, eol, lts, status, vuln_status, vuln_count, vuln_ids, "
                        "vuln_details, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                db.commit()
            with _refresh_lock:
                _refresh["done"] += 1

        for pkg, name, category, rows in ex.map(_fetch_npm, npm_pkgs):
            with _db_lock, get_db() as db:
                db.execute("INSERT OR REPLACE INTO products (slug, category, updated_at, display_name) VALUES (?,?,?,?)",
                           (pkg, category, utcnow(), name))
                db.execute("DELETE FROM cycles WHERE slug = ?", (pkg,))
                if rows:
                    db.executemany(
                        "INSERT OR REPLACE INTO cycles (slug, cycle, latest, release_date, "
                        "support, eol, lts, status, vuln_status, vuln_count, vuln_ids, "
                        "vuln_details, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                db.commit()
            with _refresh_lock:
                _refresh["done"] += 1

    # Actualizar también los artefactos Maven/Gradle ya presentes en el inventario.
    try:
        refresh_maven_inventory()
    except Exception:
        pass

    with _refresh_lock:
        # If endoflife failed but npm worked, surface a soft note (the catalog
        # still has the npm libraries).
        _refresh.update(running=False, at=utcnow(),
                        error=(f"endoflife.date no disponible ({eol_error}); "
                               "se cargaron solo las librerías npm" if eol_error else None))


def _norm(v):
    """Store endoflife bool/date fields as text: True/False kept as flags."""
    if v is True:
        return "__true__"
    if v is False:
        return "__false__"
    return v if v else None


def _denorm(v):
    if v == "__true__":
        return True
    if v == "__false__":
        return False
    return v


# ============================================================ routes
@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/catalog")
def api_catalog():
    """Flattened product×cycle rows from the local cache, for the inventory table."""
    with _db_lock, get_db() as db:
        rows = db.execute(
            "SELECT c.*, p.category, p.display_name FROM cycles c "
            "JOIN products p ON p.slug = c.slug "
            "ORDER BY p.category, c.slug, c.cycle DESC").fetchall()
    out = []
    for r in rows:
        try:
            ids = json.loads(r["vuln_ids"]) if r["vuln_ids"] else []
        except Exception:
            ids = []
        try:
            details = json.loads(r["vuln_details"]) if r["vuln_details"] else []
        except Exception:
            details = []
        out.append({
            "slug": r["slug"], "name": r["display_name"] or r["slug"],
            "category": r["category"], "cycle": r["cycle"],
            "latest": r["latest"], "release_date": r["release_date"],
            "support": _denorm(r["support"]), "eol": _denorm(r["eol"]),
            "lts": _denorm(r["lts"]), "status": r["status"],
            "vuln_status": r["vuln_status"], "vuln_count": r["vuln_count"],
            "vuln_ids": ids, "vuln_details": details, "updated_at": r["updated_at"],
        })
    return jsonify(out)


@app.get("/api/auth-info")
def api_auth_info():
    """Endpoint público: informa al frontend si la instancia requiere autenticación."""
    return jsonify({"auth_required": bool(_AUTH_TOKEN)})


@app.get("/api/status")
def api_status():
    with _db_lock, get_db() as db:
        np = db.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        nc = db.execute("SELECT COUNT(*) FROM cycles").fetchone()[0]
        last = db.execute("SELECT MAX(updated_at) FROM products").fetchone()[0]
    with _refresh_lock:
        rf = dict(_refresh)
    return jsonify({"products": np, "cycles": nc, "last_update": last,
                    "refresh": rf, "categories": cd.CATEGORY_ORDER})


@app.post("/api/refresh")
@_limit("3 per minute")
def api_refresh():
    with _refresh_lock:
        if _refresh["running"]:
            return jsonify({"ok": True, "started": False, "msg": "ya en curso"})
    with_cves = request.args.get("cves", "1") != "0"
    threading.Thread(target=_refresh_worker, kwargs={"with_cves": with_cves},
                     daemon=True).start()
    return jsonify({"ok": True, "started": True})


@app.post("/api/audit")
@_limit("30 per minute")
def api_audit():
    """Audita un manifiesto (package.json npm o build.gradle(.kts) Android/Maven)
    contra el registro correspondiente + OSV (insumo para la revisión QA)."""
    # Cap por-request: un manifiesto de texto no debe superar 2 MB (anti-DoS).
    request.max_content_length = MAX_UPLOAD_BYTES
    content = None
    filename = None
    toml = None
    extra = None
    if request.files.get("file"):
        try:
            content = request.files["file"].read().decode("utf-8", "replace")
            filename = request.files["file"].filename
        except Exception:
            content = None
        if request.files.get("toml"):
            try:
                toml = request.files["toml"].read().decode("utf-8", "replace")
            except Exception:
                toml = None
        if request.files.get("extra"):
            try:
                extra = request.files["extra"].read().decode("utf-8", "replace")
            except Exception:
                extra = None
    if content is None:
        data = request.get_json(silent=True) or {}
        content = data.get("content")
        filename = data.get("filename") or filename
        toml = data.get("toml") or toml
        extra = data.get("extra") or extra
    if not content:
        return jsonify({"ok": False, "error": "no se recibió un manifiesto"}), 400
    with_cves = request.args.get("cves", "1") != "0"
    return jsonify(audit_manifest(content, with_cves=with_cves, filename=filename, toml=toml, extra=extra))


@app.post("/api/report")
@_limit("10 per minute")
def api_report():
    """Audita un package.json y arma el reporte de riesgo estructurado
    (Análisis General / Técnico / Conclusión). Usa IA (Claude) si hay API key.
    Además guarda la auditoría en el historial (tabla audits)."""
    request.max_content_length = MAX_UPLOAD_BYTES
    content = None
    filename = None
    if request.files.get("file"):
        try:
            content = request.files["file"].read().decode("utf-8", "replace")
            filename = request.files["file"].filename
        except Exception:
            content = None
    if content is None:
        data = request.get_json(silent=True) or {}
        content = data.get("content")
        filename = data.get("filename") or filename
    toml = None
    extra = None
    if request.files.get("toml"):
        try:
            toml = request.files["toml"].read().decode("utf-8", "replace")
        except Exception:
            toml = None
    if request.files.get("extra"):
        try:
            extra = request.files["extra"].read().decode("utf-8", "replace")
        except Exception:
            extra = None
    if toml is None and not request.files:
        _j = request.get_json(silent=True) or {}
        toml = _j.get("toml")
        extra = _j.get("extra")
    author = (request.form.get("author") if request.files.get("file")
              else (request.get_json(silent=True) or {}).get("author")) or None
    if not content:
        return jsonify({"ok": False, "error": "no se recibió un manifiesto"}), 400

    audit = audit_manifest(content, with_cves=True, filename=filename, toml=toml, extra=extra)
    if not audit.get("ok"):
        return jsonify(audit), 400

    cfg = net.load_config()
    use_ai = request.args.get("ai", "1") != "0"
    api_key = cfg.get("anthropic_api_key") or None
    model = cfg.get("ai_model") or report_mod.DEFAULT_MODEL
    rep = report_mod.build_report(audit, ai=use_ai, api_key=api_key, model=model, author=author)
    rep["ok"] = True
    rep["markdown"] = report_mod.report_to_markdown(rep)

    # Guardar en el historial (no debe romper la respuesta si falla).
    save = request.args.get("save", "1") != "0"
    if save:
        try:
            rep["audit_id"] = _save_audit(content, filename, audit, rep)
            _log.info("REPORT SAVED audit_id=%s file=%r ip=%s", rep["audit_id"], filename, request.remote_addr)
        except Exception:
            rep["audit_id"] = None
    return jsonify(rep)


def _save_audit(content, filename, audit, rep):
    """Persiste una auditoría en el historial y devuelve su id."""
    import hashlib
    sha = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
    proj = audit.get("project") or {}
    ov = rep.get("overall") or {}
    with _db_lock, get_db() as db:
        cur = db.execute(
            "INSERT INTO audits (filename, sha256, app_name, app_version, created_at, "
            "summary, verdict, audit_json, report_json, source) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (filename or "package.json", sha, proj.get("name"), proj.get("version"),
             utcnow(), json.dumps(audit.get("summary") or {}, default=str),
             ov.get("verdict"), json.dumps(audit, default=str),
             json.dumps(rep, default=str), content))
        db.commit()
        return cur.lastrowid


@app.get("/api/audits")
def api_audits_list():
    """Lista el historial de auditorías (sin los blobs grandes)."""
    with _db_lock, get_db() as db:
        rows = db.execute(
            "SELECT id, filename, sha256, app_name, app_version, created_at, "
            "summary, verdict FROM audits ORDER BY id DESC").fetchall()
    out = []
    for r in rows:
        try:
            summ = json.loads(r["summary"]) if r["summary"] else {}
        except Exception:
            summ = {}
        out.append({"id": r["id"], "filename": r["filename"], "sha256": r["sha256"],
                    "app_name": r["app_name"], "app_version": r["app_version"],
                    "created_at": r["created_at"], "verdict": r["verdict"],
                    "summary": summ})
    return jsonify(out)


@app.get("/api/audits/<int:aid>")
def api_audit_get(aid):
    """Devuelve el reporte completo de una auditoría guardada (para el modal)."""
    with _db_lock, get_db() as db:
        r = db.execute("SELECT report_json, audit_json FROM audits WHERE id = ?",
                       (aid,)).fetchone()
    if not r:
        return jsonify({"ok": False, "error": "auditoría no encontrada"}), 404
    try:
        rep = json.loads(r["report_json"]) if r["report_json"] else {}
    except Exception:
        rep = {}
    rep["ok"] = True
    return jsonify(rep)


@app.get("/api/audits/<int:aid>/export")
def api_audit_export_saved(aid):
    """Exporta una auditoría guardada en el formato pedido (pdf/docx/md/txt/csv)."""
    import exporters
    from flask import Response
    fmt = (request.args.get("format") or "pdf").lower()
    if fmt not in exporters.EXPORTERS:
        return jsonify({"ok": False, "error": f"formato no soportado: {fmt}"}), 400
    with _db_lock, get_db() as db:
        r = db.execute("SELECT report_json, app_name FROM audits WHERE id = ?",
                       (aid,)).fetchone()
    if not r:
        return jsonify({"ok": False, "error": "auditoría no encontrada"}), 404
    try:
        rep = json.loads(r["report_json"])
    except Exception:
        return jsonify({"ok": False, "error": "reporte no recuperable"}), 500
    try:
        blob, mime = exporters.export(rep, fmt)
    except Exception as e:
        return jsonify({"ok": False, "error": f"error al generar {fmt}: {e}"}), 500
    name = "".join(ch if ch.isalnum() else "_" for ch in (r["app_name"] or "proyecto"))[:40] or "proyecto"
    return Response(blob, mimetype=mime,
                    headers={"Content-Disposition": f"attachment; filename=reporte_{name}.{fmt}"})


@app.delete("/api/audits/<int:aid>")
def api_audit_delete(aid):
    with _db_lock, get_db() as db:
        db.execute("DELETE FROM audits WHERE id = ?", (aid,))
        db.commit()
    _log.info("AUDIT DELETE id=%s ip=%s", aid, request.remote_addr)
    return jsonify({"ok": True})


@app.post("/api/report/export")
def api_report_export():
    """Genera el reporte y lo devuelve como archivo descargable en el formato
    pedido: txt, md, docx o pdf (con estilos, tablas, colores y enlaces)."""
    import exporters
    from flask import Response
    data = request.get_json(silent=True) or {}
    content = data.get("content")
    author = data.get("author") or None
    filename = data.get("filename") or None
    toml = data.get("toml") or None
    extra = data.get("extra") or None
    fmt = (request.args.get("format") or data.get("format") or "md").lower()
    if not content:
        return jsonify({"ok": False, "error": "no se recibió un manifiesto"}), 400
    if fmt not in exporters.EXPORTERS:
        return jsonify({"ok": False, "error": f"formato no soportado: {fmt}"}), 400

    audit = audit_manifest(content, with_cves=True, filename=filename, toml=toml, extra=extra)
    if not audit.get("ok"):
        return jsonify(audit), 400
    cfg = net.load_config()
    use_ai = request.args.get("ai", "1") != "0"
    rep = report_mod.build_report(audit, ai=use_ai,
                                  api_key=cfg.get("anthropic_api_key") or None,
                                  model=cfg.get("ai_model") or report_mod.DEFAULT_MODEL,
                                  author=author)
    try:
        blob, mime = exporters.export(rep, fmt)
    except Exception as e:
        return jsonify({"ok": False, "error": f"error al generar {fmt}: {e}"}), 500
    name = (rep["project"].get("name") or "proyecto")
    name = "".join(ch if ch.isalnum() else "_" for ch in name)[:40] or "proyecto"
    filename = f"reporte_{name}.{fmt}"
    return Response(blob, mimetype=mime,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/ai-config")
def api_get_ai_config():
    cfg = net.load_config()
    return jsonify({"configured": bool(cfg.get("anthropic_api_key")),
                    "model": cfg.get("ai_model") or report_mod.DEFAULT_MODEL,
                    "author": cfg.get("report_author") or ""})


@app.post("/api/author")
def api_set_author():
    """Persiste el nombre por defecto de quien genera los informes."""
    data = request.get_json(silent=True) or {}
    net.save_config({"report_author": (data.get("author") or "").strip()})
    return jsonify({"ok": True})


@app.post("/api/ai-config")
def api_set_ai_config():
    data = request.get_json(silent=True) or {}
    updates = {}
    # Solo sobrescribir la key si llega un valor no vacío (vacío = mantener).
    if data.get("api_key"):
        updates["anthropic_api_key"] = data["api_key"].strip()
    if data.get("model"):
        updates["ai_model"] = data["model"].strip()
    net.save_config(updates)
    cfg = net.load_config()
    return jsonify({"ok": True, "configured": bool(cfg.get("anthropic_api_key")),
                    "model": cfg.get("ai_model") or report_mod.DEFAULT_MODEL})


@app.get("/api/diag")
def api_diag():
    return jsonify(net.selftest())


@app.get("/api/proxy")
def api_get_proxy():
    cfg = net.load_config()
    return jsonify({"proxy_url": cfg.get("proxy_url") or "",
                    "resolved": net.resolve_proxy() or "(directo)"})


@app.post("/api/proxy")
def api_set_proxy():
    from urllib.parse import urlparse
    data = request.get_json(silent=True) or {}
    proxy_url = (data.get("proxy_url") or "").strip()
    if proxy_url:
        parsed = urlparse(proxy_url if "://" in proxy_url else "http://" + proxy_url)
        if parsed.scheme not in ("http", "https", "socks4", "socks5"):
            return jsonify({"ok": False, "error": "Esquema de proxy no permitido. Usa http://, https://, socks4:// o socks5://."}), 400
    net.save_config({"proxy_url": proxy_url})
    return jsonify({"ok": True, "resolved": net.resolve_proxy() or "(directo)"})


# ============================================================ análisis de código
@app.post("/api/codescan")
@_limit("5 per minute")
def api_codescan():
    """Recibe un comprimido (zip/7z/rar) de la app, lo extrae de forma segura en
    un sandbox temporal, analiza el código y devuelve hallazgos de cumplimiento.
    NUNCA ejecuta el código extraído; el directorio temporal se elimina siempre."""
    import archive_extract as AE
    import code_scan as CS
    import tempfile

    up = request.files.get("file")
    if not up:
        return jsonify({"ok": False, "error": "sube un archivo .zip, .7z o .rar"}), 400
    safe_name = secure_filename(up.filename or "app.zip")
    _log.info("CODESCAN upload filename=%r safe=%r ip=%s", up.filename, safe_name, request.remote_addr)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="codescan_up_")
    os.close(tmp_fd)
    workdir = None
    try:
        up.save(tmp_path)
        workdir, meta = AE.extract(tmp_path, safe_name)
        # Análisis avanzado (motores SAST OSS + flujo de datos) salvo que se
        # desactive con ?ext=0. Es opcional y se degrada si no hay herramientas.
        run_ext = (request.args.get("ext", "1") != "0")
        result = CS.scan_tree(workdir, run_external=run_ext)
        result["archive"] = {"nombre": up.filename, **meta}
        result["generated_at"] = _now_str()

        # 1) Integrar los componentes detectados al inventario de software.
        comp = result.pop("_componentes", {}) or {}
        try:
            inv = _codescan_to_inventory(comp)
            result["inventario"] = inv
        except Exception:
            result["inventario"] = {"agregados": 0, "error": "no se pudo actualizar inventario"}

        # 2) Razonamiento profundo (ML local + IA opcional) sobre la evidencia.
        cfg = net.load_config()
        import code_reason as CR
        use_ai = (request.args.get("ai", "1") != "0")
        reasoned = CR.reason(result, api_key=cfg.get("anthropic_api_key") or None,
                             model=cfg.get("ai_model") or CR.DEFAULT_MODEL, use_ai=use_ai)
        result["findings"] = reasoned["enriched"]
        result["analisis"] = {
            "resumen_ejecutivo": reasoned.get("resumen_ejecutivo"),
            "nivel_global": reasoned.get("nivel_global"),
            "riesgo_global": reasoned.get("riesgo_global"),
            "hotspots": reasoned.get("hotspots"),
            "ai_used": reasoned.get("ai_used"), "ai_error": reasoned.get("ai_error"),
        }

        # 3) Evaluación de cumplimiento normativo (motor de controles auditables
        #    de los Decretos 7/9/10/11 de la Ley 21.180 y el DS 83/2004).
        try:
            import regulatory as REG
            result["cumplimiento"] = REG.evaluate(result, reasoned)
        except Exception:
            result["cumplimiento"] = None

        result["ok"] = True
        return jsonify(result)
    except AE.ExtractionError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"error al analizar: {type(e).__name__}"}), 500
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        if workdir:
            AE.cleanup(workdir)


def _codescan_to_inventory(comp):
    """Audita los manifiestos detectados en el código y los integra al inventario
    (reutiliza el pipeline de auditoría existente). Devuelve un pequeño resumen."""
    agregados = 0
    detalle = []
    # Gradle/Maven
    if comp.get("gradle_build"):
        try:
            import gradle_audit
            audit = audit_manifest(comp["gradle_build"], with_cves=False,
                                   filename="build.gradle.kts", toml=comp.get("gradle_toml"))
            deps = audit.get("deps", [])
            inventory_upsert_maven([d for d in deps if d.get("section") not in ("plataforma", "plugin")])
            inventory_upsert_platform([d for d in deps if d.get("section") == "plataforma"])
            inventory_upsert_plugins([d for d in deps if d.get("section") == "plugin"])
            n = len(deps)
            agregados += n
            detalle.append({"tipo": "gradle", "componentes": n})
        except Exception:
            pass
    # npm
    for rel, content in comp.get("npm", []):
        try:
            audit = audit_manifest(content, with_cves=False, filename="package.json")
            deps = audit.get("deps", [])
            inventory_upsert_npm(deps)
            agregados += len(deps)
            detalle.append({"tipo": "npm", "archivo": rel, "componentes": len(deps)})
        except Exception:
            pass
    return {"agregados": agregados, "detalle": detalle}


@app.post("/api/codescan/export")
def api_codescan_export():
    """Exporta el informe profesional de cumplimiento (DOCX/PDF/MD)."""
    import exporters
    from flask import Response
    data = request.get_json(silent=True) or {}
    report = data.get("report")
    fmt = (request.args.get("format") or "docx").lower()
    author = data.get("author") or "no indicado"
    if not report:
        return jsonify({"ok": False, "error": "falta el informe"}), 400
    if not hasattr(exporters, "codescan_to_" + fmt):
        return jsonify({"ok": False, "error": f"formato no soportado: {fmt}"}), 400
    blob = getattr(exporters, "codescan_to_" + fmt)(report, author=author,
                                                    generated_at=_now_str())
    ext = {"docx": "docx", "pdf": "pdf", "md": "md"}[fmt]
    mime = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "pdf": "application/pdf", "md": "text/markdown"}[fmt]
    return Response(blob, mimetype=mime, headers={
        "Content-Disposition": f'attachment; filename="informe_cumplimiento.{ext}"'})


def main():
    init_db()
    # Auto-refresh on first run if the cache is empty.
    with _db_lock, get_db() as db:
        empty = db.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] == 0
    if empty:
        threading.Thread(target=_refresh_worker, kwargs={"with_cves": True},
                         daemon=True).start()
    print("WebDev Software Catalog → http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, threaded=True)


if __name__ == "__main__":
    main()
