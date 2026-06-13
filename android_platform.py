"""
Base de conocimiento de la plataforma Android para evaluar compileSdk / targetSdk
/ minSdk, la versión del Android Gradle Plugin (AGP) y de Gradle declaradas en un
proyecto, y graduar su vigencia/soporte.

Datos de referencia al 2026-06 (verificables en developer.android.com / apilevels.com):
  - API 36 = Android 16 (Baklava), estable desde jun-2025 — última estable.
  - API 35 = Android 15 (Vanilla Ice Cream), sep-2024.
  - API 37 = Android 17 (Cinnamon Bun) — en beta, aún no final.

Google Play exige que las apps nuevas y sus actualizaciones apunten a un targetSdk
reciente (por política, cercano a la última versión estable). Se usa una referencia
orientativa; el valor exacto debe confirmarse en la consola de Play.
"""

# api_level -> (versión Android, nombre, año, estado)
ANDROID_API = {
    37: ("17", "Cinnamon Bun", 2026, "beta"),
    36: ("16", "Baklava", 2025, "estable"),
    35: ("15", "Vanilla Ice Cream", 2024, "estable"),
    34: ("14", "Upside Down Cake", 2023, "estable"),
    33: ("13", "Tiramisu", 2022, "estable"),
    32: ("12L", "Snow Cone v2", 2022, "antigua"),
    31: ("12", "Snow Cone", 2021, "antigua"),
    30: ("11", "Red Velvet Cake", 2020, "antigua"),
    29: ("10", "Quince Tart", 2019, "obsoleta"),
    28: ("9", "Pie", 2018, "obsoleta"),
    27: ("8.1", "Oreo", 2017, "obsoleta"),
    26: ("8.0", "Oreo", 2017, "obsoleta"),
    25: ("7.1", "Nougat", 2016, "obsoleta"),
    24: ("7.0", "Nougat", 2016, "obsoleta"),
    23: ("6.0", "Marshmallow", 2015, "obsoleta"),
    22: ("5.1", "Lollipop", 2015, "obsoleta"),
    21: ("5.0", "Lollipop", 2014, "obsoleta"),
}

LATEST_STABLE_API = 36          # Android 16
PLAY_TARGET_MIN_API = 35        # objetivo mínimo orientativo exigido por Play (Android 15)

# Última versión estable conocida del Android Gradle Plugin y de Gradle (2026-06).
AGP_LATEST = "9.2.0"
GRADLE_LATEST = "8.14"

DEV_API_URL = "https://developer.android.com/tools/releases/platforms"
AGP_URL = "https://developer.android.com/build/releases/gradle-plugin"
GRADLE_URL = "https://gradle.org/releases/"


def _to_int(v):
    try:
        return int(str(v).strip())
    except Exception:
        return None


def assess_sdk(kind, value):
    """Evalúa compileSdk/targetSdk/minSdk. Devuelve un dict tipo 'entry de plataforma'
    compatible con el pipeline de reporte/inventario."""
    api = _to_int(value)
    info = ANDROID_API.get(api)
    ver, codename, year, estado = info if info else (None, None, None, None)
    label = f"API {api}" + (f" (Android {ver} {codename})" if ver else "")
    latest_label = f"API {LATEST_STABLE_API} (Android {ANDROID_API[LATEST_STABLE_API][0]})"
    gap = None
    if api is not None:
        if api < LATEST_STABLE_API:
            gap = "major"  # cada API level es un salto de versión mayor de Android
    level, note, reco = "ok", None, None

    if api is None:
        level = "desconocido"
        note = f"No se pudo interpretar el valor de {kind}: «{value}»."
    elif kind == "minSdk":
        # minSdk es una decisión de alcance, no un riesgo de obsolescencia en sí.
        level = "ok"
        note = (f"minSdk {label}: define el dispositivo más antiguo soportado. "
                f"No es un riesgo de obsolescencia; valores muy bajos (≤ API 23) "
                f"pueden implicar mantener parches de seguridad para SO sin soporte.")
        if api <= 23:
            level = "bajo"
            reco = "Evaluar elevar minSdk si no se requiere soporte de equipos muy antiguos."
    elif kind == "targetSdk":
        if api >= LATEST_STABLE_API:
            level, note = "ok", f"targetSdk {label}: alineado con la última versión estable."
        elif api >= PLAY_TARGET_MIN_API:
            level = "bajo"
            note = f"targetSdk {label}: vigente, pero por debajo de la última estable ({latest_label})."
            reco = f"Planificar actualización a {latest_label} para nuevas funciones y compatibilidad."
        else:
            level = "alto"
            note = (f"targetSdk {label}: por debajo del mínimo orientativo exigido por Google Play "
                    f"(API {PLAY_TARGET_MIN_API}). Puede impedir publicar/actualizar la app en Play.")
            reco = (f"Subir targetSdk al menos a API {PLAY_TARGET_MIN_API} (idealmente {latest_label}). "
                    f"Confirmar el requisito vigente en la consola de Google Play.")
    elif kind == "compileSdk":
        if api >= LATEST_STABLE_API:
            level, note = "ok", f"compileSdk {label}: alineado con la última versión estable."
        elif api >= LATEST_STABLE_API - 1:
            level, note = "bajo", f"compileSdk {label}: una versión por detrás de la última estable ({latest_label})."
            reco = f"Actualizar compileSdk a {latest_label} cuando sea posible."
        else:
            level = "medio"
            note = (f"compileSdk {label}: {LATEST_STABLE_API - api} versiones por detrás de la última "
                    f"estable ({latest_label}); puede impedir usar APIs y parches recientes.")
            reco = f"Actualizar compileSdk a {latest_label}."

    return _platform_entry(
        kind=kind, name=f"Android {kind}", installed=str(api) if api is not None else str(value),
        range_label=label, latest=str(LATEST_STABLE_API), latest_label=latest_label,
        gap=gap, level=level, note=note, reco=reco, url=DEV_API_URL,
        eol_info=(f"Android {ver} ({codename}) — estado: {estado}." if ver else "API level no reconocido."))


def assess_tool(kind, value):
    """Evalúa AGP o Gradle declarados. kind ∈ {'AGP','Gradle'}."""
    latest = AGP_LATEST if kind == "AGP" else GRADLE_LATEST
    url = AGP_URL if kind == "AGP" else GRADLE_URL
    gap = _semver_gap(value, latest)
    level, note, reco = "ok", None, None
    if not value:
        level = "desconocido"
        note = f"No se detectó la versión de {kind}."
    elif gap == "major":
        level = "medio"
        note = f"{kind} {value}: hay una versión mayor más reciente ({latest}); puede faltar soporte de APIs/seguridad del build."
        reco = f"Actualizar {kind} a {latest} (revisar notas de migración)."
    elif gap in ("minor", "patch"):
        level = "bajo"
        note = f"{kind} {value}: desactualizado respecto de {latest}."
        reco = f"Actualizar {kind} a {latest}."
    else:
        note = f"{kind} {value}: al día respecto de la última versión conocida ({latest})."
    return _platform_entry(
        kind=kind, name=f"{kind}" if kind == "Gradle" else "Android Gradle Plugin",
        installed=value or "n/d", range_label=value or "n/d",
        latest=latest, latest_label=latest, gap=gap, level=level, note=note, reco=reco,
        url=url, eol_info=f"Herramienta de build; última versión conocida: {latest}.")


def _semver_gap(installed, latest):
    import re
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


def _platform_entry(kind, name, installed, range_label, latest, latest_label,
                    gap, level, note, reco, url, eol_info):
    """Entrada compatible con el pipeline (deps): el reporte la trata como ítem
    de plataforma usando platform_kind/platform_level/platform_note/platform_reco."""
    return {
        "package": name, "section": "plataforma", "range": range_label,
        "installed": installed, "pinned": True,
        "latest": latest, "latest_label": latest_label, "latest_release": None,
        "outdated": bool(gap), "gap": gap,
        "vuln_status": None, "vuln_count": 0, "vuln_ids": [], "vuln_details": [],
        "note": None, "ecosystem": "Android Platform",
        "npm_url": url, "homepage": url, "repository": None, "description": None,
        "eol_url": url, "eol_info": eol_info,
        "compliance": None,
        "platform_kind": kind, "platform_level": level,
        "platform_note": note, "platform_reco": reco,
    }
