"""
bootstrap.py — instalación y configuración automática de dependencias en el arranque.

La aplicación funciona con su MOTOR PROPIO sin nada de esto. Este módulo, de forma
SEGURA y *best-effort*, intenta dejar disponibles los motores SAST OPCIONALES que
robustecen el análisis, usando el gestor de paquetes adecuado a cada caso:

  - pip : semgrep, bandit, detect-secrets, njsscan.
          njsscan SOLO en Python < 3.14: su dependencia `pydantic-core` aún no
          publica wheel para 3.14+ y compilarla exige toolchain de Rust. En 3.14+
          se omite y su dimensión (JS) la cubre RetireJS por npm.
  - npm : retire (RetireJS) — escáner de librerías JavaScript vulnerables;
          alternativa multiplataforma e independiente de la versión de Python.

Principios DevSecOps aplicados (ver auditoría en el README):
  - NO bloquea el arranque: corre en un hilo *daemon* en segundo plano.
  - NO derriba la app: cada paso está aislado; los fallos se registran y se sigue.
  - Idempotente: si el motor ya está disponible, no se reinstala.
  - Sin entrada de usuario en los comandos y sin `shell=True`: los paquetes son
    literales fijos del propio código → no hay superficie de inyección de comandos.
  - Versiones con mínimo acotado (reproducibilidad / cadena de suministro).
  - Conmutable: `WEBDEV_AUTO_INSTALL=0` lo desactiva por completo.
  - Respeta el proxy del entorno (se propaga a pip y npm).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading

_log = logging.getLogger("webdev.bootstrap")

PYV = sys.version_info[:2]

# Registro declarativo de motores opcionales.
#   py_max : última versión (major, minor) de Python soportada por el paquete.
ENGINES = [
    {"key": "semgrep",        "manager": "pip", "package": "semgrep>=1.60",       "check": "semgrep"},
    {"key": "bandit",         "manager": "pip", "package": "bandit>=1.7",         "check": "bandit"},
    {"key": "detect-secrets", "manager": "pip", "package": "detect-secrets>=1.4", "check": "detect-secrets"},
    {"key": "njsscan",        "manager": "pip", "package": "njsscan>=0.4",        "check": "njsscan",
     "py_max": (3, 13),
     "nota": "njsscan depende de pydantic-core (sin wheel para Python 3.14+); en 3.14+ se usa RetireJS."},
    {"key": "retire",         "manager": "npm", "package": "retire",              "check": "retire"},
]

# Estado por motor, observable por la UI / endpoint /api/engines.
#   ya-presente | instalado | omitido-pyver | sin-gestor | fallo | deshabilitado | pendiente
_status: dict[str, str] = {e["key"]: "pendiente" for e in ENGINES}
_status_lock = threading.Lock()
_done = threading.Event()
_started = False
_start_lock = threading.Lock()


def _enabled() -> bool:
    return os.environ.get("WEBDEV_AUTO_INSTALL", "1").strip() != "0"


def _have(check: str) -> bool:
    return bool(shutil.which(check))


def _set(key: str, value: str) -> None:
    with _status_lock:
        _status[key] = value


def _proxy_env() -> dict:
    """Propaga el proxy configurado en la app (o el del entorno) a pip/npm."""
    env = dict(os.environ)
    try:
        import net
        p = net.resolve_proxy()
        if p:
            env.setdefault("HTTPS_PROXY", p)
            env.setdefault("HTTP_PROXY", p)
            env.setdefault("npm_config_proxy", p)
            env.setdefault("npm_config_https_proxy", p)
    except Exception:
        pass
    return env


def _ensure_scripts_on_path() -> None:
    """Agrega al PATH del proceso los directorios donde pip (incl. --user) y npm
    dejan los ejecutables, para que los CLIs recién instalados se descubran SIN
    reiniciar la app (afecta a este proceso, del que también depende sast_external)."""
    import sysconfig
    extra = []
    try:
        extra.append(sysconfig.get_path("scripts"))
    except Exception:
        pass
    try:
        extra.append(sysconfig.get_path("scripts", scheme=f"{os.name}_user"))
    except Exception:
        pass
    appdata = os.environ.get("APPDATA")
    if appdata:
        extra.append(os.path.join(appdata, "npm"))           # npm -g en Windows
    extra.append(os.path.expanduser("~/.npm-global/bin"))     # npm -g típico en POSIX
    parts = os.environ.get("PATH", "").split(os.pathsep)
    added = [d for d in extra if d and os.path.isdir(d) and d not in parts]
    if added:
        os.environ["PATH"] = os.pathsep.join(parts + added)
        _log.info("bootstrap: PATH ampliado con %s", added)


def _configure() -> None:
    """Configuración liviana e idempotente del entorno de análisis."""
    # Semgrep: telemetría desactivada por defecto (privacidad / red).
    os.environ.setdefault("SEMGREP_SEND_METRICS", "off")
    _ensure_scripts_on_path()


def _pip_install(package: str, timeout: int = 600) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", "--quiet",
           "--disable-pip-version-check", "--no-input", package]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=_proxy_env())
        if p.returncode != 0:
            _log.warning("pip install %s falló (rc=%s): %s", package,
                         p.returncode, (p.stderr or "")[-300:].strip())
        return p.returncode == 0
    except Exception as e:
        _log.warning("pip install %s excepción: %s", package, e)
        return False


def _npm_install(package: str, timeout: int = 600) -> bool:
    npm = shutil.which("npm")
    if not npm:
        return False
    cmd = [npm, "install", "-g", "--no-fund", "--no-audit", package]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=_proxy_env(), shell=False)
        if p.returncode != 0:
            _log.warning("npm install -g %s falló (rc=%s): %s", package,
                         p.returncode, (p.stderr or "")[-300:].strip())
        return p.returncode == 0
    except Exception as e:
        _log.warning("npm install -g %s excepción: %s", package, e)
        return False


def _eligible(engine: dict) -> bool:
    py_max = engine.get("py_max")
    return not (py_max and PYV > tuple(py_max))


def ensure_engines() -> dict:
    """Asegura (instala si falta) los motores opcionales. Devuelve el estado.
    Pensado para correr en segundo plano; nunca lanza excepción hacia afuera."""
    _configure()
    for e in ENGINES:
        key, mgr, pkg, check = e["key"], e["manager"], e["package"], e["check"]
        try:
            if _have(check):
                _set(key, "ya-presente")
                continue
            if not _eligible(e):
                _set(key, "omitido-pyver")
                _log.info("bootstrap: %s omitido en Python %s.%s (%s)",
                          key, PYV[0], PYV[1], e.get("nota", ""))
                continue
            if mgr == "npm" and not shutil.which("npm"):
                _set(key, "sin-gestor")
                _log.info("bootstrap: %s requiere npm (no encontrado); se omite.", key)
                continue
            _log.info("bootstrap: instalando %s vía %s …", key, mgr)
            ok = _pip_install(pkg) if mgr == "pip" else _npm_install(pkg)
            # Reconfirmar por presencia real del ejecutable, no solo por el rc.
            _set(key, "instalado" if (ok and _have(check)) else "fallo")
        except Exception as e2:  # defensa: ningún motor puede tumbar el bootstrap
            _set(key, "fallo")
            _log.warning("bootstrap: error con %s: %s", key, e2)
    _done.set()
    with _status_lock:
        _log.info("bootstrap: motores -> %s", dict(_status))
        return dict(_status)


def start_async() -> None:
    """Dispara el bootstrap una sola vez, en segundo plano, sin bloquear el arranque."""
    global _started
    with _start_lock:
        if _started:
            return
        _started = True
    # La configuración del entorno (incl. ampliar PATH para descubrir motores ya
    # instalados) se aplica SIEMPRE, aunque la autoinstalación esté desactivada.
    try:
        _configure()
    except Exception as e:
        _log.warning("bootstrap: _configure falló: %s", e)
    if not _enabled():
        for e in ENGINES:
            _set(e["key"], "deshabilitado")
        _done.set()
        _log.info("bootstrap: WEBDEV_AUTO_INSTALL=0 → autoinstalación desactivada.")
        return
    threading.Thread(target=ensure_engines, name="webdev-bootstrap",
                     daemon=True).start()


def status() -> dict:
    """Estado observable (para diagnóstico / endpoint)."""
    with _status_lock:
        engines = dict(_status)
    return {
        "python": f"{PYV[0]}.{PYV[1]}",
        "auto_install": _enabled(),
        "npm": bool(shutil.which("npm")),
        "completado": _done.is_set(),
        "engines": engines,
    }


if __name__ == "__main__":
    # Ejecución manual y SÍNCRONA: útil en despliegues (waitress) para preparar
    # los motores antes de servir.  >  python bootstrap.py
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    print("WebDev bootstrap — Python", f"{PYV[0]}.{PYV[1]}")
    print(ensure_engines())
