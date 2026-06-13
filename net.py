"""
HTTP helper — completely self-contained for this app.

Talks to the public APIs (endoflife.date, OSV.dev) through the corporate proxy
and trusting the OS certificate store (so TLS-inspection CAs like Zscaler work),
exactly like a browser would. Plain `requests` verifies against certifi and
ignores the stdlib SSL context, so on an inspected network it fails; mounting a
`truststore`-backed SSL context fixes that. Network failures raise NetworkError
so callers can report them clearly instead of pretending there's no data.
"""

import os
import json
import threading
import requests

_CFG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
_cfg_lock = threading.Lock()

_truststore_ctx = None
try:
    import ssl
    import truststore
    _truststore_ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
except Exception:
    _truststore_ctx = None


class _TruststoreAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *a, **k):
        if _truststore_ctx is not None:
            k["ssl_context"] = _truststore_ctx
        return super().init_poolmanager(*a, **k)

    def proxy_manager_for(self, *a, **k):
        if _truststore_ctx is not None:
            k["ssl_context"] = _truststore_ctx
        return super().proxy_manager_for(*a, **k)


# Pool grande + reintentos con backoff: necesario para auditar en paralelo sin
# agotar conexiones ni caerse por 429/5xx transitorios del registro o el proxy.
try:
    from urllib3.util.retry import Retry
    _RETRY = Retry(total=2, connect=2, read=2, backoff_factor=0.4,
                   status_forcelist=(429, 500, 502, 503, 504),
                   allowed_methods=frozenset(["GET", "POST"]))
except Exception:
    _RETRY = None

_POOL_SIZE = 24


def _make_session():
    s = requests.Session()
    s.trust_env = True
    s.headers.update({"User-Agent": "WebDevCatalog/1.0",
                      "Accept-Encoding": "gzip, deflate"})
    adapter_kwargs = dict(pool_connections=_POOL_SIZE, pool_maxsize=_POOL_SIZE)
    if _RETRY is not None:
        adapter_kwargs["max_retries"] = _RETRY
    if _truststore_ctx is not None:
        https_adapter = _TruststoreAdapter(**adapter_kwargs)
    else:
        https_adapter = requests.adapters.HTTPAdapter(**adapter_kwargs)
    s.mount("https://", https_adapter)
    s.mount("http://", requests.adapters.HTTPAdapter(**adapter_kwargs))
    return s


_session = _make_session()


# ---- config (proxy) persistence -----------------------------------------
_cfg_cache = None  # dict | None ; cacheado para no leer disco en cada request


def _apply_env_overrides(cfg: dict) -> dict:
    """Variables de entorno tienen precedencia sobre config.json para credenciales sensibles."""
    env_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env_key:
        cfg = {**cfg, "anthropic_api_key": env_key}
    return cfg


def load_config():
    global _cfg_cache
    with _cfg_lock:
        if _cfg_cache is not None:
            return _apply_env_overrides(dict(_cfg_cache))
        try:
            with open(_CFG_FILE, encoding="utf-8") as f:
                _cfg_cache = json.load(f)
        except Exception:
            _cfg_cache = {}
        return _apply_env_overrides(dict(_cfg_cache))


def save_config(updates):
    global _cfg_cache
    with _cfg_lock:
        cfg = {}
        try:
            with open(_CFG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        cfg.update(updates)
        try:
            with open(_CFG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass
        _cfg_cache = cfg          # refrescar caché (sin override de env)
        _proxy_cache["v"] = None  # invalidar proxy resuelto
        return _apply_env_overrides(cfg)


_proxy_cache = {"v": None}


def resolve_proxy():
    """Proxy priority: explicit app config → environment variables → none.
    Cacheado en memoria para no parsear config.json en cada petición."""
    if _proxy_cache["v"] is not None:
        return _proxy_cache["v"] or None
    cfg = load_config()
    p = (cfg.get("proxy_url")
         or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
         or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    _proxy_cache["v"] = p or ""
    return p or None


def _proxies(explicit=None):
    url = explicit or resolve_proxy()
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    return {"http": url, "https": url}


class NetworkError(Exception):
    pass


def get(url, **kwargs):
    kwargs.setdefault("proxies", _proxies())
    kwargs.setdefault("timeout", 15)
    try:
        return _session.get(url, **kwargs)
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"{type(e).__name__}: {e}") from e


def post(url, **kwargs):
    kwargs.setdefault("proxies", _proxies())
    kwargs.setdefault("timeout", 15)
    try:
        return _session.post(url, **kwargs)
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"{type(e).__name__}: {e}") from e


# ---- caché TTL en memoria para GET JSON (metadata que cambia lento) -------
import time as _time

_json_cache = {}        # url -> (expira_ts, valor)
_json_cache_lock = threading.Lock()
_JSON_TTL = 600         # 10 min: la última versión publicada no cambia minuto a minuto


# Tope de tamaño de respuesta JSON (DevSecOps): un upstream comprometido o un
# documento gigante no debe agotar la memoria del proceso.
_MAX_JSON_BYTES = int(os.environ.get("WEBDEV_MAX_JSON_BYTES", str(8 * 1024 * 1024)))


def get_json_cached(url, ttl=_JSON_TTL, timeout=15, headers=None):
    """GET + parseo JSON con caché en memoria por URL. Devuelve (data|None, error).
    Reduce red y CPU al re-auditar o al repetir paquetes entre secciones.
    Corta lecturas por encima de _MAX_JSON_BYTES para acotar memoria."""
    now = _time.time()
    with _json_cache_lock:
        hit = _json_cache.get(url)
        if hit and hit[0] > now:
            return hit[1], None
    try:
        r = get(url, timeout=timeout, headers=headers or {"Accept": "application/json"},
                stream=True)
    except NetworkError:
        return None, "neterror"
    if r.status_code == 404:
        with _json_cache_lock:
            _json_cache[url] = (now + ttl, None)
        return None, "not-found"
    if r.status_code != 200:
        return None, f"http-{r.status_code}"
    declared = r.headers.get("Content-Length")
    if declared and declared.isdigit() and int(declared) > _MAX_JSON_BYTES:
        return None, "too-large"
    try:
        raw = r.raw.read(_MAX_JSON_BYTES + 1, decode_content=True)
        if len(raw) > _MAX_JSON_BYTES:
            return None, "too-large"
        import json as _json
        data = _json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None, "parse"
    with _json_cache_lock:
        _json_cache[url] = (now + ttl, data)
    return data, None


def cache_clear():
    with _json_cache_lock:
        _json_cache.clear()


def selftest():
    """Live connectivity probe for the diagnostic UI."""
    proxy = resolve_proxy()
    out = {"truststore": _truststore_ctx is not None,
           "proxy": proxy or "(directo — sin proxy)", "targets": {}}
    probes = {
        "endoflife.date": ("get", "https://endoflife.date/api/all.json", None),
        "osv.dev": ("post", "https://api.osv.dev/v1/query",
                    {"package": {"name": "jquery", "ecosystem": "npm"}, "version": "1.0.0"}),
    }
    for name, (method, url, body) in probes.items():
        try:
            if method == "post":
                r = _session.post(url, json=body, timeout=12, proxies=_proxies(proxy))
            else:
                r = _session.get(url, timeout=12, proxies=_proxies(proxy))
            out["targets"][name] = {"ok": r.status_code == 200, "status": r.status_code}
        except requests.exceptions.SSLError as e:
            out["targets"][name] = {"ok": False, "error": "SSL/CA", "detail": str(e)[:160]}
        except requests.exceptions.ProxyError as e:
            out["targets"][name] = {"ok": False, "error": "proxy", "detail": str(e)[:160]}
        except requests.exceptions.RequestException as e:
            out["targets"][name] = {"ok": False, "error": type(e).__name__, "detail": str(e)[:160]}
    return out
