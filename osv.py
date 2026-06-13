"""
Cliente OSV.dev compartido y optimizado.

En lugar de una petición por dependencia (N round-trips), usa el endpoint
`/v1/querybatch` para consultar TODAS las (ecosystem, name, version) en UNA sola
petición. Ese endpoint devuelve solo IDs de vulnerabilidad; el detalle (resumen,
severidad, referencias) se obtiene con `/v1/vulns/{id}`, pero únicamente para las
pocas vulnerabilidades realmente presentes, y con caché en memoria.

Resultado típico (proyecto con la mayoría de deps sin CVE):
  antes:  N peticiones POST /v1/query con payload completo
  ahora:  1 POST /v1/querybatch  +  (nº de CVE únicos) GET /v1/vulns/{id} cacheados
"""

import threading
import time

import net

QUERY = "https://api.osv.dev/v1/query"
QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/{id}"

_detail_cache = {}            # vuln_id -> (expira, shaped|None)
_detail_lock = threading.Lock()
_DETAIL_TTL = 3600


def _pick_cve(vobj):
    aliases = vobj.get("aliases") or []
    return next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")),
                vobj.get("id"))


def shape(vobj):
    """Forma compacta del detalle de una vulnerabilidad OSV."""
    cve = _pick_cve(vobj)
    sev = None
    for s in (vobj.get("severity") or []):
        if isinstance(s, dict) and s.get("score"):
            sev = s.get("score"); break
    refs = [rf.get("url") for rf in (vobj.get("references") or [])[:5]
            if isinstance(rf, dict) and rf.get("url")]
    return {"id": cve or vobj.get("id"), "osv_id": vobj.get("id"),
            "aliases": vobj.get("aliases") or [],
            "summary": (vobj.get("summary") or "")[:300],
            "details": (vobj.get("details") or "")[:1000],
            "severity": sev, "published": vobj.get("published"),
            "modified": vobj.get("modified"), "references": refs}


def _detail(vuln_id):
    now = time.time()
    with _detail_lock:
        hit = _detail_cache.get(vuln_id)
        if hit and hit[0] > now:
            return hit[1]
    data, err = net.get_json_cached(VULN.format(id=vuln_id), ttl=_DETAIL_TTL)
    shaped = shape(data) if (data and not err) else {"id": vuln_id, "osv_id": vuln_id,
                                                     "summary": "", "severity": None, "references": []}
    with _detail_lock:
        _detail_cache[vuln_id] = (now + _DETAIL_TTL, shaped)
    return shaped


_MAX_BATCH = 256  # OSV recomienda lotes acotados; evita payloads gigantes.


def batch(queries, fetch_details=True, max_detail_workers=8):
    """queries: lista de (ecosystem, name, version). Devuelve lista alineada con
    queries; cada elemento: {status, count, ids, details}.

    Hace POST querybatch (troceado en lotes de _MAX_BATCH) y, si fetch_details,
    baja el detalle de los CVE únicos en paralelo (cacheado)."""
    n = len(queries)
    out = [{"status": "no-version", "count": None, "ids": [], "details": []} for _ in range(n)]
    valid = [(i, q) for i, q in enumerate(queries) if q[0] and q[1] and q[2]]
    if not valid:
        return out

    results = []
    for start in range(0, len(valid), _MAX_BATCH):
        chunk = valid[start:start + _MAX_BATCH]
        payload = {"queries": [{"package": {"ecosystem": e, "name": nm}, "version": str(v)}
                               for _, (e, nm, v) in chunk]}
        try:
            r = net.post(QUERYBATCH, json=payload, timeout=20)
            if r.status_code != 200:
                raise net.NetworkError(f"HTTP {r.status_code}")
            results.extend((r.json() or {}).get("results") or [])
        except (net.NetworkError, ValueError):
            for i, _ in chunk:
                out[i] = {"status": "neterror", "count": None, "ids": [], "details": []}
            results.extend([None] * len(chunk))

    # Mapear resultados del batch (alineados con 'valid') y juntar IDs únicos.
    per_index_vulns = {}
    unique_ids = set()
    for (idx, _), res in zip(valid, results):
        if res is None:        # chunk falló: ya marcado neterror, no tocar
            continue
        vulns = (res or {}).get("vulns") or []
        per_index_vulns[idx] = [v.get("id") for v in vulns if v.get("id")]
        unique_ids.update(per_index_vulns[idx])

    details_map = {}
    if fetch_details and unique_ids:
        from concurrent.futures import ThreadPoolExecutor
        ids = list(unique_ids)
        with ThreadPoolExecutor(max_workers=min(max_detail_workers, len(ids))) as ex:
            for vid, shaped in zip(ids, ex.map(_detail, ids)):
                details_map[vid] = shaped

    for i, _ in valid:
        if out[i].get("status") == "neterror":   # preservar fallos de chunk
            continue
        vids = per_index_vulns.get(i, [])
        if not vids:
            out[i] = {"status": "clean", "count": 0, "ids": [], "details": []}
            continue
        details = [details_map.get(vid) or {"id": vid, "osv_id": vid} for vid in vids[:8]]
        ids = [d.get("id") for d in details if d.get("id")]
        out[i] = {"status": "vulnerable", "count": len(vids), "ids": ids, "details": details}
    return out


def query_one(ecosystem, pkg, version):
    """Consulta puntual (compatibilidad). Usa el batch de 1 elemento."""
    return batch([(ecosystem, pkg, version)])[0]
