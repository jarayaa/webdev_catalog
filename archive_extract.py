"""
Extracción SEGURA de archivos comprimidos (.zip, .7z, .rar) a un directorio
temporal aislado, con defensas DevSecOps:

  - Zip-Slip: se rechazan rutas que escapen del directorio destino (../ o absolutas).
  - Zip-bomb: límites de tamaño total descomprimido, número de archivos y ratio
    de compresión.
  - Aislamiento (compartimentaje): cada análisis usa su propio directorio temporal,
    que se elimina al terminar; no se ejecuta NUNCA el código extraído.

7z requiere py7zr; rar requiere el binario 'unrar'/'bsdtar' o el paquete rarfile
con backend disponible. Si falta el soporte, se informa con un mensaje claro.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile

MAX_TOTAL_BYTES = 500 * 1024 * 1024     # 500 MB descomprimido
MAX_FILES = 20000
MAX_RATIO = 200                          # ratio de compresión máximo permitido


class ExtractionError(Exception):
    pass


def _safe_join(base: str, *paths) -> str:
    """Evita Zip-Slip: la ruta final debe quedar dentro de `base`."""
    target = os.path.realpath(os.path.join(base, *paths))
    if not (target == os.path.realpath(base) or target.startswith(os.path.realpath(base) + os.sep)):
        raise ExtractionError(f"Ruta insegura en el archivo (zip-slip): {paths}")
    return target


def detect_kind(filename: str, head: bytes) -> str:
    fn = (filename or "").lower()
    if head.startswith(b"PK\x03\x04") or fn.endswith(".zip"):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c") or fn.endswith(".7z"):
        return "7z"
    if head.startswith(b"Rar!") or fn.endswith(".rar"):
        return "rar"
    return "zip" if fn.endswith(".zip") else "desconocido"


def extract(src_path: str, filename: str) -> tuple[str, dict]:
    """Extrae el archivo a un directorio temporal aislado. Devuelve (dir, meta)."""
    with open(src_path, "rb") as f:
        head = f.read(8)
    kind = detect_kind(filename, head)
    dest = tempfile.mkdtemp(prefix="codescan_")
    meta = {"kind": kind, "files": 0, "bytes": 0}
    try:
        if kind == "zip":
            _extract_zip(src_path, dest, meta)
        elif kind == "7z":
            _extract_7z(src_path, dest, meta)
        elif kind == "rar":
            _extract_rar(src_path, dest, meta)
        else:
            raise ExtractionError("Formato no reconocido. Usa .zip, .7z o .rar.")
    except ExtractionError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(dest, ignore_errors=True)
        raise ExtractionError(f"No se pudo extraer ({kind}): {e}") from e
    return dest, meta


def _check_limits(meta, add_bytes=0, add_files=0):
    if meta["bytes"] + add_bytes > MAX_TOTAL_BYTES:
        raise ExtractionError("El contenido descomprimido supera el límite (posible zip-bomb).")
    if meta["files"] + add_files > MAX_FILES:
        raise ExtractionError("Demasiados archivos en el comprimido (posible zip-bomb).")


def _extract_zip(src, dest, meta):
    import stat as _stat
    with zipfile.ZipFile(src) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            # Bloquear symlinks embebidos en el ZIP (atributo externo en modo Unix).
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if unix_mode and _stat.S_ISLNK(unix_mode):
                raise ExtractionError(f"El archivo contiene un symlink: {info.filename}. Operación denegada.")
            # Defensa zip-bomb por ratio
            if info.compress_size > 0 and info.file_size / max(info.compress_size, 1) > MAX_RATIO \
               and info.file_size > 1_000_000:
                raise ExtractionError(f"Ratio de compresión sospechoso en {info.filename}.")
            _check_limits(meta, info.file_size, 1)
            target = _safe_join(dest, info.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as srcf, open(target, "wb") as dstf:
                shutil.copyfileobj(srcf, dstf, length=1024 * 64)
            meta["files"] += 1
            meta["bytes"] += info.file_size


def _extract_7z(src, dest, meta):
    try:
        import py7zr
    except ImportError:
        raise ExtractionError("Soporte 7z no disponible: instala 'py7zr'.")
    with py7zr.SevenZipFile(src, mode="r") as z:
        total = sum(getattr(e, "uncompressed", 0) or 0 for e in z.list())
        if total > MAX_TOTAL_BYTES:
            raise ExtractionError("El contenido 7z supera el límite (posible zip-bomb).")
        names = z.getnames()
        for n in names:
            _safe_join(dest, n)  # valida cada ruta antes de extraer
        if len(names) > MAX_FILES:
            raise ExtractionError("Demasiados archivos en el 7z.")
        z.extractall(path=dest)
    for dirpath, _d, files in os.walk(dest):
        for fn in files:
            meta["files"] += 1
            try:
                meta["bytes"] += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass


def _extract_rar(src, dest, meta):
    # rarfile necesita un backend: binario 'unrar' o 'bsdtar'. Si no está, avisar.
    try:
        import rarfile
    except ImportError:
        raise ExtractionError("Soporte RAR no disponible: instala 'rarfile' y el binario 'unrar'.")
    if not (shutil.which("unrar") or shutil.which("bsdtar") or shutil.which("unar")):
        raise ExtractionError(
            "RAR requiere el binario 'unrar' (o 'bsdtar'/'unar') instalado en el sistema. "
            "Sugerencia: recomprime la app como .zip o .7z, que no requieren binarios externos.")
    with rarfile.RarFile(src) as rf:
        for info in rf.infolist():
            if info.isdir():
                continue
            _check_limits(meta, getattr(info, "file_size", 0), 1)
            _safe_join(dest, info.filename)
            meta["files"] += 1
            meta["bytes"] += getattr(info, "file_size", 0)
        rf.extractall(path=dest)


def cleanup(directory: str) -> None:
    shutil.rmtree(directory, ignore_errors=True)
