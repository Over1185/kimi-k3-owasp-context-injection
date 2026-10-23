"""Utilidades compartidas por los scripts del paquete de replicación."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocol"
CONTEXT_FILES = ROOT / "context_files"
FRAGMENTS = ROOT / "fragments"
CHAT_LOGS = ROOT / "chat_logs"
SAST_REPORTS = ROOT / "sast_reports"
DATA = ROOT / "data"
RESULTS = ROOT / "results"

GROUPS = ("control", "experimental")
# La carpeta de trabajo que ve el modelo debe ser NEUTRA: sin "owasp", "control", "experimental"
# ni el código del escenario en su ruta (el modelo lee la ruta del workspace).
DEFAULT_BASE_NAME = "trabajo"
WORKSPACE_NAME = "app"
# Carpeta desechable de cada corrida (ruta NEUTRA): ~/trabajo/app
DEFAULT_BASE = Path.home() / DEFAULT_BASE_NAME
# Export del chat por defecto (fuera del workspace): ~/owasp_runs/_export/chat.json
DEFAULT_EXPORT_DIR = Path.home() / "owasp_runs" / "_export"
DEFAULT_CHAT_JSON = DEFAULT_EXPORT_DIR / "chat.json"
N_ITERATIONS = 5
FRAGMENT_RE = re.compile(r"^(E\d{2})_(control|experimental)_iter(\d+)$")


# ----------------------------------------------------------------------------
# Anonimización (rutas con nombre de usuario y términos personales)
# ----------------------------------------------------------------------------
PLACEHOLDER = "<USER>"
TERMS_FILE = ROOT / ".anonymize_terms.txt"   # NO se sube a GitHub (ver .gitignore)
_SEP = r"(?:\\{1,4}|/|%2[Ff]|%5[Cc])+"
_NAME = r"(?:(?!%2[Ff]|%5[Cc])[^\\/\"'\s<>:*?|,;()\[\]{}])+"
# C:\Users\NOMBRE, C:\\Users\\NOMBRE (JSON), file:///c%3A/Users/NOMBRE
_WIN_USER = re.compile(rf"(?P<pre>(?<![A-Za-z])[A-Za-z](?::|%3[Aa]){_SEP}Users{_SEP})(?P<name>{_NAME})", re.I)
_MAC_USER = re.compile(rf"(?P<pre>(?<![\w.\-])/Users/)(?P<name>{_NAME})")
_KEEP_NAMES = {"public", "default", "<user>", "all", "shared"}


def load_terms() -> list[str]:
    """Términos personales extra (nombre completo, correo, equipo...) desde .anonymize_terms.txt."""
    if not TERMS_FILE.is_file():
        return []
    out = []
    for line in TERMS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def anonymize_text(text: str, extra_terms=()) -> tuple[str, dict]:
    """Reemplaza el nombre de usuario en rutas de Windows/macOS por <USER> y los
    términos extra (coincidencia exacta, con límites de palabra) por <REDACTED>.

    Devuelve (texto_nuevo, {término_o_nombre: n_reemplazos}).
    No toca palabras sueltas del texto: el nombre de usuario solo se reemplaza
    cuando aparece dentro de una ruta.
    """
    counts: dict[str, int] = {}

    def _sub(m):
        name = m.group("name")
        if name.lower() in _KEEP_NAMES:
            return m.group(0)
        counts[name] = counts.get(name, 0) + 1
        return m.group("pre") + PLACEHOLDER

    text = _WIN_USER.sub(_sub, text)
    text = _MAC_USER.sub(_sub, text)
    for term in extra_terms:
        if not term:
            continue
        pat = re.compile(rf"(?<!\w){re.escape(term)}(?!\w)")
        n = len(pat.findall(text))
        if n:
            counts[term] = counts.get(term, 0) + n
            text = pat.sub("<REDACTED>", text)
    return text, counts


def load_expected_env() -> dict:
    return json.loads((PROTOCOL / "expected_environment.json").read_text(encoding="utf-8"))


def load_protocol() -> dict:
    return json.loads((PROTOCOL / "prompts.json").read_text(encoding="utf-8"))


def scenarios() -> dict[str, dict]:
    return {s["id"]: s for s in load_protocol()["scenarios"]}


def fragment_id(scenario: str, group: str, iteration: int) -> str:
    return f"{scenario}_{group}_iter{iteration}"


def resolve_workspace(base_arg=None):
    """Devuelve (base, carpeta_de_trabajo, archivo_marcador).

    La ruta es siempre NEUTRA (<base>/app, base ~/trabajo): el modelo lee la ruta del
    workspace y no debe ver "owasp", el grupo ni el escenario. El marcador de la corrida
    en curso va fuera de la carpeta de trabajo (git no lo ve y el modelo tampoco).
    """
    base = Path(base_arg or DEFAULT_BASE).expanduser().resolve()
    return base, base / WORKSPACE_NAME, base / "_current.json"


def run_status(fid: str) -> str:
    """Estado de una corrida según data/run_log.csv (último evento de cierre/preparación).

    Devuelve: "recogido" (hecha y guardada), "descartado", "preparado" (preparada pero nunca
    cerrada) o "nuevo" (sin registros).
    """
    path = DATA / "run_log.csv"
    status = "nuevo"
    if not path.is_file():
        return status
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("id_fragmento") != fid:
                continue
            ev = row.get("evento")
            if ev == "RECOGIDO":
                status = "recogido"
            elif ev == "DESCARTADO":
                status = "descartado"
            elif ev == "PREPARADO":
                status = "preparado"
    return status


def parse_fragment_id(fid: str) -> tuple[str, str, int]:
    m = FRAGMENT_RE.match(fid)
    if not m:
        raise ValueError(f"ID de fragmento inválido: {fid}")
    return m.group(1), m.group(2), int(m.group(3))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(fid: str, event: str, detail: str = "") -> None:
    """Agrega una línea a data/run_log.csv (registro automático, no sustituye la bitácora manual)."""
    DATA.mkdir(exist_ok=True)
    detail = anonymize_text(detail, load_terms())[0]
    path = DATA / "run_log.csv"
    is_new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if is_new:
            w.writerow(["timestamp_utc", "id_fragmento", "evento", "detalle"])
        w.writerow([utc_now(), fid, event, detail])


BITACORA_HEADER = ["fecha_hora", "id_fragmento", "tipo_evento", "descripcion", "accion_tomada"]


def log_incident(fid: str, event: str, detail: str, action: str) -> None:
    """Registra la incidencia en data/run_log.csv Y en data/bitacora.csv (anotación automática).

    La bitácora conserva sus columnas; estas filas llevan el prefijo "[auto]" para distinguirlas
    de las observaciones que escribas a mano (que siguen siendo bienvenidas).
    """
    log_event(fid, event, detail)
    DATA.mkdir(exist_ok=True)
    path = DATA / "bitacora.csv"
    detail = anonymize_text(detail, load_terms())[0]
    needs_header = (not path.exists()) or path.stat().st_size == 0
    needs_newline = False
    if not needs_header:
        with path.open("rb") as f:
            f.seek(-1, os.SEEK_END)
            needs_newline = f.read(1) not in (b"\n", b"\r")
    with path.open("a", newline="", encoding="utf-8") as f:
        if needs_newline:
            f.write("\r\n")
        w = csv.writer(f)
        if needs_header:
            w.writerow(BITACORA_HEADER)
        w.writerow([utc_now(), fid, event, f"[auto] {detail}", action])


def count_loc(path: Path) -> int:
    """LdC = líneas no vacías que no son un comentario puro (#).

    Es una definición operativa: documéntala en el artículo. Las líneas de
    docstrings cuentan como código.
    """
    n = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            n += 1
    return n


def rmtree_force(path: Path, retries: int = 5, delay: float = 1.0) -> bool:
    """Borra una carpeta aunque tenga archivos de solo lectura (.git en Windows).

    Si Windows la tiene bloqueada (WinError 32: VS Code, una terminal con cd ahí,
    Copilot, antivirus...) reintenta con espera creciente. Devuelve True si la
    carpeta quedó borrada y False si sigue existiendo; NO lanza excepción por bloqueo,
    para que el llamador decida qué hacer (y no se rompa el flujo de la bitácora).
    """
    path = Path(path)

    def _handler(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)   # arregla solo-lectura; un bloqueo real lo gestiona el bucle
        func(p)

    for attempt in range(1, retries + 1):
        if not path.exists():
            return True
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=_handler)
            else:
                shutil.rmtree(path, onerror=_handler)
        except OSError:
            if attempt < retries:
                time.sleep(delay * attempt)
        if not path.exists():
            return True
    return not path.exists()