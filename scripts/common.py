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

# --- Diseño ORGANIZADO (por defecto): <base>/<grupo>/<escenario>/iter<N>
#     p. ej. C:\Users\Over\owasp_runs\experimental\E05\iter2
# --- Diseño NEUTRO (--neutral): <base>/app, con base ~/trabajo (ruta sin pistas para el modelo)
DEFAULT_BASE = Path.home() / "owasp_runs"
DEFAULT_EXPORT_DIR = DEFAULT_BASE / "_export"
DEFAULT_CHAT_JSON = DEFAULT_EXPORT_DIR / "chat.json"   # export del chat por defecto en collect_run.py
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


def resolve_workspace(base_arg, group: str, scenario: str, iteration: int, neutral: bool):
    """Devuelve (base, carpeta_de_trabajo, archivo_marcador) según el diseño elegido.

    El marcador (qué corrida está en curso) va SIEMPRE fuera de la carpeta de trabajo,
    para que git no lo vea como archivo extra y el modelo no lo lea.
    """
    fid = fragment_id(scenario, group, iteration)
    if neutral:
        base = Path(base_arg or (Path.home() / DEFAULT_BASE_NAME)).expanduser().resolve()
        return base, base / WORKSPACE_NAME, base / "_current.json"
    base = Path(base_arg or DEFAULT_BASE).expanduser().resolve()
    return base, base / group / scenario / f"iter{iteration}", base / "_runs" / f"{fid}.json"


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


def rmtree_force(path: Path) -> None:
    """Borra una carpeta incluso si tiene archivos de solo lectura (.git en Windows)."""

    def _handler(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_handler)
    else:
        shutil.rmtree(path, onerror=_handler)
