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
N_ITERATIONS = 5
FRAGMENT_RE = re.compile(r"^(E\d{2})_(control|experimental)_iter(\d+)$")


def load_protocol() -> dict:
    return json.loads((PROTOCOL / "prompts.json").read_text(encoding="utf-8"))


def scenarios() -> dict[str, dict]:
    return {s["id"]: s for s in load_protocol()["scenarios"]}


def fragment_id(scenario: str, group: str, iteration: int) -> str:
    return f"{scenario}_{group}_iter{iteration}"


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
