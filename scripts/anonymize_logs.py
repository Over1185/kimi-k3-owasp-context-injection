#!/usr/bin/env python3
"""Revisa (y opcionalmente limpia) datos personales en los archivos del repositorio.

Qué detecta y reemplaza:
  - El nombre de usuario dentro de rutas de Windows/macOS (C:\\Users\\NOMBRE, file:///c%3A/Users/NOMBRE,
    /Users/NOMBRE)  ->  <USER>
  - Los términos personales de .anonymize_terms.txt (nombre completo, correo, nombre del equipo...)
    ->  <REDACTED>     (un término por línea; ese archivo NO se sube a GitHub)

Qué solo AVISA (no modifica): correos y posibles tokens/claves (ghp_..., sk-..., AKIA...).

Por defecto es una REVISIÓN (no cambia nada) y termina con código 1 si hay algo que limpiar,
así que sirve como comprobación previa a publicar. Con --apply reescribe los archivos.

Los fragmentos (fragments/) son datos primarios: se revisan pero NO se modifican salvo que
los pases explícitamente con --paths fragments.

Uso:
    python scripts/anonymize_logs.py                 # revisar
    python scripts/anonymize_logs.py --apply         # limpiar chat_logs/, data/ y sast_reports/
    python scripts/anonymize_logs.py --paths chat_logs --apply
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from common import ROOT, anonymize_text, load_terms, log_event, sha256

DEFAULT_PATHS = ["chat_logs", "data", "sast_reports"]
READ_ONLY_PATHS = ["fragments"]
TEXT_EXT = {".json", ".md", ".txt", ".csv", ".py", ".yml", ".yaml"}
WARN_PATTERNS = {
    "correo": re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"),
    "token GitHub": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    "clave tipo sk-": re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    "clave AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}


def iter_files(folder: Path):
    if not folder.exists():
        return
    for p in sorted(folder.rglob("*")):
        if p.is_file() and p.suffix.lower() in TEXT_EXT and p.name != ".gitkeep":
            yield p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="reescribe los archivos (sin esto solo revisa)")
    ap.add_argument("--paths", nargs="+", help="carpetas a procesar (por defecto: chat_logs data sast_reports)")
    args = ap.parse_args()

    terms = load_terms()
    modify = args.paths or DEFAULT_PATHS
    targets = [(f, True) for f in modify] + [(f, False) for f in READ_ONLY_PATHS if f not in modify]

    pending = 0     # archivos con algo que limpiar
    cleaned = 0
    warnings = 0
    for folder_name, may_modify in targets:
        for path in iter_files(ROOT / folder_name):
            rel = path.relative_to(ROOT)
            try:
                text = path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                print(f"AVISO: {rel} no es UTF-8; se omite")
                continue
            new, counts = anonymize_text(text, terms)
            for label, pat in WARN_PATTERNS.items():
                n = len(pat.findall(new))
                if n:
                    warnings += n
                    print(f"AVISO: {rel}: {n} posible(s) {label} (revisar a mano)")
            if not counts:
                continue
            pending += 1
            resumen = ", ".join(f"{k}×{v}" for k, v in counts.items())
            if not may_modify:
                print(f"REVISAR A MANO: {rel} contiene datos personales ({resumen}); es un dato primario "
                      f"y no se modifica automáticamente.")
                continue
            if args.apply:
                if path.suffix.lower() == ".json":
                    try:
                        json.loads(text)
                        json.loads(new)
                    except ValueError:
                        print(f"ERROR: {rel}: la limpieza dejaría el JSON inválido; no se modificó.")
                        continue
                path.write_bytes(new.encode("utf-8"))
                cleaned += 1
                log_event(str(rel).replace("\\", "/"), "ANONIMIZADO",
                          f"reemplazos={sum(counts.values())}; sha256={sha256(path)[:16]}")
                print(f"LIMPIADO: {rel} ({resumen})")
            else:
                print(f"POR LIMPIAR: {rel} ({resumen})")

    if args.apply:
        print(f"\nArchivos limpiados: {cleaned}. Avisos pendientes de revisión manual: {warnings}.")
        return 0
    if pending:
        print(f"\n{pending} archivo(s) con datos personales. Ejecuta de nuevo con --apply.")
        return 1
    print(f"\nSin datos personales detectados. Avisos de revisión manual: {warnings}.")
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
