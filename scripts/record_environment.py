#!/usr/bin/env python3
"""Registra AUTOMÁTICAMENTE el entorno experimental en data/environment_versions.csv.

Cada vez que se llama (prepare_workspace.py lo hace en cada corrida) toma una "foto" del entorno:
  - versión de VS Code (commit y arquitectura), versión de GitHub Copilot Chat y TODAS las
    extensiones instaladas en el perfil (sirve para demostrar que el perfil está limpio)
  - versiones de Python, Bandit, Semgrep y pip-audit
  - huella (SHA-256) del protocolo: prompts, entorno esperado, mapeo de reglas, ajustes del perfil,
    archivos de contexto y ruleset de Semgrep
  - modelo, razonamiento y agente que se esperan (protocol/expected_environment.json)
y la compara con la última fila. SOLO agrega una fila nueva si algo cambió, y te dice qué cambió.
Así el archivo es un historial de cambios del entorno, no 100 filas idénticas.

Lo que NO se puede leer automáticamente: la versión interna de Kimi K3 en GitHub (el selector solo
muestra "Kimi K3"). Si GitHub anuncia un cambio del modelo, anótalo en la columna nota_manual.

Uso:
    python scripts/record_environment.py                    # foto + registro si cambió
    python scripts/record_environment.py --profile Experimento --force
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import platform
import shutil
import subprocess
import sys

from common import CONTEXT_FILES, DATA, PROTOCOL, load_expected_env, sha256, utc_now

CSV_PATH = DATA / "environment_versions.csv"
COLUMNS = ["fecha_utc", "version_vscode", "commit_vscode", "arquitectura", "version_copilot_chat",
           "extensiones_perfil", "python", "bandit", "semgrep", "pip_audit", "ruleset_semgrep_sha",
           "huella_protocolo", "modelo_esperado", "razonamiento_esperado", "agente_esperado", "nota_manual"]
IGNORED_FOR_COMPARISON = {"fecha_utc", "nota_manual"}


def run(cmd: list[str], timeout: int = 90) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip() or (r.stderr or "").strip()
        return out
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {type(e).__name__}"


def first_line(text: str) -> str:
    return text.splitlines()[0].strip() if text else "no_disponible"


def protocol_fingerprint() -> str:
    h = hashlib.sha256()
    files = sorted([p for p in PROTOCOL.glob("*.json")] + [p for p in CONTEXT_FILES.rglob("*") if p.is_file()])
    for p in files:
        h.update(p.name.encode())
        h.update(sha256(p).encode())
    return h.hexdigest()[:16]


def snapshot(profile: str) -> dict:
    env = load_expected_env()
    code = shutil.which("code")
    row = {c: "" for c in COLUMNS}
    row["fecha_utc"] = utc_now()
    if code:
        v = run([code, "--version"]).splitlines()
        row["version_vscode"] = v[0].strip() if len(v) > 0 else "no_disponible"
        row["commit_vscode"] = v[1].strip()[:12] if len(v) > 1 else ""
        row["arquitectura"] = v[2].strip() if len(v) > 2 else ""
        exts_raw = run([code, "--list-extensions", "--show-versions", "--profile", profile])
        exts = sorted(l.strip() for l in exts_raw.splitlines() if "@" in l)
        row["extensiones_perfil"] = ";".join(exts) if exts else f"sin_extensiones_o_error: {first_line(exts_raw)[:80]}"
        chat = [e for e in exts if e.lower().startswith("github.copilot-chat@")]
        row["version_copilot_chat"] = chat[0].split("@", 1)[1] if chat else "no_instalado_en_el_perfil"
    else:
        for k in ("version_vscode", "commit_vscode", "arquitectura", "version_copilot_chat", "extensiones_perfil"):
            row[k] = "code_no_encontrado_en_PATH"
    row["python"] = platform.python_version()
    row["bandit"] = first_line(run([sys.executable, "-m", "bandit", "--version"]))
    row["semgrep"] = first_line(run(["semgrep", "--version"]))
    row["pip_audit"] = first_line(run(["pip-audit", "--version"]))
    rules = PROTOCOL / "semgrep_rules" / "owasp-top-ten.yml"
    row["ruleset_semgrep_sha"] = sha256(rules)[:12] if rules.is_file() else "sin_ruleset_local"
    row["huella_protocolo"] = protocol_fingerprint()
    row["modelo_esperado"] = env["model_substring"]
    row["razonamiento_esperado"] = env["reasoning"]
    row["agente_esperado"] = env["agent_id"]
    return row


def read_rows() -> list[dict]:
    if not CSV_PATH.is_file():
        return []
    with CSV_PATH.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != COLUMNS:       # formato antiguo: se conserva como copia
            backup = CSV_PATH.with_suffix(".old.csv")
            f.close()
            CSV_PATH.replace(backup)
            print(f"AVISO: el formato de {CSV_PATH.name} era distinto; copia guardada como {backup.name}")
            return []
        return list(reader)


def record_environment(profile: str, force: bool = False, quiet: bool = False) -> tuple[dict, list[str]]:
    """Devuelve (fila, lista_de_cambios). Agrega la fila al CSV solo si hubo cambios (o force)."""
    DATA.mkdir(exist_ok=True)
    row = snapshot(profile)
    rows = read_rows()
    changes: list[str] = []
    if rows:
        last = rows[-1]
        changes = [f"{k}: {last.get(k, '')!s} -> {row[k]!s}" for k in COLUMNS
                   if k not in IGNORED_FOR_COMPARISON and last.get(k, "") != row[k]]
    if rows and not changes and not force:
        if not quiet:
            print(f"Entorno sin cambios desde {rows[-1]['fecha_utc']}.")
        return row, changes
    new_file = not CSV_PATH.is_file()
    with CSV_PATH.open("a", newline="", encoding="utf-8-sig" if new_file else "utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow(row)
    if not quiet:
        if rows:
            print("EL ENTORNO CAMBIÓ desde la última corrida; se agregó una fila a environment_versions.csv:")
            for c in changes:
                print("   -", c)
            print("   Anótalo en la bitácora y, si ocurrió a mitad de un escenario, reinicia sus iteraciones "
                  "restantes (3.6.2.1-g).")
        else:
            print("Primer registro del entorno guardado en data/environment_versions.csv.")
    return row, changes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", default="Experimento", help="perfil de VS Code a inspeccionar")
    ap.add_argument("--force", action="store_true", help="agrega la fila aunque no haya cambios")
    args = ap.parse_args()
    record_environment(args.profile, args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
