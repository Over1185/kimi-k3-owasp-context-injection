#!/usr/bin/env python3
"""Ejecuta Bandit, Semgrep y pip-audit sobre los fragmentos y guarda los JSON CRUDOS.

- Bandit y Semgrep: sobre cada fragments/<grupo>/<ID>.py
- pip-audit: solo sobre el requirements.txt del escenario E03
- Además hace una comprobación de versiones fijadas (pins) en E03, porque pip-audit
  no reporta dependencias sin versión fijada.

NUNCA edites los JSON de sast_reports/: las correcciones van en la matriz de registro.

Uso:
    python scripts/run_sast.py                      # todos los fragmentos pendientes
    python scripts/run_sast.py --group control --only E05
    python scripts/run_sast.py --force              # re-escanea aunque exista el reporte

En Windows, Semgrep funciona mejor desde WSL o Docker.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common import FRAGMENT_RE, FRAGMENTS, GROUPS, PROTOCOL, ROOT, SAST_REPORTS, log_event, utc_now

PIN_RE = re.compile(r"^[A-Za-z0-9_.\-]+(\[[A-Za-z0-9_,\-]+\])?==[^\s;,]+")


def tool_version(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=60)
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except Exception as e:  # noqa: BLE001
        return f"no disponible ({e})"


def run_bandit(frag: Path, out: Path) -> str | None:
    r = subprocess.run([sys.executable, "-m", "bandit", "-f", "json", "-o", str(out), str(frag)],
                       capture_output=True, text=True)
    # Bandit devuelve 1 cuando encuentra hallazgos: no es un error.
    if r.returncode not in (0, 1) or not out.exists():
        return f"bandit falló (código {r.returncode}): {r.stderr.strip()[:500]}"
    return None


def run_semgrep(frag: Path, out: Path, config: str) -> str | None:
    exe = shutil.which("semgrep")
    if not exe:
        return "semgrep no está instalado o no está en el PATH"
    r = subprocess.run([exe, "scan", "--config", config, "--json", "--output", str(out),
                        "--metrics=off", "--disable-version-check", "--no-git-ignore", "--quiet",
                        str(frag)], capture_output=True, text=True)
    if r.returncode not in (0, 1) or not out.exists():
        return f"semgrep falló (código {r.returncode}): {r.stderr.strip()[:500]}"
    return None


def run_pip_audit(req: Path, out: Path) -> str | None:
    exe = shutil.which("pip-audit")
    if not exe:
        return "pip-audit no está instalado o no está en el PATH"
    r = subprocess.run([exe, "-r", str(req), "-f", "json", "-o", str(out), "--progress-spinner", "off"],
                       capture_output=True, text=True)
    if not out.exists() or out.stat().st_size == 0:
        return f"pip-audit no produjo reporte (código {r.returncode}): {r.stderr.strip()[:800]}"
    return None


def check_pins(req: Path, out: Path) -> None:
    items = []
    for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "://" in line or " @ " in line:
            items.append({"requirement": line, "pinned": False, "reason": "URL_SIN_HASH"})
        elif PIN_RE.match(line):
            items.append({"requirement": line, "pinned": True, "reason": ""})
        else:
            items.append({"requirement": line, "pinned": False, "reason": "SIN_VERSION_FIJADA"})
    out.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--group", choices=[*GROUPS, "all"], default="all")
    ap.add_argument("--only", help="limitar a un escenario, p. ej. E05")
    ap.add_argument("--force", action="store_true", help="re-escanear aunque ya exista el reporte")
    args = ap.parse_args()

    local_rules = PROTOCOL / "semgrep_rules" / "owasp-top-ten.yml"
    if local_rules.is_file():
        semgrep_cfg = str(local_rules)
    else:
        semgrep_cfg = "p/owasp-top-ten"
        print("AVISO: no hay ruleset local congelado; uso 'p/owasp-top-ten' del registro "
              "(ver protocol/sast_config.md).")

    for sub in ("bandit", "semgrep", "pip_audit"):
        (SAST_REPORTS / sub).mkdir(parents=True, exist_ok=True)

    info = {"fecha_utc": utc_now(), "semgrep_config": semgrep_cfg,
            "bandit": tool_version([sys.executable, "-m", "bandit"]),
            "semgrep": tool_version(["semgrep"]), "pip-audit": tool_version(["pip-audit"])}
    (SAST_REPORTS / "_run_info.json").write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Herramientas:", json.dumps(info, ensure_ascii=False))

    groups = GROUPS if args.group == "all" else (args.group,)
    fragments = sorted(p for g in groups for p in (FRAGMENTS / g).glob("*.py") if FRAGMENT_RE.match(p.stem))
    if args.only:
        fragments = [p for p in fragments if p.stem.startswith(args.only + "_")]
    if not fragments:
        print("No hay fragmentos para escanear.")
        return 0

    errors = 0
    for frag in fragments:
        fid = frag.stem
        scenario = fid.split("_")[0]
        todo = []
        b_out = SAST_REPORTS / "bandit" / f"{fid}.json"
        s_out = SAST_REPORTS / "semgrep" / f"{fid}.json"
        if args.force or not b_out.exists():
            todo.append(("bandit", lambda: run_bandit(frag, b_out)))
        if args.force or not s_out.exists():
            todo.append(("semgrep", lambda: run_semgrep(frag, s_out, semgrep_cfg)))
        if scenario == "E03":
            req = frag.with_name(f"{fid}_requirements.txt")
            p_out = SAST_REPORTS / "pip_audit" / f"{fid}.json"
            if not req.is_file():
                print(f"[{fid}] ERROR: falta {req.name}")
                errors += 1
            else:
                check_pins(req, SAST_REPORTS / "pip_audit" / f"{fid}.pins.json")
                if args.force or not p_out.exists():
                    todo.append(("pip-audit", lambda: run_pip_audit(req, p_out)))
        for name, fn in todo:
            err = fn()
            if err:
                errors += 1
                err_path = SAST_REPORTS / ("pip_audit" if name == "pip-audit" else name) / f"{fid}.error.txt"
                err_path.write_text(err, encoding="utf-8")
                log_event(fid, "SAST_ERROR", f"{name}: {err[:200]}")
                print(f"[{fid}] {name}: ERROR -> {err_path.relative_to(ROOT)}")
            else:
                log_event(fid, "SAST_OK", name)
                print(f"[{fid}] {name}: ok")
    if errors:
        print(f"\nTerminó con {errors} error(es). Revísalos y regístralos en la bitácora (contingencia 3.7).")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
