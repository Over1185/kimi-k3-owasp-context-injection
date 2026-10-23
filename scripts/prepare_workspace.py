#!/usr/bin/env python3
"""Prepara la carpeta desechable de UNA corrida (procedimiento 3.6.2.1-a del plan).

La carpeta se crea FUERA del repositorio, con git inicializado y un commit base.
- Grupo experimental: incluye AGENTS.md, .github/copilot-instructions.md y
  .github/skills/owasp-mitigacion/SKILL.md (copiados de context_files/, verificados por hash).
- Grupo control: sin ningún archivo de contexto.
En ambos grupos se copia .vscode/settings.json (mismo contenido) para que la única
diferencia entre grupos sea el contexto.

Carpeta creada (por defecto): ~/owasp_runs/<grupo>/<escenario>/iter<N>
    p. ej. C:\\Users\\Over\\owasp_runs\\experimental\\E05\\iter2
Con --neutral se usa la ruta neutra ~/trabajo/app (sin pistas en la ruta).

Uso:
    python scripts/prepare_workspace.py --scenario E05 --group experimental --iter 2
    python scripts/prepare_workspace.py --scenario E05 --group control --iter 1 --open
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

import json

from common import (CONTEXT_FILES, DEFAULT_BASE, GROUPS, N_ITERATIONS, ROOT,
                    fragment_id, load_protocol, log_event, resolve_workspace, rmtree_force,
                    scenarios, sha256, utc_now)

# origen (dentro de context_files/)  ->  destino (dentro de la carpeta desechable)
CONTEXT_MAP = {
    "AGENTS.md": "AGENTS.md",
    "copilot-instructions.md": ".github/copilot-instructions.md",
    "skills/owasp-mitigacion/SKILL.md": ".github/skills/owasp-mitigacion/SKILL.md",
}


def git(ws: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=ws, check=True, capture_output=True, text=True)


def find_code_cli() -> str | None:
    """Localiza el ejecutable de VS Code: primero el PATH y luego rutas típicas de Windows."""
    found = shutil.which("code") or shutil.which("code.cmd")
    if found:
        return found
    candidates = []
    for env, rel in (("LOCALAPPDATA", r"Programs\Microsoft VS Code\bin\code.cmd"),
                     ("ProgramFiles", r"Microsoft VS Code\bin\code.cmd"),
                     ("ProgramFiles(x86)", r"Microsoft VS Code\bin\code.cmd")):
        base = os.environ.get(env)
        if base:
            candidates.append(Path(base) / rel)
    return next((str(c) for c in candidates if c.is_file()), None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True, help="E01 ... E10")
    ap.add_argument("--group", required=True, choices=GROUPS)
    ap.add_argument("--iter", type=int, required=True, dest="iteration", help="1 ... 5")
    ap.add_argument("--base", default=None,
                    help=f"carpeta base, FUERA del repositorio (default: {DEFAULT_BASE}; con --neutral: ~/trabajo)")
    ap.add_argument("--neutral", action="store_true",
                    help="usa la ruta NEUTRA <base>/app (sin 'owasp', grupo ni escenario en la ruta que ve el modelo)")
    ap.add_argument("--profile", default="Experimento", help="perfil de VS Code a usar con --open")
    ap.add_argument("--open", action="store_true", help="abre la carpeta en VS Code con ese perfil")
    ap.add_argument("--force", action="store_true", help="si la carpeta existe, la borra y la recrea")
    ap.add_argument("--no-env", action="store_true", help="no registrar el entorno en environment_versions.csv")
    args = ap.parse_args()

    scn = scenarios()
    if args.scenario not in scn:
        sys.exit(f"Escenario desconocido: {args.scenario} (válidos: {', '.join(scn)})")
    if not 1 <= args.iteration <= N_ITERATIONS:
        sys.exit(f"La iteración debe estar entre 1 y {N_ITERATIONS}")

    base, ws, marker = resolve_workspace(args.base, args.group, args.scenario, args.iteration, args.neutral)
    if base == ROOT or ROOT in base.parents:
        sys.exit("La carpeta base NO puede estar dentro del repositorio de investigación.")

    fid = fragment_id(args.scenario, args.group, args.iteration)
    if not args.neutral:
        print("AVISO: la ruta del workspace contiene el grupo/escenario (y 'owasp_runs'); el modelo puede leerla.\n"
              "       Si quieres una ruta sin pistas, usa --neutral.")
    if ws.exists():
        if not args.force:
            sys.exit(f"{ws} ya existe (¿corrida anterior sin recoger?). Ejecuta collect_run.py o "
                     f"usa --force para recrearla.")
        rmtree_force(ws)
    ws.mkdir(parents=True)
    # Qué corrida está en curso (fuera del workspace, para que el modelo no lo vea)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(
        {"id": fid, "scenario": args.scenario, "group": args.group, "iter": args.iteration,
         "created_utc": utc_now(), "layout": "neutral" if args.neutral else "organized"}), encoding="utf-8")

    # Archivos de contexto solo en el grupo experimental
    hashes = []
    if args.group == "experimental":
        for src_rel, dst_rel in CONTEXT_MAP.items():
            src, dst = CONTEXT_FILES / src_rel, ws / dst_rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            if sha256(src) != sha256(dst):
                sys.exit(f"Error de copia: el hash de {dst_rel} no coincide con el original.")
            hashes.append(f"{dst_rel}={sha256(dst)[:12]}")
    else:
        for dst_rel in CONTEXT_MAP.values():
            if (ws / dst_rel).exists():
                sys.exit(f"Contaminación: {dst_rel} existe en una carpeta de control.")

    # Repositorio git limpio con commit base (permite detectar archivos extra después)
    git(ws, "init", "-q")
    git(ws, "config", "user.name", "experimento")
    git(ws, "config", "user.email", "experimento@example.invalid")
    git(ws, "add", "-A")
    git(ws, "commit", "-q", "--allow-empty", "-m", "baseline")

    log_event(fid, "PREPARADO", f"contexto={';'.join(hashes) or 'ninguno'}")

    if not args.no_env:
        from record_environment import record_environment
        record_environment(args.profile)

    proto = load_protocol()
    scope = proto["scope_instruction_E03"] if args.scenario == "E03" else proto["scope_instruction"]
    full_prompt = f"{scn[args.scenario]['prompt']} {scope}"

    print(f"\nCarpeta lista: {ws}   (corrida {fid})\n")
    print("PASOS (modo Agent, Kimi K3, nivel de razonamiento máximo, chat NUEVO):")
    print("  0. Registra en la bitácora/environment_versions.csv las versiones (si es inicio de bloque).")
    print("  1. Abre SOLO esta carpeta en VS Code (perfil limpio, con los ajustes de protocol/profile_settings.json).")
    print("  2. Envía el prompt de VERIFICACIÓN y anota el resultado en la bitácora:")
    print(f"\n     {proto['verification_prompt']}\n")
    print("     Experimental: debe listar las directrices Y la skill 'owasp-mitigacion'.")
    print("     Control: debe indicar que NO hay convenciones ni skills. Si no se cumple -> descarta:")
    print(f"        python scripts/collect_run.py --scenario {args.scenario} --group {args.group} "
          f"--iter {args.iteration}{' --neutral' if args.neutral else ''} --discard \"verificacion fallida\"")
    print("  3. En el MISMO chat, envía el prompt del escenario:\n")
    print(f"     {full_prompt}\n")
    print("  4. Rechaza cualquier acción fuera de scenario.py (y requirements.txt en E03).")
    print("  5. Exporta el chat (comando 'Chat: Export Chat...') y luego ejecuta:")
    print(f"        python scripts/collect_run.py --scenario {args.scenario} --group {args.group} "
          f"--iter {args.iteration}{' --neutral' if args.neutral else ''} --verification ok\n")
    print("     (exporta el chat a ~/owasp_runs/_export/chat.json; si lo guardas en otro sitio añade --chat-json RUTA)\n")

    if args.open:
        code = find_code_cli()
        if not code:
            print("(No encontré VS Code (comando 'code'); abre la carpeta manualmente con el perfil indicado.)")
        else:
            subprocess.Popen([code, "--profile", args.profile, str(ws)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
