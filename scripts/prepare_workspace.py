#!/usr/bin/env python3
"""Prepara la carpeta desechable de UNA corrida (procedimiento 3.6.2.1-a del plan).

La carpeta se crea FUERA del repositorio, con git inicializado y un commit base.
- Grupo experimental: incluye AGENTS.md, .github/copilot-instructions.md y
  .github/skills/owasp-mitigacion/SKILL.md (copiados de context_files/, verificados por hash).
- Grupo control: sin ningún archivo de contexto.
En ambos grupos se copia .vscode/settings.json (mismo contenido) para que la única
diferencia entre grupos sea el contexto.

La carpeta es SIEMPRE ~/trabajo/app (ruta neutra: el modelo la lee, así que no lleva "owasp",
grupo ni escenario). Cada preparación borra la carpeta de la corrida anterior.

Antes de crear nada, revisa data/run_log.csv: si esa corrida (escenario + grupo + iteración) ya
fue recogida con éxito, se niega a prepararla otra vez (usa --redo para repetirla a propósito).

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

from datetime import datetime

from common import (CONTEXT_FILES, DEFAULT_BASE, DEFAULT_EXPORT_DIR, FRAGMENTS, GROUPS, N_ITERATIONS, ROOT,
                    fragment_id, load_protocol, log_event, log_incident, resolve_workspace, rmtree_force,
                    run_status, scenarios, sha256, utc_now)

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
                    help=f"carpeta base, FUERA del repositorio y con nombre neutro (default: {DEFAULT_BASE})")
    ap.add_argument("--redo", action="store_true",
                    help="permite preparar una corrida que ya fue recogida (repetición deliberada; "
                         "collect_run.py sobrescribirá el fragmento)")
    ap.add_argument("--profile", default="Experimento", help="perfil de VS Code a usar con --open")
    ap.add_argument("--open", action="store_true", help="abre la carpeta en VS Code con ese perfil")
    # Opciones antiguas, ya sin efecto (se aceptan para no romper comandos previos)
    ap.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--neutral", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--no-env", action="store_true", help="no registrar el entorno en environment_versions.csv")
    ap.add_argument("--menu", action="store_true", help=argparse.SUPPRESS)   # lo usa scripts/menu.py
    args = ap.parse_args()

    scn = scenarios()
    if args.scenario not in scn:
        sys.exit(f"Escenario desconocido: {args.scenario} (válidos: {', '.join(scn)})")
    if not 1 <= args.iteration <= N_ITERATIONS:
        sys.exit(f"La iteración debe estar entre 1 y {N_ITERATIONS}")

    base, ws, marker = resolve_workspace(args.base)
    if base == ROOT or ROOT in base.parents:
        sys.exit("La carpeta base NO puede estar dentro del repositorio de investigación.")

    fid = fragment_id(args.scenario, args.group, args.iteration)

    # --- 1. Evitar solapamiento: ¿esta corrida ya está hecha? (data/run_log.csv + fragmento guardado)
    status = run_status(fid)
    frag = FRAGMENTS / args.group / f"{fid}.py"
    if (status == "recogido" or frag.exists()) and not args.redo:
        sys.exit(f"La corrida {fid} YA está hecha (run_log: {status}; fragmento: "
                 f"{'existe' if frag.exists() else 'no existe'}). No se prepara para evitar solapamientos.\n"
                 f"Si de verdad quieres repetirla, usa --redo (queda anotado en la bitácora).")
    if args.redo and (status == "recogido" or frag.exists()):
        print(f"AVISO: repitiendo la corrida {fid} (--redo); al recogerla se sobrescribirá el fragmento.")
        log_incident(fid, "REPETICION_AUTORIZADA", "corrida ya recogida, preparada de nuevo con --redo",
                     "Repetición deliberada; el fragmento previo se sobrescribirá al recoger")
    elif status == "preparado":
        print(f"AVISO: {fid} fue preparada antes y nunca se recogió ni se descartó; se prepara de nuevo.")

    # --- 2. Limpiar la corrida anterior (carpeta desechable + export de chat viejo)
    if ws.exists():
        prev = "desconocida"
        if marker.is_file():
            try:
                prev = json.loads(marker.read_text(encoding="utf-8")).get("id", prev)
            except ValueError:
                pass
        if prev != "desconocida" and run_status(prev) == "preparado":
            msg = f"carpeta de {prev} borrada sin haberse recogido ni descartado"
            print(f"AVISO: {msg}. Quedó anotado en run_log.csv y en la bitácora.")
            log_incident(prev, "ABANDONADA_AL_PREPARAR", f"{msg} al preparar {fid}",
                         "Carpeta borrada; la corrida debe repetirse")
        if not rmtree_force(ws):
            sys.exit(f"No se pudo borrar la carpeta anterior {ws}: está en uso por otro proceso.\n"
                     "Cierra VS Code, terminales y cualquier programa que la tenga abierta, y vuelve a intentarlo.")
        print(f"Carpeta anterior borrada: {ws} (corrida {prev})")
    old_chat = DEFAULT_EXPORT_DIR / "chat.json"
    if old_chat.is_file():
        arch = DEFAULT_EXPORT_DIR / "anteriores"
        arch.mkdir(parents=True, exist_ok=True)
        stamp = datetime.fromtimestamp(old_chat.stat().st_mtime).strftime("%Y%m%d_%H%M%S")
        shutil.move(str(old_chat), str(arch / f"chat_{stamp}.json"))
        print(f"Export de chat anterior archivado en {arch} (así no se confunde con el de esta corrida).")

    ws.mkdir(parents=True)
    # Qué corrida está en curso (fuera del workspace, para que el modelo no lo vea)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(
        {"id": fid, "scenario": args.scenario, "group": args.group, "iter": args.iteration,
         "created_utc": utc_now(), "redo": bool(args.redo)}), encoding="utf-8")

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
    if not args.menu:   # el menú (scripts/menu.py) muestra los pasos uno a uno
        print("PASOS (modo Agent, Kimi K3, nivel de razonamiento máximo, chat NUEVO):")
        print("  0. Registra en la bitácora/environment_versions.csv las versiones (si es inicio de bloque).")
        print("  1. Abre SOLO esta carpeta en VS Code (perfil limpio, con los ajustes de protocol/profile_settings.json).")
        print("  2. Envía el prompt de VERIFICACIÓN y anota el resultado en la bitácora:")
        print(f"\n     {proto['verification_prompt']}\n")
        print("     Experimental: debe listar las directrices Y la skill 'owasp-mitigacion'.")
        print("     Control: debe indicar que NO hay convenciones ni skills. Si no se cumple -> descarta:")
        print(f"        python scripts/collect_run.py --scenario {args.scenario} --group {args.group} "
              f"--iter {args.iteration} --discard \"verificacion fallida\"")
        print("  3. En el MISMO chat, envía el prompt del escenario:\n")
        print(f"     {full_prompt}\n")
        print("  4. Rechaza cualquier acción fuera de scenario.py (y requirements.txt en E03).")
        print("  5. Exporta el chat (comando 'Chat: Export Chat...') y luego ejecuta:")
        print(f"        python scripts/collect_run.py --scenario {args.scenario} --group {args.group} "
              f"--iter {args.iteration} --verification ok\n")
        print(f"     (guarda el export como {DEFAULT_EXPORT_DIR / 'chat.json'}; si lo guardas en otro sitio añade --chat-json RUTA)\n")

    if args.open:
        code = find_code_cli()
        if not code:
            print("(No encontré VS Code (comando 'code'); abre la carpeta manualmente con el perfil indicado.)")
        else:
            subprocess.Popen([code, "--profile", args.profile, str(ws)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
