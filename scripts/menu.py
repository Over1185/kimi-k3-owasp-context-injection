#!/usr/bin/env python3
"""Menú interactivo para ejecutar las corridas del experimento paso a paso.

    python scripts/menu.py

Flujo:
  1. Muestra el progreso global y te deja elegir el ESCENARIO.
  2. Muestra qué corridas ya están hechas de ese escenario (por grupo e iteración).
  3. Eliges GRUPO e ITERACIÓN (te sugiere la primera pendiente).
  4. Prepara la carpeta y te guía en 5 PASOS SECUENCIALES: muestra un paso, te pregunta si salió
     bien y solo entonces pasa al siguiente (si la verificación falla, ofrece descartar).
  5. Tras el último paso recoge los datos (collect_run.py). Si la corrida resulta inválida te
     ofrece descartar, reintentar o aceptarla con justificación.
  Si pausas (M), al volver a elegir la corrida se retoma en el paso donde la dejaste.

El menú solo orquesta los scripts existentes: todo lo que hacen (validaciones, bitácora
automática, limpieza) sigue igual.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from common import (DATA, DEFAULT_CHAT_JSON, FRAGMENTS, GROUPS, N_ITERATIONS, ROOT, fragment_id,
                    load_protocol, log_incident, resolve_workspace, run_status, scenarios)

SCRIPTS = Path(__file__).resolve().parent
PY = sys.executable

# Símbolos ASCII (la consola de Windows puede no soportar emojis)
SYMBOLS = {"hecha": "[OK]", "hecha_sin_ok": "[ ? ]", "en curso": "[>>]", "descartada": "[X ]", "pendiente": "[  ]"}


# ----------------------------------------------------------------------------- utilidades
def out(msg: str = "") -> None:
    print(msg, flush=True)


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        ans = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        out("\nSaliendo del menú.")
        raise SystemExit(0)
    return ans or (default or "")


def yes(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    ans = ask(f"{prompt} ({d})").lower()
    if not ans:
        return default
    return ans in ("y", "s", "si", "sí", "yes")


def choose(prompt: str, valid: list[str], default: str | None = None) -> str:
    while True:
        ans = ask(prompt, default).lower()
        if ans in valid:
            return ans
        out(f"  Opción no válida. Elige una de: {', '.join(valid)}")


def last_recogido_detail(fid: str) -> str | None:
    path = DATA / "run_log.csv"
    if not path.is_file():
        return None
    detail = None
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("id_fragmento") == fid:
                if row.get("evento") == "RECOGIDO":
                    detail = row.get("detalle", "")
                elif row.get("evento") == "DESCARTADO":
                    detail = None
    return detail


def run_state(scenario: str, group: str, it: int) -> str:
    """hecha | hecha_sin_ok | en curso | descartada | pendiente"""
    fid = fragment_id(scenario, group, it)
    st = run_status(fid)
    frag = FRAGMENTS / group / f"{fid}.py"
    if st == "recogido" or frag.exists():
        detail = last_recogido_detail(fid) or ""
        return "hecha" if "verificacion=ok" in detail else "hecha_sin_ok"
    _base, ws, marker = resolve_workspace()
    if ws.is_dir() and marker.is_file():
        try:
            if json.loads(marker.read_text(encoding="utf-8")).get("id") == fid:
                return "en curso"
        except ValueError:
            pass
    if st == "descartado":
        return "descartada"
    return "pendiente"


def current_run() -> str | None:
    """ID de la corrida con carpeta de trabajo existente (preparada y sin recoger), si hay."""
    _base, ws, marker = resolve_workspace()
    if ws.is_dir() and marker.is_file():
        try:
            return json.loads(marker.read_text(encoding="utf-8")).get("id")
        except ValueError:
            return "desconocida"
    return None


def run_script(name: str, *args: str) -> int:
    cmd = [PY, str(SCRIPTS / name), *args]
    return subprocess.run(cmd, cwd=ROOT).returncode


# ----------------------------------------------------------------------------- pantallas
def show_progress(scn: dict) -> None:
    total = len(scn) * len(GROUPS) * N_ITERATIONS
    done = sum(run_state(s, g, i) in ("hecha", "hecha_sin_ok")
               for s in scn for g in GROUPS for i in range(1, N_ITERATIONS + 1))
    out(f"\n=== PROGRESO: {done}/{total} corridas hechas ===")
    out(f"{'':36} {'control':<14} {'experimental':<14}")
    for sid, s in scn.items():
        cells = []
        for g in GROUPS:
            n = sum(run_state(sid, g, i) in ("hecha", "hecha_sin_ok") for i in range(1, N_ITERATIONS + 1))
            cells.append(f"{n}/{N_ITERATIONS}")
        out(f"  {sid}  {s['category']} {s['category_name'][:28]:<28} {cells[0]:<14} {cells[1]:<14}")


def show_scenario(scn: dict, sid: str) -> None:
    s = scn[sid]
    out(f"\n--- {sid}: {s['category']} {s['category_name']} ---")
    out("   (" + "  ".join(f"{v} {k}" for k, v in SYMBOLS.items()) + ")")
    out(f"{'':14}" + "".join(f"iter{i:<5}" for i in range(1, N_ITERATIONS + 1)))
    for g in GROUPS:
        row = "".join(f"{SYMBOLS[run_state(sid, g, i)]:<9}" for i in range(1, N_ITERATIONS + 1))
        out(f"  {g:<12}{row}")


def pick_scenario(scn: dict) -> str | None:
    show_progress(scn)
    cur = current_run()
    if cur:
        out(f"\n(!) Hay una corrida preparada sin recoger: {cur}")
        out("    Elígela de nuevo para continuar, o prepara otra (la carpeta actual se borrará).")
    out("\nEscribe el escenario (E01 ... E10) o Q para salir.")
    valid = [k.lower() for k in scn] + ["q"]
    ans = choose("Escenario", valid)
    return None if ans == "q" else ans.upper()


def pick_run(scn: dict, sid: str) -> tuple[str, int] | None:
    show_scenario(scn, sid)
    out("\nGrupo: [c] control   [e] experimental   [b] volver")
    g = choose("Grupo", ["c", "e", "b"])
    if g == "b":
        return None
    group = "control" if g == "c" else "experimental"
    pend = [i for i in range(1, N_ITERATIONS + 1) if run_state(sid, group, i) in ("pendiente", "descartada", "en curso")]
    default = str(pend[0]) if pend else None
    it = int(choose(f"Iteración (1-{N_ITERATIONS})", [str(i) for i in range(1, N_ITERATIONS + 1)], default))
    return group, it


# ----------------------------------------------------------------------------- progreso de la corrida
TOTAL_STEPS = 5


def read_meta() -> dict:
    marker = resolve_workspace()[2]
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def update_meta(**kw) -> None:
    marker = resolve_workspace()[2]
    meta = read_meta()
    meta.update(kw)
    marker.write_text(json.dumps(meta), encoding="utf-8")


# ----------------------------------------------------------------------------- recogida
def wait_for_chat() -> bool:
    while not DEFAULT_CHAT_JSON.is_file():
        out(f"\nNo encuentro el export del chat en:\n  {DEFAULT_CHAT_JSON}")
        out("Expórtalo con 'Chat: Export Chat...' (formato JSON) y guárdalo con ese nombre.")
        if ask("Pulsa Enter cuando esté listo (o Q para cancelar)").lower() == "q":
            return False
    return True


def collect_flow(sid: str, group: str, it: int, ver: str) -> bool:
    """Devuelve True si la corrida quedó cerrada (recogida o descartada)."""
    fid = fragment_id(sid, group, it)
    base = ["--scenario", sid, "--group", group, "--iter", str(it)]
    if not wait_for_chat():
        return False
    extra: list[str] = []
    while True:
        out("\n>>> Recogiendo datos...\n")
        code = run_script("collect_run.py", *base, "--verification", ver, *extra)
        if code == 0:
            return True
        out(f"\nLa recogida terminó con código {code}.")
        out("  [d] descartar la corrida (se borra la carpeta y hay que repetirla)")
        out("  [r] reintentar (p. ej. después de volver a exportar el chat)")
        out("  [s] aceptar igualmente, omitiendo la validación del chat (solo si es un falso positivo)")
        out("  [q] volver al menú dejando la carpeta como está")
        opt = choose("Opción", ["d", "r", "s", "q"], "q")
        if opt == "d":
            motivo = ask("Motivo del descarte", "corrida invalida segun la validacion automatica")
            return discard_flow(base, fid, motivo)
        if opt == "s":
            just = ""
            while not just:
                just = ask("Justificación (obligatoria; quedará en la bitácora)")
            log_incident(fid, "JUSTIFICACION_SKIP_CHECK", just,
                         "Corrida aceptada pese a la validación automática; justificación del investigador")
            extra = ["--skip-chat-check"]
            continue
        if opt == "q":
            return False
        extra = []


def discard_flow(base: list[str], fid: str, motivo: str) -> bool:
    code = run_script("collect_run.py", *base, "--discard", motivo)
    return code == 0


# ----------------------------------------------------------------------------- pasos secuenciales
def step_header(k: int, title: str, fid: str) -> None:
    out("\n" + "=" * 70)
    out(f"  {fid}  |  PASO {k} de {TOTAL_STEPS}: {title}")
    out("=" * 70)


def next_or_pause(prompt: str = "Pulsa Enter para continuar al siguiente paso (M = pausar y volver al menú)") -> bool:
    """True = continuar; False = pausar."""
    ans = ask(prompt).lower()
    return ans != "m"


def yes_no_pause(prompt: str) -> str:
    """Devuelve 'y', 'n' o 'm' (pausar)."""
    return choose(f"{prompt} [y = sí, n = no, m = pausar]", ["y", "n", "m"])


def guided_steps(sid: str, group: str, it: int, opened: bool, start: int = 1) -> bool:
    """Guía la corrida paso a paso. Devuelve True si la corrida quedó cerrada (recogida/descartada)."""
    scn = scenarios()
    proto = load_protocol()
    fid = fragment_id(sid, group, it)
    base = ["--scenario", sid, "--group", group, "--iter", str(it)]
    ws = resolve_workspace()[1]
    scope = proto["scope_instruction_E03"] if sid == "E03" else proto["scope_instruction"]
    full_prompt = f"{scn[sid]['prompt']} {scope}"
    ver = read_meta().get("verification", "ok")
    step = start
    if start > 1:
        out(f"\nRetomando la corrida {fid} en el paso {start}.")

    while step <= TOTAL_STEPS:
        update_meta(menu_step=step)

        if step == 1:
            step_header(1, "Abrir la carpeta y preparar el chat", fid)
            if opened:
                out("  La carpeta ya se abrió en VS Code con el perfil 'Experimento'.")
            else:
                out(f"  Abre SOLO esta carpeta en VS Code (perfil 'Experimento'):\n     {ws}")
            out("  En el panel de chat comprueba:")
            out("    - Sesión LOCAL (no Copilot CLI), modo Agent")
            out("    - Modelo Kimi K3, nivel de razonamiento máximo")
            out("    - Chat NUEVO (sin mensajes previos)")
            out("    - Aprobación automática desactivada (tú apruebas cada acción)")
            if not next_or_pause():
                return False

        elif step == 2:
            step_header(2, "Prompt de VERIFICACIÓN", fid)
            out("  Envía este prompt en el chat nuevo:\n")
            out(f"     {proto['verification_prompt']}\n")
            if group == "experimental":
                out("  Resultado esperado (EXPERIMENTAL): debe listar las directrices Y la skill 'owasp-mitigacion'.")
            else:
                out("  Resultado esperado (CONTROL): debe indicar que NO hay convenciones ni skills.")
            ans = yes_no_pause("\n¿Salió bien la verificación?")
            if ans == "m":
                return False
            if ans == "n":
                if yes("La verificación falló: la corrida debe descartarse. ¿Descartarla ahora?", True):
                    return discard_flow(base, fid, "verificacion fallida")
                ver = "fail"
                out("  Se continuará registrando la verificación como FALLIDA (quedará anotado en la bitácora).")
            else:
                ver = "ok"
            update_meta(verification=ver)

        elif step == 3:
            step_header(3, "Prompt del ESCENARIO (en el MISMO chat)", fid)
            out("  Envía este prompt en el mismo chat de la verificación:\n")
            out(f"     {full_prompt}\n")
            ans = yes_no_pause("¿Ya lo enviaste y el agente terminó de responder?")
            if ans == "m":
                return False
            if ans == "n":
                out("  Espera a que el agente termine y vuelve a responder.")
                continue

        elif step == 4:
            step_header(4, "Control de alcance", fid)
            allowed = "scenario.py" + (" y requirements.txt" if sid == "E03" else "")
            out(f"  El agente solo puede crear {allowed}.")
            out("  Debes haber DENEGADO/OMITIDO cualquier otra acción (sobre todo el terminal) y NO haber")
            out("  ejecutado ni probado el código generado.")
            ans = yes_no_pause("\n¿Cumpliste esto (denegaste todo lo que estaba fuera de alcance)?")
            if ans == "m":
                return False
            if ans == "n":
                out("  Si aprobaste un comando o se ejecutó código, la corrida es inválida.")
                if yes("¿Descartarla ahora?", True):
                    return discard_flow(base, fid, "se aprobo o ejecuto una accion fuera de alcance")
                out("  Se continúa: la validación automática del chat revisará lo ocurrido.")

        elif step == 5:
            step_header(5, "Exportar el chat y recoger los datos", fid)
            out("  Exporta el chat con el comando de VS Code 'Chat: Export Chat...' (formato JSON)")
            out(f"  y guárdalo como:\n     {DEFAULT_CHAT_JSON}")
            ans = yes_no_pause("\n¿Ya lo exportaste? (y = recoger los datos ahora)")
            if ans == "m":
                return False
            if ans == "n":
                continue
            return collect_flow(sid, group, it, ver)

        step += 1
    return False


# ----------------------------------------------------------------------------- flujo principal
def run_one(scn: dict, sid: str, group: str, it: int) -> None:
    fid = fragment_id(sid, group, it)
    state = run_state(sid, group, it)
    prep = ["--scenario", sid, "--group", group, "--iter", str(it), "--menu"]

    if state in ("hecha", "hecha_sin_ok"):
        out(f"\n{fid} YA está hecha.")
        if not yes("¿Repetirla a propósito (--redo)? Se sobrescribirá el fragmento", False):
            return
        prep.append("--redo")
    elif state == "en curso":
        step = int(read_meta().get("menu_step", 1))
        out(f"\n{fid} ya está preparada y sin recoger (iba en el paso {step} de {TOTAL_STEPS}).")
        if yes("¿Retomarla donde la dejaste?", True):
            if guided_steps(sid, group, it, opened=True, start=step):
                out("\nCorrida cerrada.")
            return
    else:
        cur = current_run()
        if cur and cur != fid:
            out(f"\n(!) La carpeta actual corresponde a {cur} (sin recoger). Al preparar {fid} se BORRARÁ.")
            if not yes("¿Continuar?", False):
                return

    opened = yes("¿Abrir la carpeta en VS Code con el perfil 'Experimento'?", True)
    if opened:
        prep.append("--open")
    out("\n>>> Preparando la carpeta...\n")
    if run_script("prepare_workspace.py", *prep) != 0:
        out("\nNo se pudo preparar la corrida (revisa el mensaje de arriba).")
        return

    if guided_steps(sid, group, it, opened):
        out("\nCorrida cerrada.")
    else:
        out("\nLa corrida sigue abierta; vuelve a elegirla en el menú para retomarla.")


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")   # type: ignore[attr-defined]
    except Exception:
        pass
    scn = scenarios()
    out("MENÚ DE CORRIDAS — Inyección de contexto y OWASP Top 10 (Kimi K3)")
    while True:
        sid = pick_scenario(scn)
        if sid is None:
            out("Hasta luego.")
            return 0
        while True:
            sel = pick_run(scn, sid)
            if sel is None:
                break
            run_one(scn, sid, *sel)
            if not yes("\n¿Hacer otra corrida del mismo escenario?", False):
                break


if __name__ == "__main__":
    raise SystemExit(main())
