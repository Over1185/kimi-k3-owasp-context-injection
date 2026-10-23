#!/usr/bin/env python3
"""Recoge el resultado de UNA corrida y limpia la carpeta desechable (pasos 3.6.2.1 d, e, f).

1. Verifica con git que el agente solo creó scenario.py (y requirements.txt en E03).
   Si tocó cualquier otro archivo la corrida es inválida (hay que descartarla y repetirla).
2. Copia scenario.py a fragments/<grupo>/<ID>.py (y requirements.txt en E03).
3. Copia el export del chat a chat_logs/<grupo>/.
4. Registra todo en data/run_log.csv y borra la carpeta desechable.

Uso:
    python scripts/collect_run.py --scenario E05 --group experimental --iter 2 \
        --chat-json ~/Descargas/chat.json --verification ok
    python scripts/collect_run.py --scenario E05 --group control --iter 1 --discard "motivo"
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import re

from common import (DEFAULT_BASE_NAME, WORKSPACE_NAME, anonymize_text, load_expected_env, load_terms,
                    CHAT_LOGS, FRAGMENTS, GROUPS, N_ITERATIONS, ROOT, fragment_id, log_event,
                    rmtree_force, scenarios, sha256)


def git_changes(ws: Path) -> list[tuple[str, str]]:
    out = subprocess.run(["git", "status", "--porcelain", "-uall"], cwd=ws, check=True,
                         capture_output=True, text=True).stdout
    changes = []
    for line in out.splitlines():
        status, path = line[:2].strip(), line[3:].strip().strip('"')
        changes.append((status, path))
    return changes


def inspect_chat(path: Path) -> dict:
    """Resume el export JSON de VS Code: modelo, agente, modo, herramientas, créditos y texto."""
    data = json.loads(path.read_text(encoding="utf-8"))
    reqs = data.get("requests", [])
    info = {"n_requests": len(reqs), "models": [], "agents": set(), "modes": set(),
            "tools": [], "credits": None, "texts": [], "prompt_tokens": 0, "completion_tokens": 0,
            "thinking": set(), "auto_approved": [], "thought": [], "credits_sum": 0.0}
    for r in reqs:
        info["models"] += [str(r.get("modelId", ""))]
        info["models"] += [str(m.get("model", "")) for m in (r.get("modelTotals") or [])]
        details = (r.get("result") or {}).get("details")
        if details:
            info["models"].append(str(details))
        info["agents"].add(str((r.get("agent") or {}).get("id", "")))
        mc = r.get("modelConfiguration") or {}
        # El arnés "Copilot" exporta thinkingLevel; el arnés "Local" exporta reasoningEffort
        info["thinking"].add(str(mc.get("thinkingLevel") or mc.get("reasoningEffort") or "sin_dato"))
        info["credits_sum"] += float(r.get("copilotCredits") or 0)
        info["modes"].add(str((r.get("modeInfo") or {}).get("kind", "")))
        info["credits"] = r.get("sessionCopilotCredits", info["credits"])
        info["prompt_tokens"] += int(r.get("promptTokens") or 0)
        info["completion_tokens"] += int(r.get("completionTokens") or 0)
        text = ""
        for part in r.get("response", []):
            kind = part.get("kind")
            if kind == "toolInvocationSerialized":
                info["tools"].append(str(part.get("toolId")))
                ic = part.get("isConfirmed")
                if isinstance(ic, dict) and ic.get("type") == 2:   # 2 = aprobada por un ajuste (auto-aprobación)
                    info["auto_approved"].append(f"{part.get('toolId')}<-{ic.get('id')}")
            elif kind == "thinking":
                tv = part.get("value")
                if isinstance(tv, str):
                    info["thought"].append(tv)
            elif kind in (None, "markdownContent"):
                v = part.get("value", (part.get("content") or {}).get("value"))
                if isinstance(v, dict):
                    v = v.get("value")
                if isinstance(v, str):
                    text += v
        info["texts"].append(text)
    info["credits"] = info["credits"] if info["credits"] is not None else round(info["credits_sum"], 2)
    return info


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--group", required=True, choices=GROUPS)
    ap.add_argument("--iter", type=int, required=True, dest="iteration")
    ap.add_argument("--base", default=str(Path.home() / DEFAULT_BASE_NAME))
    ap.add_argument("--chat-json", help="export del chat en JSON (Chat: Export Chat...)")
    ap.add_argument("--chat-md", help="export del chat en Markdown (opcional)")
    ap.add_argument("--verification", choices=["ok", "fail"], help="resultado de la verificación de contexto")
    ap.add_argument("--discard", metavar="MOTIVO", help="descarta la corrida: registra el motivo y borra la carpeta")
    env = load_expected_env()
    ap.add_argument("--model-substring", default=env["model_substring"], help="texto que debe aparecer en el modelo")
    ap.add_argument("--thinking-level", default=env["reasoning"], help="nivel de razonamiento esperado")
    ap.add_argument("--agent-id", default=env["agent_id"], help="id del agente esperado (protocol/expected_environment.json)")
    ap.add_argument("--skip-chat-check", action="store_true",
                    help="omite la validación automática del chat (justifícalo en la bitácora)")
    ap.add_argument("--keep", action="store_true", help="no borra la carpeta desechable al terminar")
    ap.add_argument("--overwrite", action="store_true", help="permite sobrescribir un fragmento ya guardado")
    args = ap.parse_args()

    if args.scenario not in scenarios():
        sys.exit(f"Escenario desconocido: {args.scenario}")
    if not 1 <= args.iteration <= N_ITERATIONS:
        sys.exit(f"La iteración debe estar entre 1 y {N_ITERATIONS}")

    fid = fragment_id(args.scenario, args.group, args.iteration)
    base = Path(args.base).expanduser().resolve()
    ws = base / WORKSPACE_NAME
    if not ws.is_dir():
        sys.exit(f"No existe la carpeta de trabajo: {ws}")
    cur = base / "_current.json"
    if cur.is_file():
        current = json.loads(cur.read_text(encoding="utf-8")).get("id")
        if current != fid:
            sys.exit(f"La carpeta de trabajo corresponde a la corrida {current}, no a {fid}. "
                     "Revisa los argumentos (--scenario/--group/--iter).")
    else:
        sys.exit("Falta _current.json: la carpeta no fue creada con prepare_workspace.py.")

    # --- Descarte explícito
    if args.discard:
        log_event(fid, "DESCARTADO", args.discard)
        rmtree_force(ws)
        print(f"Corrida {fid} descartada y carpeta borrada. Regístralo en la bitácora y repite la corrida.")
        return 0

    # --- 1. Verificar alcance
    allowed = {"scenario.py"} | ({"requirements.txt"} if args.scenario == "E03" else set())
    changes = git_changes(ws)
    extra = [(s, p) for s, p in changes
             if p not in allowed and "__pycache__" not in p and not p.endswith(".pyc")]
    pycache = [p for _, p in changes if "__pycache__" in p or p.endswith(".pyc")]
    if extra:
        detail = "; ".join(f"{s} {p}" for s, p in extra)
        log_event(fid, "INVALIDA_ARCHIVOS_EXTRA", detail)
        print(f"CORRIDA INVÁLIDA: el agente tocó archivos fuera del alcance:\n  {detail}")
        print("Documenta el caso en la bitácora y vuelve a ejecutar con --discard para repetirla.")
        return 2
    if pycache:
        print("AVISO: hay __pycache__ (el agente ejecutó código). Anótalo en la bitácora.")
        log_event(fid, "AVISO_PYCACHE", "el agente ejecutó código")
    if not (ws / "scenario.py").is_file():
        log_event(fid, "INVALIDA_SIN_SCENARIO", "no existe scenario.py")
        sys.exit("No existe scenario.py: la generación falló. Usa --discard para repetirla.")
    if args.scenario == "E03" and not (ws / "requirements.txt").is_file():
        log_event(fid, "INVALIDA_SIN_REQUIREMENTS", "E03 sin requirements.txt")
        sys.exit("E03 requiere requirements.txt: la generación falló. Usa --discard para repetirla.")

    # --- 1b. Validar el export del chat (modelo, nº de turnos, verificación de contexto)
    chat_summary = ""
    if args.chat_json and not args.skip_chat_check:
        cj = Path(args.chat_json).expanduser()
        if not cj.is_file():
            sys.exit(f"No existe el archivo de chat: {cj}")
        info = inspect_chat(cj)
        problems = []
        if not any(args.model_substring.lower() in m.lower() for m in info["models"]):
            problems.append(f"el modelo del chat no contiene '{args.model_substring}': "
                            f"{sorted(set(m for m in info['models'] if m))}")
        if info["thinking"] != {args.thinking_level}:
            problems.append(f"nivel de razonamiento {sorted(info['thinking'])} (se esperaba {args.thinking_level})")
        if info["agents"] != {args.agent_id}:
            problems.append(f"agente {sorted(info['agents'])} (se esperaba {args.agent_id}); "
                            "usa SIEMPRE el mismo tipo de sesión/arnés en las 100 corridas")
        if info["n_requests"] != env["turns"]:
            problems.append(f"se esperaban {env['turns']} turnos (verificación + prompt) y hay {info['n_requests']}")
        bad_tools = sorted({t for t in info["tools"] if re.search(env["forbidden_tools_regex"], t, re.I)})
        if bad_tools:
            problems.append(f"herramientas fuera de alcance usadas por el agente: {bad_tools}")
        if info["modes"] - {"agent"}:
            problems.append(f"modo distinto de Agent: {sorted(info['modes'])}")
        if info["texts"]:
            has_skill = "owasp-mitigacion" in info["texts"][0].lower()
            expected = args.group == "experimental"
            if has_skill != expected:
                problems.append("la respuesta de verificación "
                                f"{'NO menciona' if expected else 'menciona'} la skill 'owasp-mitigacion' "
                                f"(en el grupo {args.group} se esperaba lo contrario)")
        chat_summary = (f"modelo={sorted(set(m for m in info['models'] if m))}; agente={sorted(info['agents'])}; "
                        f"razonamiento={sorted(info['thinking'])}; turnos={info['n_requests']}; herramientas={sorted(set(info['tools']))}; "
                        f"tokens_in={info['prompt_tokens']}; tokens_out={info['completion_tokens']}; "
                        f"creditos={info['credits']}")
        print("Chat:", chat_summary)
        warns = []
        if info["auto_approved"]:
            warns.append("herramientas aprobadas AUTOMÁTICAMENTE por un ajuste "
                         f"({sorted(set(info['auto_approved']))}): desactiva 'chat.tools.global.autoApprove' "
                         "en el perfil para aprobar tú cada acción")
        if args.group == "control" and re.search(r"owasp", " ".join(info["thought"] + info["texts"]), re.I):
            warns.append("el modelo mencionó 'OWASP' en el grupo CONTROL: revisa qué se lo sugirió "
                         "(nombre de carpeta, archivos visibles) y anótalo en la bitácora")
        for w in warns:
            print("AVISO:", w)
            log_event(fid, "AVISO_CHAT", w)
        if problems:
            log_event(fid, "INVALIDA_CHAT", " | ".join(problems) + " || " + chat_summary)
            print("CORRIDA INVÁLIDA según el chat exportado:\n  - " + "\n  - ".join(problems))
            print("Si es un falso positivo, repite con --skip-chat-check y justifícalo en la bitácora; "
                  "si no, usa --discard y repite la corrida.")
            return 2
    elif args.chat_json and args.skip_chat_check:
        log_event(fid, "CHAT_CHECK_OMITIDO", "validación automática del chat omitida por el investigador")

    # --- 2. Copiar fragmento(s)
    dest_dir = FRAGMENTS / args.group
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_py = dest_dir / f"{fid}.py"
    to_copy = [(ws / "scenario.py", dest_py)]
    if args.scenario == "E03":
        to_copy.append((ws / "requirements.txt", dest_dir / f"{fid}_requirements.txt"))
    for _src, dst in to_copy:
        if dst.exists() and not args.overwrite:
            sys.exit(f"{dst.name} ya existe. Usa --overwrite solo si estás repitiendo la corrida a propósito.")
    hashes = []
    for src, dst in to_copy:
        shutil.copy2(src, dst)
        hashes.append(f"{dst.name}={sha256(dst)[:16]}")

    # --- 3. Copiar logs del chat
    chat_dir = CHAT_LOGS / args.group
    chat_dir.mkdir(parents=True, exist_ok=True)
    for opt, suffix in ((args.chat_json, ".chat.json"), (args.chat_md, ".chat.md")):
        if opt:
            src = Path(opt).expanduser()
            if not src.is_file():
                sys.exit(f"No existe el archivo de chat: {src}")
            raw_text = src.read_bytes().decode("utf-8")
            clean, counts = anonymize_text(raw_text, load_terms())
            if suffix.endswith(".json"):
                try:
                    json.loads(clean)
                except ValueError:
                    sys.exit("La anonimización dejó el JSON inválido; no se guardó el chat.")
            dst_chat = chat_dir / f"{fid}{suffix}"
            dst_chat.write_bytes(clean.encode("utf-8"))
            hashes.append(f"{dst_chat.name}={sha256(dst_chat)[:16]}"
                          f"(anonimizados={sum(counts.values())})")
    if not (args.chat_json or args.chat_md):
        print("AVISO: no indicaste export del chat (--chat-json / --chat-md). Se recomienda guardarlo siempre.")

    # --- 4. Registrar y limpiar
    log_event(fid, "RECOGIDO", f"verificacion={args.verification or 'sin_dato'}; " + "; ".join(hashes)
              + (f"; {chat_summary}" if chat_summary else ""))
    if not args.keep:
        rmtree_force(ws)
    print(f"OK: {dest_py.relative_to(ROOT)} guardado."
          f"{'' if args.keep else ' Carpeta desechable borrada.'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
