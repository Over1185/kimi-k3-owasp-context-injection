#!/usr/bin/env python3
"""Consolida los reportes JSON de Bandit, Semgrep y pip-audit en tablas CSV.

Genera:
  data/fragmentos.csv            -> TODOS los fragmentos (incluso los que no tienen hallazgos) con su LdC
  data/matriz_registro_auto.csv  -> hallazgos deduplicados (Tabla 4 del plan), regenerable

FLUJO DE REVISIÓN: copia matriz_registro_auto.csv como data/matriz_registro.csv (la matriz
"maestra" revisada a mano) y completa allí la columna Confirmado (Sí/No). Los falsos negativos
se agregan a mano con Herramienta = Manual. NUNCA ejecutes este script sobre la maestra:
siempre escribe en *_auto.csv.

Asignación de categoría (protocol/rule_mapping.json):
  - regla propia del escenario            -> Categoria_OWASP = categoría del escenario
  - regla de OTRA categoría               -> FUERA_DE_ALCANCE (no cuenta en las métricas)
  - regla sin mapear                      -> SIN_MAPEAR (decídelo en la revisión manual)

Uso:
    python scripts/consolidate.py [--osv-lookup]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from pathlib import Path

from common import (DATA, FRAGMENT_RE, FRAGMENTS, GROUPS, PROTOCOL, SAST_REPORTS, count_loc,
                    parse_fragment_id, scenarios)

SEV_ORDER = {"SinDato": 0, "Baja": 1, "Media": 2, "Alta": 3, "Crítica": 4}
BANDIT_SEV = {"LOW": "Baja", "MEDIUM": "Media", "HIGH": "Alta"}
SEMGREP_SEV = {"INFO": "Baja", "WARNING": "Media", "ERROR": "Alta"}
OSV_SEV = {"LOW": "Baja", "MODERATE": "Media", "MEDIUM": "Media", "HIGH": "Alta", "CRITICAL": "Crítica"}
# Decisión metodológica NO prevista en la Tabla 5 del plan: documéntala en el artículo.
UNPINNED_SEVERITY = "Media"

COLUMNS = ["ID_fragmento", "Escenario", "Categoria_OWASP", "Grupo", "Iteracion", "Herramienta",
           "Hallazgo", "Severidad", "Linea_o_dependencia", "Detalle", "Requiere_revision",
           "Confirmado", "LdC"]


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def osv_severity(vuln: dict, cache_dir: Path, enabled: bool) -> str:
    """Severidad cualitativa (GHSA: LOW/MODERATE/HIGH/CRITICAL) desde OSV, con caché en disco."""
    if not enabled:
        return "SinDato"
    cache_dir.mkdir(parents=True, exist_ok=True)
    for vid in [vuln.get("id", "")] + list(vuln.get("aliases", [])):
        if not vid:
            continue
        cache = cache_dir / f"{vid}.json"
        data = load_json(cache)
        if data is None:
            try:
                with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=20) as r:
                    data = json.loads(r.read().decode("utf-8"))
                cache.write_text(json.dumps(data, indent=1), encoding="utf-8")
            except Exception:  # noqa: BLE001
                continue
        sev = str((data.get("database_specific") or {}).get("severity", "")).upper()
        if sev in OSV_SEV:
            return OSV_SEV[sev]
    return "SinDato"


def categorize(scenario: str, tool: str, rule: str, mapping: dict, cat_of: dict) -> str:
    def matches(scn: str) -> bool:
        m = mapping.get(scn, {})
        if tool == "Bandit":
            return rule in m.get("bandit", [])
        return any(s.lower() in rule.lower() for s in m.get("semgrep", []))

    if matches(scenario):
        return cat_of[scenario]
    if any(matches(other) for other in mapping if other.startswith("E") and other != scenario):
        return "FUERA_DE_ALCANCE"
    return "SIN_MAPEAR"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--osv-lookup", action="store_true",
                    help="consulta api.osv.dev para la severidad de hallazgos de pip-audit (requiere internet)")
    args = ap.parse_args()

    scn = scenarios()
    cat_of = {k: v["category"] for k, v in scn.items()}
    mapping = json.loads((PROTOCOL / "rule_mapping.json").read_text(encoding="utf-8"))

    DATA.mkdir(exist_ok=True)
    frag_rows, raw = [], []
    warnings = []

    for group in GROUPS:
        for path in sorted((FRAGMENTS / group).glob("*.py")):
            if not FRAGMENT_RE.match(path.stem):
                continue
            fid = path.stem
            scenario, grp, it = parse_fragment_id(fid)
            ldc = count_loc(path)
            missing = []
            bandit = load_json(SAST_REPORTS / "bandit" / f"{fid}.json")
            semgrep = load_json(SAST_REPORTS / "semgrep" / f"{fid}.json")
            if bandit is None:
                missing.append("bandit")
            if semgrep is None:
                missing.append("semgrep")
            audit = pins = None
            if scenario == "E03":
                audit = load_json(SAST_REPORTS / "pip_audit" / f"{fid}.json")
                pins = load_json(SAST_REPORTS / "pip_audit" / f"{fid}.pins.json")
                if audit is None:
                    missing.append("pip-audit")
            if missing:
                warnings.append(f"{fid}: faltan reportes de {', '.join(missing)}")
            frag_rows.append({"ID_fragmento": fid, "Escenario": scenario, "Categoria_OWASP": cat_of[scenario],
                              "Grupo": grp, "Iteracion": it, "LdC": ldc, "Reportes_faltantes": ";".join(missing)})

            def add(tool, rule, sev, where, detail):
                raw.append({"ID_fragmento": fid, "Escenario": scenario, "Grupo": grp, "Iteracion": it,
                            "Herramienta": tool, "Hallazgo": rule, "Severidad": sev,
                            "Linea_o_dependencia": str(where), "Detalle": detail[:300].replace("\n", " "),
                            "LdC": ldc, "_cat": categorize(scenario, tool, rule, mapping, cat_of)})

            for r in (bandit or {}).get("results", []):
                add("Bandit", r["test_id"], BANDIT_SEV.get(r["issue_severity"], "SinDato"),
                    r["line_number"], f'{r["test_name"]}: {r["issue_text"]}')
            for r in (semgrep or {}).get("results", []):
                sev_native = r.get("extra", {}).get("severity", "")
                if sev_native not in SEMGREP_SEV:
                    warnings.append(f"{fid}: severidad Semgrep no reconocida '{sev_native}'")
                add("Semgrep", r["check_id"], SEMGREP_SEV.get(sev_native, "SinDato"),
                    r["start"]["line"], r.get("extra", {}).get("message", ""))
            for dep in (audit or {}).get("dependencies", []):
                for v in dep.get("vulns", []):
                    sev = osv_severity(v, SAST_REPORTS / "osv_cache", args.osv_lookup)
                    add("pip-audit", v["id"], sev, f'{dep["name"]}=={dep.get("version", "?")}',
                        v.get("description", ""))
            for p in pins or []:
                if not p["pinned"]:
                    add("pip-audit", f'UNPINNED:{p["reason"]}', UNPINNED_SEVERITY, p["requirement"],
                        "Dependencia sin versión fijada o sin verificación de integridad")

    # --- Deduplicación (3.6.4.2): mismo fragmento + misma línea/dependencia + misma categoría
    groups: dict[tuple, list[dict]] = {}
    for r in raw:
        groups.setdefault((r["ID_fragmento"], r["Linea_o_dependencia"], r["_cat"]), []).append(r)
    matrix = []
    for (fid, where, cat), rows in groups.items():
        tools = sorted({r["Herramienta"] for r in rows})
        sev = max((r["Severidad"] for r in rows), key=lambda s: SEV_ORDER[s])
        first = rows[0]
        matrix.append({
            "ID_fragmento": fid, "Escenario": first["Escenario"], "Categoria_OWASP": cat,
            "Grupo": first["Grupo"], "Iteracion": first["Iteracion"], "Herramienta": "; ".join(tools),
            "Hallazgo": " | ".join(sorted({r["Hallazgo"] for r in rows})), "Severidad": sev,
            "Linea_o_dependencia": where, "Detalle": rows[0]["Detalle"],
            "Requiere_revision": "Sí" if len(tools) == 1 else "No",  # detectado por una sola herramienta
            "Confirmado": "", "LdC": first["LdC"]})
    matrix.sort(key=lambda r: (r["ID_fragmento"], str(r["Linea_o_dependencia"])))

    with (DATA / "fragmentos.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["ID_fragmento", "Escenario", "Categoria_OWASP", "Grupo",
                                          "Iteracion", "LdC", "Reportes_faltantes"])
        w.writeheader()
        w.writerows(frag_rows)
    with (DATA / "matriz_registro_auto.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(matrix)

    print(f"Fragmentos: {len(frag_rows)} (esperados: 100) | hallazgos crudos: {len(raw)} | "
          f"tras deduplicar: {len(matrix)}")
    for wmsg in warnings:
        print("AVISO:", wmsg)
    pend = sum(1 for r in matrix if r["Requiere_revision"] == "Sí")
    print(f"Hallazgos de una sola herramienta (revisión manual obligatoria): {pend}")
    print("Siguiente paso: copia data/matriz_registro_auto.csv a data/matriz_registro.csv y completa 'Confirmado'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
