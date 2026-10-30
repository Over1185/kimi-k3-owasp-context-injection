#!/usr/bin/env python3
"""Ayuda para la revisión manual: muestra el código marcado de cada hallazgo DENTRO DE ALCANCE.

Es de solo lectura: no modifica ningún archivo. Colócalo en scripts/ y ejecútalo desde la raíz:

    python scripts\\revisar_hallazgos.py              # todos los hallazgos dentro de alcance
    python scripts\\revisar_hallazgos.py E07          # solo un escenario
    python scripts\\revisar_hallazgos.py E02 --contexto 6

Un hallazgo "dentro de alcance" es el que tiene Categoria_OWASP distinta de FUERA_DE_ALCANCE y SIN_MAPEAR.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
EXCLUIDAS = {"FUERA_DE_ALCANCE", "SIN_MAPEAR"}


def mostrar_codigo(path: Path, linea: int, ctx: int) -> None:
    lineas = path.read_text(encoding="utf-8", errors="replace").splitlines()
    ini, fin = max(1, linea - ctx), min(len(lineas), linea + ctx)
    for n in range(ini, fin + 1):
        marca = ">>" if n == linea else "  "
        print(f"  {marca} {n:4d} | {lineas[n - 1]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("escenario", nargs="?", help="p. ej. E07 (opcional)")
    ap.add_argument("--contexto", type=int, default=4, help="líneas de contexto antes y después (por defecto 4)")
    args = ap.parse_args()

    m = pd.read_csv(ROOT / "data" / "matriz_registro.csv", dtype=str, keep_default_na=False, encoding="utf-8-sig")
    m = m[~m["Categoria_OWASP"].isin(EXCLUIDAS)]
    if args.escenario:
        m = m[m["Escenario"] == args.escenario.upper()]
    if m.empty:
        print("No hay hallazgos dentro de alcance con ese filtro.")
        return 0

    m = m.sort_values(["Escenario", "Grupo", "Iteracion", "Linea_o_dependencia"])
    for i, (_, r) in enumerate(m.iterrows(), start=1):
        fid, grupo, donde = r["ID_fragmento"], r["Grupo"], r["Linea_o_dependencia"]
        print("=" * 100)
        print(f"[{i}/{len(m)}] {fid} | {r['Categoria_OWASP']} | {r['Herramienta']} | severidad {r['Severidad']}")
        print(f"Hallazgo: {r['Hallazgo']}")
        print(f"Detalle : {r['Detalle'][:200]}")
        frag = ROOT / "fragments" / grupo / f"{fid}.py"
        if donde.isdigit():
            print(f"Archivo : {frag.relative_to(ROOT)} (línea {donde})")
            if frag.is_file():
                mostrar_codigo(frag, int(donde), args.contexto)
            else:
                print("  (no se encontró el fragmento)")
        else:
            print(f"Dependencia: {donde}")
            req = frag.with_name(f"{fid}_requirements.txt")
            if req.is_file():
                print(f"Contenido de {req.relative_to(ROOT)}:")
                for linea in req.read_text(encoding="utf-8", errors="replace").splitlines():
                    print(f"     {linea}")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
