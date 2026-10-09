#!/usr/bin/env python3
"""Calcula las métricas del plan (apartados 2.2.7, 3.6.5.2 y 3.8) y genera tablas y gráficos.

Entradas:
  data/fragmentos.csv        (lo genera scripts/consolidate.py)
  data/matriz_registro.csv   (matriz revisada a mano; columna Confirmado = Sí/No)

Salidas:
  results/tables/*.csv       results/figures/*.png

Solo cuentan los hallazgos con Confirmado = Sí Y Categoria_OWASP igual a la categoría del
escenario (los FUERA_DE_ALCANCE y SIN_MAPEAR no sumados a la categoría se excluyen).

Uso:
    python analysis/run_all.py
    python analysis/run_all.py --allow-unreviewed   # trata Confirmado vacío como Sí (solo para pruebas)
"""
from __future__ import annotations

import argparse
import sys
import unicodedata
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402
from scipy import stats  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA, TABLES, FIGURES = ROOT / "data", ROOT / "results" / "tables", ROOT / "results" / "figures"
SEV_NUM = {"Baja": 1, "Media": 2, "Alta": 3, "Crítica": 4}
SEV_LEVELS = ["Baja", "Media", "Alta", "Crítica"]
GROUP_ORDER = ["control", "experimental"]
ALPHA = 0.05


def norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode().strip().lower()
    return s


def tasa_reduccion(v_sin: int, v_con: int) -> tuple[float, str]:
    """TR = ((VSIN - VCON) / VSIN) * 100, con la regla de manejo de VSIN = 0 (apartado 2.2.7)."""
    if v_sin > 0:
        tr = (v_sin - v_con) / v_sin * 100
        return tr, f"{tr:.1f}"
    if v_con == 0:
        return float("nan"), "No aplica (0/0)"
    return float("nan"), "No aplica (VSIN=0)"


def load_inputs(allow_unreviewed: bool) -> tuple[pd.DataFrame, pd.DataFrame]:
    frag = pd.read_csv(DATA / "fragmentos.csv", encoding="utf-8-sig")
    mat = pd.read_csv(DATA / "matriz_registro.csv", dtype=str, keep_default_na=False, encoding="utf-8-sig")
    mat["_conf"] = mat["Confirmado"].map(norm)
    blank = mat["_conf"] == ""
    if blank.any() and not allow_unreviewed:
        sys.exit(f"Hay {int(blank.sum())} hallazgos sin revisar (Confirmado vacío) en matriz_registro.csv. "
                 "Revísalos (apartado 3.6.4.3) o usa --allow-unreviewed solo para pruebas.")
    mat.loc[blank, "_conf"] = "si"
    bad = ~mat["_conf"].isin(["si", "no"])
    if bad.any():
        sys.exit(f"Valores no válidos en Confirmado (use Sí/No): {sorted(set(mat.loc[bad, 'Confirmado']))}")
    cat_of = frag.drop_duplicates("Escenario").set_index("Escenario")["Categoria_OWASP"]
    mat["_cat_escenario"] = mat["Escenario"].map(cat_of)
    keep = (mat["_conf"] == "si") & (mat["Categoria_OWASP"] == mat["_cat_escenario"])
    excluded = mat[~keep]
    print(f"Hallazgos en la matriz: {len(mat)} | contados: {int(keep.sum())} | excluidos "
          f"(No confirmados o fuera de categoría): {len(excluded)}")
    return frag, mat[keep].copy()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--allow-unreviewed", action="store_true")
    args = ap.parse_args()
    TABLES.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    frag, conf = load_inputs(args.allow_unreviewed)
    if (frag["Reportes_faltantes"].fillna("") != "").any():
        print("AVISO: hay fragmentos con reportes SAST faltantes; sus conteos pueden estar subestimados.")

    # ---- Métricas por fragmento: V, DV (por 100 LdC) y severidad
    conf["sev_num"] = conf["Severidad"].map(SEV_NUM)
    if conf["sev_num"].isna().any():
        print(f"AVISO: {int(conf['sev_num'].isna().sum())} hallazgos confirmados sin severidad válida "
              "(se cuentan en V pero no entran en la severidad promedio).")
    v = conf.groupby("ID_fragmento").agg(V=("ID_fragmento", "size"), sev_mean=("sev_num", "mean"))
    per_frag = frag.merge(v, how="left", left_on="ID_fragmento", right_index=True)
    per_frag["V"] = per_frag["V"].fillna(0).astype(int)
    per_frag["DV_por_100LdC"] = per_frag["V"] / per_frag["LdC"] * 100
    per_frag.to_csv(TABLES / "metricas_por_fragmento.csv", index=False, encoding="utf-8-sig")

    # ---- Totales por escenario/categoría y grupo + tasa de reducción
    tot = per_frag.pivot_table(index=["Escenario", "Categoria_OWASP"], columns="Grupo", values="V",
                               aggfunc="sum", fill_value=0).reindex(columns=GROUP_ORDER, fill_value=0)
    rows = []
    for (scn, cat), r in tot.iterrows():
        tr, txt = tasa_reduccion(int(r["control"]), int(r["experimental"]))
        rows.append({"Escenario": scn, "Categoria_OWASP": cat, "V_control": int(r["control"]),
                     "V_experimental": int(r["experimental"]), "TR_pct": tr, "TR_texto": txt})
    by_cat = pd.DataFrame(rows)
    g_tr, g_txt = tasa_reduccion(int(by_cat["V_control"].sum()), int(by_cat["V_experimental"].sum()))
    by_cat.to_csv(TABLES / "vulnerabilidades_y_TR_por_categoria.csv", index=False, encoding="utf-8-sig")
    pd.DataFrame([{"V_control": int(by_cat["V_control"].sum()), "V_experimental": int(by_cat["V_experimental"].sum()),
                   "TR_global_pct": g_tr, "TR_texto": g_txt}]).to_csv(
        TABLES / "TR_global.csv", index=False, encoding="utf-8-sig")

    # ---- Densidad y severidad promedio por grupo (y por categoría)
    dens = per_frag.groupby("Grupo").agg(
        V_total=("V", "sum"), LdC_total=("LdC", "sum"),
        DV_mediana_por_100LdC=("DV_por_100LdC", "median"), DV_media_por_100LdC=("DV_por_100LdC", "mean"))
    dens["DV_global_por_100LdC"] = dens["V_total"] / dens["LdC_total"] * 100
    dens.to_csv(TABLES / "densidad_por_grupo.csv", encoding="utf-8-sig")
    sev_cat = conf.groupby(["Categoria_OWASP", "Grupo"])["sev_num"].mean().unstack().reindex(columns=GROUP_ORDER)
    sev_cat.to_csv(TABLES / "severidad_promedio_por_categoria.csv", encoding="utf-8-sig")
    sev_glob = conf.groupby("Grupo")["sev_num"].mean().reindex(GROUP_ORDER)
    sev_glob.to_csv(TABLES / "severidad_promedio_global.csv", encoding="utf-8-sig", header=["severidad_promedio"])
    sev_dist = conf.groupby(["Grupo", "Severidad"]).size().unstack(fill_value=0).reindex(
        index=GROUP_ORDER, columns=SEV_LEVELS, fill_value=0)
    sev_dist.to_csv(TABLES / "distribucion_severidad.csv", encoding="utf-8-sig")

    # ---- Pruebas estadísticas (la primera es la definida en el plan; las otras, de sensibilidad)
    piv = per_frag.pivot_table(index=["Escenario", "Iteracion"], columns="Grupo", values="V",
                               aggfunc="sum").reindex(columns=GROUP_ORDER).dropna()
    results = []

    def add_test(name, note, fn, a, b):
        try:
            res = fn(a, b)
            stat, p = float(res.statistic), float(res.pvalue)
            decision = "significativo" if p < ALPHA else "no significativo"
        except ValueError as e:  # p. ej. todas las diferencias son 0
            stat, p, decision = float("nan"), float("nan"), f"no calculable ({e})"
        results.append({"prueba": name, "nota": note, "n_pares_o_obs": len(a), "estadistico": stat,
                        "p_valor": p, "alpha": ALPHA, "decision": decision})

    a, b = piv["control"].to_numpy(), piv["experimental"].to_numpy()
    add_test("Wilcoxon pareado por iteración (plan, 50 pares)",
             "pareo i-i entre corridas independientes: discutir con el tutor",
             lambda x, y: stats.wilcoxon(x, y, alternative="two-sided"), a, b)
    sc = per_frag.groupby(["Escenario", "Grupo"])["V"].sum().unstack().reindex(columns=GROUP_ORDER)
    add_test("Wilcoxon pareado por escenario (10 pares, sensibilidad)", "totales de 5 iteraciones por escenario",
             lambda x, y: stats.wilcoxon(x, y, alternative="two-sided"),
             sc["control"].to_numpy(), sc["experimental"].to_numpy())
    add_test("Mann-Whitney U independiente (50 vs 50, sensibilidad)", "no asume pareo entre iteraciones",
             lambda x, y: stats.mannwhitneyu(x, y, alternative="two-sided"), a, b)
    pd.DataFrame(results).to_csv(TABLES / "pruebas_estadisticas.csv", index=False, encoding="utf-8-sig")

    # ---- Gráficos
    sns.set_theme(style="whitegrid")
    order_cats = sorted(by_cat["Categoria_OWASP"].unique())

    # 1) Vulnerabilidades por categoría (barras agrupadas)
    plot = by_cat.melt(id_vars=["Escenario", "Categoria_OWASP"], value_vars=["V_control", "V_experimental"],
                       var_name="Grupo", value_name="Vulnerabilidades")
    plot["Grupo"] = plot["Grupo"].str.replace("V_", "")
    plt.figure(figsize=(10, 5))
    sns.barplot(data=plot, x="Categoria_OWASP", y="Vulnerabilidades", hue="Grupo", order=order_cats,
                hue_order=GROUP_ORDER)
    plt.title("Vulnerabilidades confirmadas por categoría OWASP Top 10:2025")
    plt.xlabel("Categoría OWASP")
    plt.tight_layout()
    plt.savefig(FIGURES / "01_vulnerabilidades_por_categoria.png", dpi=300)
    plt.close()

    # 2) Distribución de severidad (barras apiladas, proporción)
    prop = sev_dist.div(sev_dist.sum(axis=1).replace(0, np.nan), axis=0).fillna(0)
    ax = prop.plot(kind="bar", stacked=True, figsize=(6, 5), colormap="YlOrRd")
    ax.set_ylabel("Proporción de vulnerabilidades confirmadas")
    ax.set_title("Distribución de severidad por grupo")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(FIGURES / "02_distribucion_severidad.png", dpi=300)
    plt.close()

    # 3) Densidad (boxplot por escenario y grupo)
    plt.figure(figsize=(11, 5))
    sns.boxplot(data=per_frag, x="Escenario", y="DV_por_100LdC", hue="Grupo", hue_order=GROUP_ORDER)
    plt.ylabel("Vulnerabilidades por 100 LdC")
    plt.title("Densidad de vulnerabilidades por escenario (5 iteraciones por caja)")
    plt.tight_layout()
    plt.savefig(FIGURES / "03_densidad_boxplot.png", dpi=300)
    plt.close()

    # 4) Tasa de reducción por categoría (barras horizontales; "No aplica" al final, anotado)
    num = by_cat.dropna(subset=["TR_pct"]).sort_values("TR_pct", ascending=False)
    na = by_cat[by_cat["TR_pct"].isna()]
    labels = list(num["Categoria_OWASP"]) + list(na["Categoria_OWASP"])
    vals = list(num["TR_pct"]) + [0.0] * len(na)
    fig, ax = plt.subplots(figsize=(8, 5))
    ypos = np.arange(len(labels))
    ax.barh(ypos, vals, color=["#4c72b0"] * len(num) + ["#cccccc"] * len(na))
    ax.set_yticks(ypos)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    for i, (_, r) in enumerate(na.iterrows()):
        ax.text(1, len(num) + i, r["TR_texto"], va="center", fontsize=9)
    ax.axvline(0, color="black", lw=0.8)
    ax.set_xlabel("Tasa de reducción (%)  [negativo = más vulnerabilidades con contexto]")
    ax.set_title("Tasa de reducción de vulnerabilidades por categoría")
    plt.tight_layout()
    plt.savefig(FIGURES / "04_tasa_reduccion_por_categoria.png", dpi=300)
    plt.close()

    print(f"\nTR global: {g_txt}%  |  tablas en {TABLES.relative_to(ROOT)}  |  figuras en {FIGURES.relative_to(ROOT)}")
    print(pd.DataFrame(results)[["prueba", "estadistico", "p_valor", "decision"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
