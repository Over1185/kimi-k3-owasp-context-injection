# Inyección de contexto y vulnerabilidades OWASP Top 10 en código generado por Kimi K3 (GitHub Copilot Chat)

Paquete de replicación del estudio *Impacto de la Inyección de Contexto en la Mitigación de Vulnerabilidades OWASP Top 10 en Código Generado por Kimi K3 en GitHub Copilot Chat*.
Autor: Jefferson Manuel Cuervo Castillo — Pontificia Universidad Católica del Ecuador, Sede Esmeraldas.

> **Advertencia.** Los archivos de `fragments/` son código generado por una IA y pueden contener vulnerabilidades (es justo lo que se mide). No usar en producción. No contiene credenciales ni datos personales.

## Diseño (resumen)

10 escenarios (E01–E10, uno por categoría OWASP Top 10:2025) × 5 iteraciones × 2 grupos (control sin contexto / experimental con `AGENTS.md`, Agent Skill y `copilot-instructions.md`) = 100 fragmentos.
Modelo: Kimi K3 (nivel de razonamiento máximo), GitHub Copilot Chat en modo Agent, Python/FastAPI.
Medición: Bandit, Semgrep (`p/owasp-top-ten`) y pip-audit (solo E03). Versiones exactas en `data/environment_versions.csv`.

## Estructura

| Carpeta | Contenido |
|---|---|
| `protocol/` | Prompts (`prompts.json`), ajustes de VS Code de cada corrida, mapeo de reglas SAST, configuración SAST |
| `context_files/` | Copia de referencia de los archivos de contexto del grupo experimental (**no se editan tras congelar el protocolo**) |
| `scripts/` | `prepare_workspace.py`, `collect_run.py`, `run_sast.py`, `consolidate.py` |
| `fragments/` | Código generado: `<escenario>_<grupo>_iter<n>.py` |
| `chat_logs/` | Conversaciones exportadas de cada corrida |
| `sast_reports/` | JSON crudos de las herramientas (sin editar) |
| `data/` | `fragmentos.csv`, `matriz_registro.csv`, `bitacora.csv`, `run_log.csv`, `environment_versions.csv` |
| `analysis/` | `run_all.py` (métricas, pruebas estadísticas y gráficos) |
| `results/` | Tablas CSV y figuras PNG finales |

## Reproducir el análisis

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt                        # o requirements-lock.txt
python scripts/run_sast.py                             # escanea los fragmentos
python scripts/consolidate.py                          # genera data/matriz_registro_auto.csv
# revisión manual: copiar a data/matriz_registro.csv y completar la columna Confirmado
python analysis/run_all.py                             # tablas y figuras en results/
```

## Reproducir la generación (una corrida)

```bash
python scripts/prepare_workspace.py --scenario E05 --group experimental --iter 2 --open
# ... ejecutar la corrida en VS Code (instrucciones impresas por el script) ...
python scripts/collect_run.py --scenario E05 --group experimental --iter 2 \
       --chat-json RUTA_DEL_EXPORT.json --verification ok
```

## Limitaciones conocidas

La temperatura del modelo no es configurable en Copilot Chat; hay un único revisor manual; el análisis estático produce falsos positivos/negativos. Ver el artículo.

## Licencias

Código y scripts: MIT (`LICENSE`). Datos, reportes y textos: CC BY 4.0 (<https://creativecommons.org/licenses/by/4.0/>). Los fragmentos de `fragments/` son salida de un modelo de IA; se publican como datos de investigación.

## Cómo citar

Ver `CITATION.cff` y el DOI de Zenodo: *Aun no publicado*.

## Antes de publicar: anonimizar

Los exports del chat y los reportes pueden contener rutas con tu usuario de Windows. `collect_run.py` anonimiza automáticamente los chats al guardarlos y `run_sast.py` usa rutas relativas. Para una revisión final (o para limpiar archivos antiguos):

```bash
python scripts/anonymize_logs.py            # revisa; termina con código 1 si hay algo que limpiar
python scripts/anonymize_logs.py --apply    # limpia chat_logs/, data/ y sast_reports/
```

Crea un archivo `.anonymize_terms.txt` (ya está en `.gitignore`) con un término por línea (tu nombre completo, correo, nombre del equipo...) para que también se reemplacen por `<REDACTED>`.