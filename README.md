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
| `protocol/` | Prompts (`prompts.json`), entorno esperado (`expected_environment.json`), ajustes del perfil de VS Code (`profile_settings.json`), mapeo de reglas SAST, configuración SAST |
| `context_files/` | Copia de referencia de los archivos de contexto del grupo experimental (**no se editan tras congelar el protocolo**) |
| `scripts/` | `prepare_workspace.py`, `collect_run.py`, `run_sast.py`, `consolidate.py`, `record_environment.py`, `anonymize_logs.py` |
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

## Reglas de aislamiento de cada corrida

- **Una sola carpeta desechable, con ruta neutra:** `~/trabajo/app` (p. ej. `C:\Users\Over\trabajo\app`). El modelo lee la ruta del workspace; por eso no contiene "owasp", el grupo ni el escenario. (En una prueba con la ruta `owasp_runs\control\E01\iter1`, el modelo del grupo control dedujo que era un benchmark OWASP.)
- **Cada `prepare_workspace.py` borra la carpeta de la corrida anterior** y archiva el export de chat viejo en `~/owasp_runs/_export/anteriores/`, para que nada se arrastre entre corridas. Si la corrida anterior nunca se recogió ni se descartó, se anota automáticamente (`ABANDONADA_AL_PREPARAR`).
- **Sin solapamientos:** antes de preparar, `prepare_workspace.py` consulta `data/run_log.csv` y `fragments/`. Si esa combinación escenario + grupo + iteración ya fue recogida, se niega a prepararla. Para repetirla a propósito hay que usar `--redo` (se anota como `REPETICION_AUTORIZADA` y `collect_run.py` sobrescribe el fragmento).
- Los ajustes de `protocol/profile_settings.json` se configuran UNA vez en el perfil de VS Code `Experimento` (no dentro de la carpeta de trabajo). **Mantén `chat.tools.global.autoApprove` en `false`**: no actives el modo de aprobación automática.
- **Usa SIEMPRE el mismo tipo de sesión de chat** (agente `github.copilot.editsAgent`, la sesión *Local* de VS Code). Una sesión de otro tipo (p. ej. Copilot CLI, agente `agent-host-copilotcli`) cambia las herramientas y el export, y la corrida se marca inválida.
- **El agente solo puede crear `scenario.py`** (y `requirements.txt` en E03). No debe ejecutar código ni usar el terminal (`run_in_terminal`, `powershell`...), la web o servidores MCP. Si pide permiso para una herramienta fuera de alcance, pulsa **Denegar/Omitir**. Una herramienta denegada solo genera un aviso; una herramienta ejecutada (aprobada por ti o que no requirió confirmación) invalida la corrida: hay que descartarla y repetirla.
- `collect_run.py` compara cada export contra `protocol/expected_environment.json` (modelo, razonamiento, tipo de agente, turnos, herramientas permitidas) y marca como inválida la corrida que no cumpla.

## Registro automático de incidencias

Los scripts registran solos todo lo ocurrido en dos archivos:

- `data/run_log.csv`: **todos** los eventos técnicos (preparada, recogida, descartada, avisos, hashes, resumen del chat).
- `data/bitacora.csv`: las **incidencias** que antes había que anotar a mano (herramienta denegada, `OWASP` mencionado en el grupo control, herramientas auto-aprobadas, `__pycache__`, corridas inválidas, descartes, corridas abandonadas, repeticiones con `--redo`, validación omitida, verificación fallida). Cada fila automática lleva el prefijo `[auto]` en la descripción y la acción sugerida en `accion_tomada`.

Puedes seguir añadiendo a mano observaciones propias en `bitacora.csv` (p. ej. la justificación de un `--skip-chat-check`, o cambios de versión de Kimi K3).

## Registro automático del entorno

`prepare_workspace.py` llama a `scripts/record_environment.py` en cada corrida. Compara el entorno (versión de VS Code, Copilot Chat, extensiones del perfil, herramientas SAST, huella del protocolo) con la última fila de `data/environment_versions.csv` y **solo agrega una fila si algo cambió**, indicando qué cambió. La versión interna de Kimi K3 no es legible automáticamente: anota cualquier cambio anunciado por GitHub en la columna `nota_manual`.

## Reproducir la generación con el menú interactivo (recomendado)

```bash
python scripts/menu.py
```

El menú guía todo el proceso:

1. Muestra el progreso global (`n/100`) y te deja elegir el **escenario**.
2. Muestra qué corridas de ese escenario ya están hechas, por grupo e iteración: `[OK]` hecha con verificación ok, `[ ? ]` hecha sin verificación ok, `[>>]` preparada sin recoger, `[X ]` descartada, `[  ]` pendiente.
3. Eliges **grupo** e **iteración** (propone la primera pendiente). Si ya está hecha, solo la repite si lo confirmas (`--redo`).
4. Prepara la carpeta, limpia la anterior y muestra el paso a paso con los prompts exactos.
5. Cuando termines, pulsa **Y** para recoger los datos (te pide el resultado de la verificación y espera el `chat.json`). Con **D** descartas la corrida y con **M** vuelves al menú dejando la carpeta preparada.
6. Si la recogida resulta inválida, ofrece descartar, reintentar (p. ej. tras volver a exportar el chat) o aceptarla omitiendo la validación **con una justificación obligatoria**, que se anota sola en la bitácora.

El menú solo orquesta `prepare_workspace.py` y `collect_run.py`: las validaciones, la limpieza y la bitácora automática funcionan igual. Los comandos de abajo siguen disponibles para usarlos sueltos.

## Reproducir la generación (una corrida, con comandos)

Flujo completo, de principio a fin:

**1. Preparar la carpeta.** Revisa que la corrida no esté hecha, limpia la anterior, crea `~/trabajo/app`, registra el entorno y, con `--open`, abre VS Code con el perfil `Experimento`:

```bash
python scripts/prepare_workspace.py --scenario E05 --group experimental --iter 2 --open
```

**2. Ejecutar la corrida en VS Code** (sesión Local, modo Agent, Kimi K3, razonamiento máximo, chat NUEVO). El script imprime los prompts exactos:

1. Envía el prompt de **verificación**. El grupo experimental debe listar las directrices y la skill `owasp-mitigacion`; el control debe indicar que no hay convenciones ni skills. Si no se cumple, descarta la corrida (paso 5).
2. En el MISMO chat, envía el prompt del escenario.
3. **Rechaza (Denegar/Omitir) cualquier acción fuera de `scenario.py`**, sobre todo el terminal. No ejecutes ni pruebes el código generado.

**3. Exportar el chat** con el comando de VS Code `Chat: Export Chat...` y guárdalo como JSON en:

```
C:\Users\Over\owasp_runs\_export\chat.json
```

**4. Recoger la corrida** (valida el alcance con git, valida el chat, copia el fragmento y el chat anonimizado, registra en `data/run_log.csv` y borra la carpeta):

```bash
python scripts/collect_run.py --scenario E05 --group experimental --iter 2 --verification ok
```

- Por defecto lee el chat de `~/owasp_runs/_export/chat.json`. Para usar otro archivo: `--chat-json RUTA`.
- Si el export es **anterior** a la preparación de la corrida, el script se detiene (probablemente es el chat de otra corrida). Vuelve a exportar, o usa `--allow-stale-chat` si estás seguro.

**5. Descartar una corrida inválida** (verificación fallida, herramienta ejecutada, archivos extra...):

```bash
python scripts/collect_run.py --scenario E05 --group experimental --iter 2 --discard "motivo"
```

Después anota el caso en `data/bitacora.csv` y repite la corrida (una corrida descartada sí puede prepararse otra vez sin `--redo`).

**Repetir una corrida ya recogida** (decisión deliberada, anótala en la bitácora):

```bash
python scripts/prepare_workspace.py --scenario E05 --group experimental --iter 2 --redo --open
```

### Opciones útiles

| Script | Opción | Efecto |
|---|---|---|
| `prepare_workspace.py` | `--redo` | Permite preparar una corrida ya recogida (el fragmento se sobrescribirá al recoger) |
| `prepare_workspace.py` | `--open` / `--profile NOMBRE` | Abre la carpeta en VS Code con ese perfil |
| `prepare_workspace.py` | `--no-env` | No registra el entorno en `environment_versions.csv` |
| `collect_run.py` | `--chat-json RUTA` | Usa otro export de chat (por defecto `~/owasp_runs/_export/chat.json`) |
| `collect_run.py` | `--chat-md RUTA` | Guarda además el export en Markdown |
| `collect_run.py` | `--verification ok\|fail` | Resultado de la verificación de contexto |
| `collect_run.py` | `--discard MOTIVO` | Descarta la corrida y borra la carpeta |
| `collect_run.py` | `--skip-chat-check` | Omite la validación automática del chat (justifícalo en la bitácora) |
| `collect_run.py` | `--allow-stale-chat` | Permite un export más antiguo que la preparación de la corrida |
| `collect_run.py` | `--overwrite` | Sobrescribe un fragmento ya guardado |
| `collect_run.py` | `--keep` | No borra la carpeta desechable |

## Limitaciones conocidas

La temperatura del modelo no es configurable en Copilot Chat; hay un único revisor manual; el análisis estático produce falsos positivos/negativos. Ver el artículo.

## Licencias

Código y scripts: MIT (`LICENSE`). Datos, reportes y textos: CC BY 4.0
(<https://creativecommons.org/licenses/by/4.0/>). Los fragmentos de `fragments/` son salida de un modelo de IA; se publican como datos de investigación.

## Cómo citar

Ver `CITATION.cff` y el DOI de Zenodo: *Aun no publicado*.

## Antes de publicar: anonimizar

Los exports del chat y los reportes pueden contener rutas con tu usuario de Windows. `collect_run.py` anonimiza automáticamente los chats al guardarlos y `run_sast.py` usa rutas relativas. Para una revisión final (o para limpiar archivos antiguos):

```bash
python scripts/anonymize_logs.py            # revisa; termina con código 1 si hay algo que limpiar
python scripts/anonymize_logs.py --apply    # limpia chat_logs/, data/ y sast_reports/
```

Crea un archivo `.anonymize_terms.txt` (ya está en `.gitignore`) con un término por línea (tu nombre completo, correo, nombre del equipo...) para que también se reemplacen por `<REDACTED>`.