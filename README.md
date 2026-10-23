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

- **Una carpeta desechable por corrida, fuera del repositorio.** Por defecto se crea en `~/owasp_runs/<grupo>/<escenario>/iter<N>` (p. ej. `C:\Users\Over\owasp_runs\experimental\E05\iter2`), con git inicializado y un commit base.
- **Ruta neutra (opcional, recomendada para el grupo control).** El modelo lee la ruta del workspace. La ruta organizada contiene `owasp_runs`, el grupo y el código del escenario, lo que puede sugerirle OWASP al modelo. Con `--neutral` la carpeta es `~/trabajo/app`, sin ninguna pista. Si usas `--neutral` al preparar, úsalo también en `collect_run.py`.
- Los ajustes de `protocol/profile_settings.json` se configuran UNA vez en el perfil de VS Code `Experimento` (no dentro de la carpeta de trabajo). **Mantén `chat.tools.global.autoApprove` en `false`**: no actives el modo de aprobación automática.
- **El agente solo puede crear `scenario.py`** (y `requirements.txt` en E03). No debe ejecutar código ni usar el terminal, la web o servidores MCP. Si el agente pide permiso para una herramienta fuera de alcance, pulsa **Denegar/Omitir**. Una herramienta denegada solo genera un aviso; una herramienta aprobada y ejecutada invalida la corrida (hay que descartarla y repetirla).
- `collect_run.py` compara cada export contra `protocol/expected_environment.json` (modelo, razonamiento, tipo de agente, turnos, herramientas permitidas) y marca como inválida la corrida que no cumpla.

## Registro automático del entorno

`prepare_workspace.py` llama a `scripts/record_environment.py` en cada corrida. Compara el entorno (versión de VS Code, Copilot Chat, extensiones del perfil, herramientas SAST, huella del protocolo) con la última fila de `data/environment_versions.csv` y **solo agrega una fila si algo cambió**, indicando qué cambió. La versión interna de Kimi K3 no es legible automáticamente: anota cualquier cambio anunciado por GitHub en la columna `nota_manual`.

## Reproducir la generación (una corrida)

Flujo completo, de principio a fin:

**1. Preparar la carpeta** (crea el workspace, registra el entorno y, con `--open`, abre VS Code con el perfil `Experimento`):

```bash
python scripts/prepare_workspace.py --scenario E05 --group experimental --iter 2 --open
# Crea: ~/owasp_runs/experimental/E05/iter2
# Ruta neutra: añade --neutral  (crea ~/trabajo/app)
```

**2. Ejecutar la corrida en VS Code** (modo Agent, Kimi K3, razonamiento máximo, chat NUEVO). El script imprime los prompts exactos:

1. Envía el prompt de **verificación**. El grupo experimental debe listar las directrices y la skill `owasp-mitigacion`; el control debe indicar que no hay convenciones ni skills. Si no se cumple, descarta la corrida (paso 5).
2. En el MISMO chat, envía el prompt del escenario.
3. **Rechaza (Denegar/Omitir) cualquier acción fuera de `scenario.py`**, sobre todo `run_in_terminal`. No ejecutes ni pruebes el código generado.

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
- Si preparaste con `--neutral`, añade `--neutral` aquí también.

**5. Descartar una corrida inválida** (verificación fallida, herramienta ejecutada, archivos extra...):

```bash
python scripts/collect_run.py --scenario E05 --group experimental --iter 2 --discard "motivo"
```

Después anota el caso en `data/bitacora.csv` y repite la corrida.

### Opciones útiles de `collect_run.py`

| Opción | Efecto |
|---|---|
| `--chat-json RUTA` | Usa otro export de chat (por defecto `~/owasp_runs/_export/chat.json`) |
| `--chat-md RUTA` | Guarda además el export en Markdown |
| `--verification ok\|fail` | Resultado de la verificación de contexto |
| `--discard MOTIVO` | Descarta la corrida y borra la carpeta |
| `--skip-chat-check` | Omite la validación automática del chat (justifícalo en la bitácora) |
| `--allow-stale-chat` | Permite un export más antiguo que la preparación de la corrida |
| `--overwrite` | Sobrescribe un fragmento ya guardado (solo al repetir una corrida a propósito) |
| `--keep` | No borra la carpeta desechable |
| `--neutral` / `--base RUTA` | Layout neutro `~/trabajo/app` / otra carpeta base |

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