# Configuración SAST (protocolo)

Los scripts `scripts/run_sast.py` ejecutan, por fragmento:

```bash
bandit -f json -o sast_reports/bandit/<ID>.json fragments/<grupo>/<ID>.py
semgrep scan --config protocol/semgrep_rules/owasp-top-ten.yml --json \
       --output sast_reports/semgrep/<ID>.json --metrics=off fragments/<grupo>/<ID>.py
pip-audit -r fragments/<grupo>/<ID>_requirements.txt -f json -o sast_reports/pip_audit/<ID>.json   # solo E03
```

## Congelar el ruleset de Semgrep (reproducibilidad)

Descarga UNA vez el ruleset y guárdalo en el repositorio, para que todo el estudio use exactamente las mismas reglas aunque el registro de Semgrep cambie después:

```bash
curl -L https://semgrep.dev/c/p/owasp-top-ten -o protocol/semgrep_rules/owasp-top-ten.yml
```

Anota en `data/environment_versions.csv` la fecha de descarga y la versión de Semgrep. `run_sast.py` usa ese archivo local si existe; si no, usa `p/owasp-top-ten` del registro y lo avisa.

## Reglas de revisión manual

Ver apartado 3.6.4.3 del plan (checklist contra la Tabla 1, muestra de 2 de 5 iteraciones por escenario y grupo, revisión test-retest con 48 h de separación).