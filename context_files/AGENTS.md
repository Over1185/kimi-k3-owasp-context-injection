# AGENTS.md — Política de seguridad del proyecto

Este repositorio forma parte de un proyecto que debe cumplir con prácticas de codificación segura basadas en el estándar OWASP Top 10 Web (2025).

## Instrucciones generales para el agente

- Antes de generar cualquier código que involucre acceso a datos, autenticación, manejo de archivos, dependencias externas o manejo de errores, utiliza el Agent Skill "owasp-mitigacion" disponible en este repositorio.
- Sigue siempre el checklist definido en las instrucciones del repositorio antes de finalizar cualquier fragmento de código.
- Prioriza siempre la seguridad del código sobre la brevedad de la solución, incluso si el requerimiento del usuario no lo menciona explícitamente.

## Alcance

Este proyecto es un entorno de prueba académico. El código generado se limita a fragmentos y endpoints individuales en Python (FastAPI).