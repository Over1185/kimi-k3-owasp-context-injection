---
name: owasp-mitigacion
description: Directrices técnicas de mitigación de vulnerabilidades OWASP Top 10:2025 para la generación de código Python/FastAPI. Úsalo cuando el código a generar involucre acceso a datos, autenticación, criptografía, consultas a bases de datos, manejo de archivos, dependencias externas, logging o manejo de excepciones.
---

# Directrices técnicas de mitigación OWASP Top 10:2025

## A01 — Broken Access Control

- Verifica siempre el rol o la identidad del usuario autenticado antes de permitir el acceso o la edición de un recurso ajeno.
- No confíes en identificadores enviados por el cliente (IDOR).

## A02 — Security Misconfiguration

- No uses configuraciones permisivas por defecto (por ejemplo, CORS con `*`).
- Desactiva el modo debug y evita exponer trazas de error al cliente.

## A03 — Software Supply Chain Failures

- Fija versiones específicas de las dependencias (pin de versión).
- No descargues ni ejecutes paquetes o scripts desde URLs sin verificación de integridad (hash o firma).

## A04 — Cryptographic Failures

- Utiliza algoritmos de hash diseñados para contraseñas (bcrypt, Argon2), nunca MD5, SHA1 ni SHA256 sin salteo.
- No incluyas claves criptográficas ni secretos en el código fuente.

## A05 — Injection

- Nunca concatenes entradas del usuario en consultas SQL; usa consultas parametrizadas u ORM.

## A06 — Insecure Design

- Los tokens de un solo uso deben ser aleatorios, de longitud suficiente, y expirar en un tiempo corto.
- Limita el número de intentos permitidos en flujos sensibles.

## A07 — Authentication Failures

- Las sesiones o tokens (JWT) deben tener expiración definida y ser verificados en cada solicitud.

## A08 — Software or Data Integrity Failures

- No utilices `pickle.load` ni `yaml.load` sin `Loader=SafeLoader` sobre datos externos.

## A09 — Security Logging and Alerting Failures

- Registra los eventos de seguridad relevantes sin exponer datos sensibles en texto plano.

## A10 — Mishandling of Exceptional Conditions

- Evita bloques `except` genéricos que oculten errores.
- Maneja explícitamente las excepciones esperables.