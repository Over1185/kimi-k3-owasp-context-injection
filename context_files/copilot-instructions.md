# Checklist de codificación segura

Antes de entregar cualquier fragmento de código, confirma lo siguiente:

- [ ] ¿Se valida la identidad y el rol del usuario antes de acceder o modificar un recurso?
- [ ] ¿Las consultas a bases de datos usan parámetros en vez de concatenación?
- [ ] ¿Las contraseñas se almacenan con un algoritmo de hash seguro?
- [ ] ¿Los tokens de sesión o recuperación tienen expiración y son suficientemente aleatorios?
- [ ] ¿Se evita exponer trazas de error o información interna al cliente?
- [ ] ¿Se evita el uso de deserialización insegura sobre datos externos?
- [ ] ¿Se registran los eventos de seguridad relevantes sin exponer datos sensibles en los logs?
- [ ] ¿Las excepciones se manejan explícitamente, sin bloques `except` vacíos o genéricos?