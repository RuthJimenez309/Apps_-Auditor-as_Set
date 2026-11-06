REPORTE TÉCNICO DE AUDITORÍA DE SEGURIDAD  

## 1. Resumen Ejecutivo
Este documento recopila las evidencias de seguridad obtenidas durante la ejecución automatizada del pipeline de pruebas SecOps sobre el ecosistema backend unificado. El motor evalúa vulnerabilidades del OWASP Top 10 bajo esquemas de validación estricta de datos.

## 2. Hallazgos de Seguridad Detectados

### Hallazgo #1: Broken Object Level Authorization (BOLA)
* **Severidad:** Alta (High)
* **Descripción:** Se detectó acceso no autorizado a un identificador de recurso directo sin validación de pertenencia ni sesión activa.
* **Evidencia Técnica:** Token evaluado intentó leer el recurso: `financial_reports_2026`.
* **Mitigación GRC:** Implementar validación de control de acceso basada en atributos (ABAC) verificando la relación del recurso con el identificador del usuario extraído del payload verificado por Zod.

### Hallazgo #2: SQL Injection Emulada
* **Severidad:** Alta (High)
* **Descripción:** Caracteres sospechosos detectados en el payload de entrada sin sanitización ni parametrización activa.
* **Evidencia Técnica:** Payload recibido: `SELECT * FROM users; --`.
* **Mitigación GRC:** Forzar el uso de consultas preparadas parametrizadas en la capa de persistencia y aplicar esquemas de validación con Zod para descartar patrones maliciosos en la entrada de datos.'
* 
* **Laboratorio practico by RJ
