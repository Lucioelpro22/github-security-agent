# Visor local de informes

`dashboard/index.html` es un visor estático de solo lectura. No inicia un servidor, no carga scripts externos, no realiza llamadas de red y no lee variables de entorno. Admite informes completos o parciales de `scan`/`plan`, `scan-local` y `audit-dependencies` mediante contratos JSON v1 identificados por `report_type`. Las salidas incompletas se muestran con una advertencia visible y sus errores permitidos; nunca se presentan como completas.

## Flujo

Generá cualquiera de estos informes JSON:

```bash
github-security-agent scan --owner OWNER --repo REPOSITORY --provider github --format json > github-report.json
github-security-agent scan-local . --format json > local-report.json
github-security-agent audit-dependencies . --format json > dependency-report.json
# Opcional: consulta de avisos OSV, envía nombres/ecosistemas/versiones exactas a OSV.dev
github-security-agent audit-dependencies . --query-osv --format json > dependency-report.json
```

Abrí `dashboard/index.html` en un navegador y seleccioná el JSON. El archivo se procesa en memoria. No se copia ni persiste; el token de GitHub solo se usa en el CLI para generar el informe remoto.

## Qué muestra

- **scan/plan:** hallazgos de Dependabot, Code Scanning y Secret Scanning con la severidad que informa GitHub.
- **scan-local:** regla, resumen, severidad, confianza, archivo y línea, y recomendación. Las rutas absolutas nunca se muestran.
- **audit-dependencies:** inventario de paquetes en una tabla separada y avisos OSV en el listado. El formato fuente no provee severidad para los avisos; el visor los marca como no incluida y no infiere una clasificación.
- Una consulta OSV no solicitada se distingue de una consulta completa sin avisos y de una consulta incompleta. “Sin avisos devueltos” no significa que el paquete no tenga vulnerabilidades.
- Búsqueda por texto, filtro por categoría y severidad, conteos según la fuente y estado del informe.

## Límites y privacidad

- Acepta archivos de hasta 5 MiB y hasta 5.000 hallazgos, paquetes o avisos por colección. Si el tamaño o cantidad excede el límite, rechaza el archivo completo; no trunca en silencio.
- Solo conserva campos permitidos para cada tipo. Campos adicionales como `secret`, `token`, `metadata` y respuestas crudas se descartan.
- Los datos remotos, rutas, nombres de paquetes y textos de OSV se muestran como texto plano con `textContent`; no se interpretan HTML/Markdown ni se generan enlaces.
- El HTML establece CSP local, no referencia CDNs y bloquea conexiones.
- El JSON puede contener nombres de repositorios, archivos, dependencias, reglas y avisos; tratá el informe como información privada. Una estructura válida no prueba autenticidad, así que verificá que el archivo provenga de tu ejecución local del CLI.
- Informes incompatibles o malformados limpian cualquier vista anterior. El visor nunca modifica repositorios, cierra alertas, rota secretos ni llama a GitHub.
