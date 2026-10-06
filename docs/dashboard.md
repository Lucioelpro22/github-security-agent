# Visor local de informes

El visor es una página estática ubicada en `dashboard/index.html`. No inicia un servidor, no carga scripts externos, no realiza llamadas de red y no lee variables de entorno. El token de GitHub solo se usa al generar el informe mediante el CLI.

## Flujo

1. Ejecutá un escaneo y guardá su salida JSON:

   ```bash
   github-security-agent scan --owner OWNER --repo REPOSITORY --provider github --format json > security-report.json
   ```

2. Abrí `dashboard/index.html` desde el repositorio en un navegador moderno.
3. Seleccioná `security-report.json`. El archivo se procesa en memoria; el visor no lo copia ni lo persiste.

El CLI solo emite JSON si el escaneo terminó correctamente. La salida incluye `schema_version: 1`, el proveedor y `status: complete`. El visor rechaza otras versiones, estados incompletos, esquemas inválidos, archivos mayores de 5 MB y más de 3.000 hallazgos. Si una carga falla, limpia la vista anterior.

## Datos y seguridad

- El visor conserva solo campos conocidos del informe; ignora campos extra como `secret` y `metadata`.
- Los valores, incluidos títulos remotos, se insertan como texto con `textContent`; no se interpreta HTML ni Markdown.
- El HTML usa una política CSP local y no referencia CDN, fuentes, imágenes ni servicios remotos.
- Muestra conteos por categoría y severidad, búsqueda de texto y filtros por categoría/severidad.
- Que un informe tenga estructura válida no prueba su autenticidad. Revisá que provenga de tu ejecución local del CLI.
- El JSON puede incluir nombres de repositorios, dependencias, reglas y títulos de alertas. Tratá el archivo como información privada y eliminálo al terminar si no necesitás conservarlo.

El visor es de lectura. No modifica repositorios, no cierra alertas, no rota secretos y no llama a la API de GitHub.
