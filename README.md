# GitHub Security Agent

Herramienta defensiva y de solo lectura para inventariar hallazgos de seguridad de GitHub y analizar archivos de repositorios localmente. No modifica repositorios, no cierra alertas, no rota secretos y no hace merge automático.

## Uso local

```bash
python -m pip install -e '.[dev]'
github-security-agent scan --owner Lucioelpro22 --repo github-security-agent
github-security-agent plan --owner Lucioelpro22 --repo github-security-agent --format json
github-security-agent scan-local . --format markdown
```

El comando `scan-local` analiza el directorio local como datos: no ejecuta scripts, instala dependencias ni hace llamadas de red. Genera un informe Markdown o JSON. Si el escaneo omite archivos por límites o errores de lectura, marca el resultado como incompleto y devuelve código de salida 2.

## Reglas locales iniciales

- Detecta algunos formatos conocidos de tokens y asignaciones de credenciales; nunca imprime el valor detectado.
- Señala permisos `write-all`, el evento `pull_request_target`, acciones de terceros sin SHA completo y expresiones de datos de eventos interpoladas directamente en `run`.
- Detecta opciones de contenedor explícitamente privilegiadas, ejecución configurada como UID 0, `USER root` en Dockerfiles y archivos `.env` distintos de ejemplos habituales.
- Los controles de workflows son heurísticos basados en texto, no una validación semántica de YAML. Revisá los hallazgos y posibles falsos positivos.
- El recorrido omite enlaces simbólicos, directorios comunes de dependencias/caché y archivos mayores de 1 MB; el presupuesto total es 25 MB y 10.000 archivos.

Sin credenciales, la integración remota sigue usando un proveedor offline vacío. La integración real de GitHub se incorporará detrás de la interfaz del proveedor, con permisos mínimos y aprobación humana.

## Límites de seguridad

- `scan`, `plan` y `scan-local` son operaciones de solo lectura.
- No existe remediación automática en esta versión.
- No se aceptan tokens por argumentos de línea de comandos.
- El escaneo es local: el usuario controla qué directorio selecciona; los archivos del repositorio nunca se ejecutan.
- Las pruebas no llaman a GitHub ni requieren credenciales.
