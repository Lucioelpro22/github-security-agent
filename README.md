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

## Visor local de informes

Abrí `dashboard/index.html` y seleccioná un JSON generado por cualquiera de estos comandos:

```bash
github-security-agent scan --owner OWNER --repo REPOSITORY --provider github --format json > github-report.json
github-security-agent scan-local . --format json > local-report.json
github-security-agent audit-dependencies . --format json > dependency-report.json
```

El visor admite contratos JSON v1 para los tres tipos. Procesa archivos de hasta 5 MiB y 5.000 elementos por informe (paquetes más avisos en auditorías), no los envía a servicios y no persiste el contenido. Los informes incompletos muestran una advertencia; en auditorías de dependencias, la severidad de OSV se mantiene como desconocida porque el informe fuente no incluye ese dato. Los informes pueden contener rutas, nombres de paquetes y títulos de avisos; tratá el JSON como información privada.

## Reglas locales iniciales

- Detecta algunos formatos conocidos de tokens y asignaciones de credenciales; nunca imprime el valor detectado.
- Señala permisos `write-all`, el evento `pull_request_target`, acciones de terceros sin SHA completo y expresiones de datos de eventos interpoladas directamente en `run`.
- Detecta opciones de contenedor explícitamente privilegiadas, ejecución configurada como UID 0, `USER root` en Dockerfiles y archivos `.env` distintos de ejemplos habituales.
- Los controles de workflows son heurísticos basados en texto, no una validación semántica de YAML. Revisá los hallazgos y posibles falsos positivos.
- El recorrido omite enlaces simbólicos, directorios comunes de dependencias/caché y archivos mayores de 1 MB; el presupuesto total es 25 MB y 10.000 archivos.

Sin credenciales, la integración remota usa el proveedor offline vacío. La API real es optativa y de solo lectura; el token se obtiene únicamente de una variable de entorno.

## Proveedor GitHub de solo lectura

```bash
export GITHUB_TOKEN="<token de corta duración o fine-grained>"
github-security-agent scan --owner OWNER --repo REPOSITORY --provider github
```

El proveedor consulta alertas abiertas de Dependabot, Code Scanning y Secret Scanning. El token fine-grained debe tener únicamente permisos **read** para esas tres categorías y estar limitado al repositorio objetivo. El valor del token no se admite por argumento ni se incluye en los informes. Secret Scanning se consulta con `hide_secret=true`; nunca se incluye el valor literal del secreto en los resultados.

Si falta un permiso, una función de alertas no está disponible, hay un error de red o se alcanza un límite, el comando termina con código 2 y no presenta un resultado parcial como inventario completo. El modo por defecto sigue siendo offline. Consultá [permisos, privacidad y límites](docs/github-provider.md) antes de habilitar la API.



## Auditoría opcional de dependencias

El comando `audit-dependencies` crea un inventario local desde `requirements.txt` (versiones exactas `==`), `package-lock.json`, `npm-shrinkwrap.json`, `poetry.lock`, `uv.lock`, `Cargo.lock` y `go.sum`. No instala paquetes, ejecuta scripts ni consulta la red por defecto:

```bash
github-security-agent audit-dependencies . --format markdown
github-security-agent audit-dependencies . --format json
```

Para consultar avisos de OSV.dev, habilitá explícitamente la consulta:

```bash
github-security-agent audit-dependencies . --query-osv --format markdown
```

La consulta envía únicamente nombre, ecosistema y versión exacta de cada dependencia; no envía archivos ni código fuente. Si activás `--query-osv`, se enviarán identificadores de paquetes y versiones a OSV.dev; pueden incluir nombres internos, paquetes npm privados, incluso cuando se resuelven desde `registry.npmjs.org` o `registry.yarnpkg.com` y rutas privadas de módulos Go. Las directivas de índice visibles en `requirements.txt` se respetan, pero una configuración externa de pip podría usar un índice privado y no se puede inferir desde ese archivo. En `uv.lock`, Poetry y Cargo, solo se consultan los paquetes cuyo origen sea un registro público reconocido; fuentes Git, URL, locales, desconocidas o índices alternativos permanecen en el inventario y no se envían. Yarn Classic requiere una URL `resolved` de `registry.npmjs.org` o `registry.yarnpkg.com`; Yarn Berry se inventaría, pero no se consulta porque el lockfile no confirma qué registro está configurado. `pnpm-lock.yaml` todavía no está soportado. En `requirements.txt` sin directivas de índice se asume PyPI, aunque una configuración externa de pip puede redirigir a otro registro. Los lockfiles no compatibles, las especificaciones sin versión exacta y los manifiestos no reconocidos se omiten. `go.sum` puede incluir versiones descargadas que ya no están seleccionadas en el módulo; interpretá esas entradas como inventario histórico, no como prueba de dependencias activas. El recorrido tiene límites de tamaño y cantidad; cualquier error de lectura, parseo o consulta aparece en el informe y marca el estado como incompleto. Los resultados de OSV.dev son orientativos y deben verificarse en la fuente antes de remediar.

## GitHub Action opcional

La acción de la raíz del repositorio ejecuta el escaneo local y el inventario de dependencias, y sube únicamente sus informes Markdown/JSON como artefacto de siete días, aislado en un directorio temporal por ejecución. El parámetro `path` debe apuntar a un directorio existente dentro del workspace. Primero hacé checkout del repositorio que querés analizar. Usá una referencia inmutable revisada o un release al consumirla; no uses `@main` en workflows de producción.

```yaml
name: Security report

on:
  pull_request:

permissions:
  contents: read

jobs:
  security-report:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: Lucioelpro22/github-security-agent@<reviewed-commit-sha>
        with:
          path: .
          query-osv: "false"
          fail-on-incomplete: "false"
```

La consulta a OSV.dev sigue desactivada por defecto; activá `query-osv: "true"` solo si aceptás enviar identificadores de paquetes validados y versiones exactas. El Action no recibe un token de GitHub ni necesita permisos de escritura. Los hallazgos no fallan el pipeline; `fail-on-incomplete: "true"` permite hacer fallar el job cuando un informe queda incompleto o no se puede subir el artefacto. El artefacto puede incluir rutas, nombres de paquetes y avisos; su acceso depende de los permisos del repositorio.

## Límites de seguridad

- `scan`, `plan` y `scan-local` son operaciones de solo lectura.
- No existe remediación automática en esta versión.
- No se aceptan tokens por argumentos de línea de comandos.
- El escaneo es local: el usuario controla qué directorio selecciona; los archivos del repositorio nunca se ejecutan.
- Las pruebas no llaman a GitHub ni requieren credenciales.
