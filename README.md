# GitHub Security Agent

Herramienta defensiva y de solo lectura para inventariar hallazgos de seguridad de GitHub y analizar archivos de repositorios localmente. No modifica repositorios, no cierra alertas, no rota secretos y no hace merge automático.

Ver [instalación y uso](docs/getting-started.md), [validación en repositorios reales](docs/validation-2026-10-06.md) y [cambios de v0.3.0](CHANGELOG.md).

## Uso local

```bash
python -m pip install -e '.[dev]'
github-security-agent scan --owner Lucioelpro22 --repo github-security-agent
github-security-agent plan --owner Lucioelpro22 --repo github-security-agent --format json
github-security-agent scan-local . --format markdown
```

El comando `scan-local` analiza el directorio local como datos: no ejecuta scripts, instala dependencias ni hace llamadas de red. Genera un informe Markdown o JSON. Si el escaneo omite archivos por límites o errores de lectura, marca el resultado como incompleto y devuelve código de salida 2. El contenido con bytes NUL o no UTF-8 también deja el informe incompleto: `files_unsupported` cuenta esos casos como un subconjunto de `files_skipped`. La extensión del archivo no basta para excluirlo.

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
- El recorrido omite enlaces simbólicos, directorios comunes de dependencias/caché y archivos mayores de 1 MB; el presupuesto total es 25 MB y 10.000 archivos. El límite de 5.000 hallazgos se aplica durante su construcción, incluso en un solo archivo; al alcanzarlo, el informe queda incompleto. Las lecturas conservan el anclaje por descriptores que rechaza enlaces simbólicos en todos los componentes.

Sin credenciales, la integración remota usa el proveedor offline vacío. La API real es optativa y de solo lectura; el token se obtiene únicamente de una variable de entorno.

## Lockfiles de Ruby

`Gemfile.lock` se interpreta como datos: no se evalúan `Gemfile`, gemspecs, scripts ni plugins de Bundler. El inventario distingue paquetes de registros (`GEM`), Git (`GIT`) y rutas locales (`PATH`); no demuestra qué paquetes están instalados ni resuelve restricciones de versiones. Comprueba la presencia de referencias directas y transitivas dentro del lockfile.

OSV permanece desactivado por defecto. Con `--query-osv`, solo se envían nombres y versiones exactas de paquetes con una fuente HTTPS única en la raíz de `rubygems.org`. Orígenes privados, múltiples o ambiguos, Git, rutas y versiones con sufijo de plataforma quedan fuera de las consultas. Un nombre puede ser privado incluso cuando el lockfile declara un registro público. No se consultan URLs ni se verifica la validez de credenciales.

Las secciones no soportadas, registros inválidos y referencias faltantes dejan la cobertura incompleta y deshabilitan consultas OSV para los paquetes de ese lockfile. `CHECKSUMS` se trata como metadata; no se descargan paquetes ni se comprueba su integridad. Las variantes de plataforma se conservan sin afirmar qué variante instala cada entorno. `CONTENT ADDRESSES` y fuentes de plugins todavía no están soportadas.

## Lockfiles de NuGet

Inventaría `packages.lock.json` y `packages.<nombre_del_proyecto>.lock.json` en formatos 1 y 2. Reconoce proyectos `.csproj`, `.fsproj` y `.vbproj`; busca compañeros en la misma carpeta y sustituye espacios por guiones bajos en el nombre del lockfile. El formato 3 y los proyectos sin un compañero compatible dejan la cobertura incompleta. Las ubicaciones personalizadas de `NuGetLockFilePath` no se infieren.

Conserva paquetes Direct, Transitive y CentralTransitive; los nodos Project solo participan en la validación de referencias. Los overlays RID heredan únicamente su framework base y las referencias se comparan sin distinguir mayúsculas. No ejecuta .NET, MSBuild ni configuración de feeds; no verifica restricciones de versiones, `contentHash` ni el grafo instalado actualmente.

El lockfile no confirma el registro de origen. Todos los paquetes NuGet permanecen con origen desconocido y fuera de OSV, incluso con `--query-osv`; en ese caso la consulta queda incompleta. JSON duplicado, entradas inválidas, referencias faltantes y límites alcanzados también dejan el inventario incompleto.

## Proveedor GitHub de solo lectura

```bash
export GITHUB_TOKEN="<token de corta duración o fine-grained>"
github-security-agent scan --owner OWNER --repo REPOSITORY --provider github
```

El proveedor consulta alertas abiertas de Dependabot, Code Scanning y Secret Scanning. El token fine-grained debe tener únicamente permisos **read** para esas tres categorías y estar limitado al repositorio objetivo. El valor del token no se admite por argumento ni se incluye en los informes. Secret Scanning se consulta con `hide_secret=true`; nunca se incluye el valor literal del secreto en los resultados.

Si falta un permiso, una función de alertas no está disponible, hay un error de red o se alcanza un límite, el comando termina con código 2 y no presenta un resultado parcial como inventario completo. El modo por defecto sigue siendo offline. Consultá [permisos, privacidad y límites](docs/github-provider.md) antes de habilitar la API.



## Auditoría opcional de dependencias

El comando `audit-dependencies` crea un inventario local desde `requirements.txt` (versiones exactas `==`), `package-lock.json`, `npm-shrinkwrap.json`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `go.sum`, `composer.lock` y `Pipfile.lock`. No instala paquetes, ejecuta scripts ni consulta la red por defecto:

```bash
github-security-agent audit-dependencies . --format markdown
github-security-agent audit-dependencies . --format json
```

Para consultar avisos de OSV.dev, habilitá explícitamente la consulta:

```bash
github-security-agent audit-dependencies . --query-osv --format markdown
```

La consulta envía únicamente nombre, ecosistema y versión exacta de cada dependencia; no envía archivos ni código fuente. Si activás `--query-osv`, se enviarán identificadores de paquetes y versiones a OSV.dev; pueden incluir nombres internos, paquetes npm privados, incluso cuando se resuelven desde `registry.npmjs.org` o `registry.yarnpkg.com` y rutas privadas de módulos Go. Las directivas de índice visibles en `requirements.txt` se respetan, pero una configuración externa de pip podría usar un índice privado y no se puede inferir desde ese archivo. En `uv.lock`, Poetry y Cargo, solo se consultan los paquetes cuyo origen sea un registro público reconocido; fuentes Git, URL, locales, desconocidas o índices alternativos permanecen en el inventario y no se envían. Yarn Classic requiere una URL `resolved` de `registry.npmjs.org` o `registry.yarnpkg.com`; Yarn Berry se inventaría, pero no se consulta porque el lockfile no confirma qué registro está configurado. `pnpm-lock.yaml` admite solo el formato v9; procesa los documentos del entorno y del proyecto, y solo considera paquetes presentes en `snapshots`. Para OSV exige un tarball HTTPS de `registry.npmjs.org`; los demás orígenes se inventarían como desconocidos o alternativos y no se consultan. Los locators sin versión npm exacta, como referencias Git, dejan el informe incompleto en esta versión. Aun con host público, el nombre puede corresponder a un paquete privado. En `requirements.txt` sin directivas de índice se asume PyPI, aunque una configuración externa de pip puede redirigir a otro registro. `composer.lock` inventaría `packages` y `packages-dev` como ecosistema Packagist, conservando versiones de etiquetas y ramas literalmente. No ejecuta plugins, scripts ni Composer; no interpreta `require`, `provide`, `replace`, alias o requisitos de plataforma como paquetes instalados. Las URLs de descarga o Git no prueban el registro de origen: todos los paquetes Composer quedan con origen desconocido y fuera de OSV, incluso con `--query-osv` (consulta incompleta). Las listas faltantes, identificadores inválidos, paquetes duplicados o claves JSON duplicadas dejan el inventario incompleto. `Pipfile.lock` admite la especificación 6 e inventaría `default`, `develop` y categorías personalizadas; conserva los pins de todas las categorías sin evaluar markers ni instalar paquetes. Solo consulta OSV cuando el campo `index` explícito apunta a una fuente única con URL HTTPS exacta `https://pypi.org/simple` y `verify_ssl: true`. Índices privados, URLs con credenciales, entradas Git/path/file/editable y entradas sin índice permanecen fuera de OSV. No expande variables en URLs ni infiere el índice por defecto. Entradas sin versión exacta `==`, versiones de formato no admitido, índices inexistentes, metadata inválida o claves JSON duplicadas dejan el inventario incompleto. Este parser no comprueba hashes ni garantiza qué paquetes están instalados en el entorno actual. Las entradas de requirements sin versión exacta y las inclusiones no resueltas se omiten del inventario y marcan el informe incompleto. Declaraciones conocidas (`pyproject.toml`, `package.json`, `composer.json`, `Pipfile`, `Cargo.toml`, `go.mod`, `Gemfile`, `pom.xml`) sin un lockfile compatible en la misma carpeta también marcan cobertura desconocida. No se infiere que un requirements cubra todo pyproject.toml; manifests no reconocidos todavía pueden quedar fuera del recorrido. `go.sum` puede incluir versiones descargadas que ya no están seleccionadas en el módulo; interpretá esas entradas como inventario histórico, no como prueba de dependencias activas. El recorrido tiene límites de tamaño y cantidad; cualquier error de lectura, parseo o consulta aparece en el informe y marca el estado como incompleto. Los resultados de OSV.dev son orientativos y deben verificarse en la fuente antes de remediar.

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
