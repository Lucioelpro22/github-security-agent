# Instalación y uso — v0.2.0

Versión para uso controlado y solo lectura. Python 3.11–3.13 es la matriz de CI validada. Instalar el agente no instala dependencias de los proyectos que se analizan.

```bash
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .

github-security-agent scan-local /ruta/al/repositorio --format json > local-report.json
github-security-agent audit-dependencies /ruta/al/repositorio --format json > dependency-report.json
```

Abrir `dashboard/index.html` y cargar uno de esos JSON. El visor no envía ni persiste el informe. Conservar los informes fuera del repositorio analizado para evitar que un siguiente escaneo analice sus propios resultados.

## Cómo interpretar resultados

- Salida 0: se completó el recorrido dentro de la cobertura declarada; puede haber hallazgos. No significa que el repositorio sea seguro.
- Salida 2: resultado incompleto o error. En auditorías revisar `errors`; no convertir cero paquetes en una auditoría limpia.
- Las dependencias de manifests sin lockfile compatible, los rangos y las inclusiones no resueltas dejan el inventario incompleto. Una carpeta con requirements compatibles no garantiza que cubran todo pyproject.toml.
- Los hallazgos en tests pueden ser sintéticos. Revisar el contexto sin suprimir automáticamente toda la carpeta ni divulgar valores.
- Los lockfiles indican versiones registradas, no garantizan qué se instaló. No se validan hashes, ejecución, explotación ni el entorno productivo.

OSV se activa exclusivamente con `--query-osv`; envía identificadores de paquetes y versiones, que pueden contener nombres privados. Ver README antes de activarlo. La validación de esta versión no hizo consultas OSV.

Para GitHub remoto, seguir [permisos y límites](github-provider.md). El token se obtiene de una variable de entorno y requiere únicamente los permisos de lectura documentados. El inventario remoto autenticado se completó el 2026-10-07 en el commit `ba42fa3`; ver [la ejecución](https://github.com/Lucioelpro22/github-security-agent/actions/runs/37614861333).

## Comprobaciones para contribuidores

```bash
python -m pip install -e '.[dev]'
python -m ruff check .
python -m mypy src
python -m pytest --cov
node --test tests/dashboard.test.cjs
```

Consultar [la validación real](validation-2026-10-06.md) y el [modelo de amenazas](threat-model.md). Usar un commit revisado e inmutable al consumir la GitHub Action. La etiqueta/release debe apuntar al commit que haya pasado CI; no se publica una etiqueta automáticamente con la edición del número de versión.

### Local scanning platform requirement

Local repository scanning requires POSIX descriptor-relative no-follow file opens to reject symlink races, including changes to parent directories. On Windows, run local scans in WSL. Native Windows `scan-local` scans fail closed: the CLI reports an incomplete inventory and the legacy `scan_directory` API raises `OSError`. GitHub API scanning is unaffected.
