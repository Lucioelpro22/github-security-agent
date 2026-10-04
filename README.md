# GitHub Security Agent

Scaffold read-only para inventariar hallazgos de seguridad de GitHub y generar
planes de remediación verificables. La primera versión no modifica repositorios,
no cierra alertas, no rota secretos y no hace merge automático.

## Uso local

```bash
python -m pip install -e '.[dev]'
github-security-agent scan --owner Lucioelpro22 --repo github-security-agent
github-security-agent plan --owner Lucioelpro22 --repo github-security-agent --format json
```

Sin credenciales, el CLI ejecuta el proveedor offline vacío y devuelve un inventario
válido. La integración real de GitHub se incorporará detrás de la interfaz del
proveedor, con permisos mínimos y aprobación humana.

## Límites de seguridad

- `scan` y `plan` son operaciones de solo lectura.
- `--apply` no existe en esta versión inicial.
- No se aceptan tokens por argumentos de línea de comandos.
- Las pruebas no llaman a GitHub ni requieren credenciales.

