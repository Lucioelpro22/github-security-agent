# Changelog

## Unreleased

- Aplica el límite de hallazgos durante su construcción y conserva las lecturas ancladas a descriptores seguros.
- Informa contenido NUL/no UTF-8 mediante `files_unsupported`, manteniendo el estado incompleto y el conteo `files_skipped`.
- Omite ejemplos comentados en las reglas heurísticas de workflows, sin omitir la detección de secretos en comentarios.

## 0.2.0 — 2026-10-06

- Corrige paginación por cursores de Dependabot y valida inventario autenticado completo el 2026-10-07.
- Endurece lecturas de archivos contra crecimiento y enlaces simbólicos; bloquea también redirecciones del cliente HTTP antiguo.

- Bloquea redirecciones HTTP en GitHub y OSV; prepara un smoke test autenticado manual sin publicar informes.

- Amplía el inventario offline a npm, Yarn, pnpm v9, Poetry, uv, Cargo, Go, Composer y Pipenv spec 6, además de requirements exactos.
- Conserva consultas OSV optativas y filtros de origen; Composer y Yarn Berry no se consultan.
- Corrige la presentación de inventarios parciales: manifests conocidos sin lockfile compatible y requirements no resueltos se marcan incompletos.
- Documenta la validación local en seis repositorios públicos, el tratamiento manual de fixtures sintéticos y la guía de instalación.
- Mantiene operaciones de solo lectura. No certifica aptitud productiva ni reemplaza una auditoría independiente.
