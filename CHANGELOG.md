# Changelog

## 0.2.0 — 2026-10-06

- Amplía el inventario offline a npm, Yarn, pnpm v9, Poetry, uv, Cargo, Go, Composer y Pipenv spec 6, además de requirements exactos.
- Conserva consultas OSV optativas y filtros de origen; Composer y Yarn Berry no se consultan.
- Corrige la presentación de inventarios parciales: manifests conocidos sin lockfile compatible y requirements no resueltos se marcan incompletos.
- Documenta la validación local en seis repositorios públicos, el tratamiento manual de fixtures sintéticos y la guía de instalación.
- Mantiene operaciones de solo lectura. No certifica aptitud productiva ni reemplaza una auditoría independiente.
