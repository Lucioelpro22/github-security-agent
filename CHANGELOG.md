# Changelog

## Unreleased

- Acepta metadata `RUBY VERSION` y `BUNDLED WITH` con dos o tres espacios; corrige el estado incompleto de la muestra real de Discourse sin cambiar sus 344 pins ni activar consultas de red.

## 0.3.3 — 2026-10-09

- Corrige el inventario NuGet v1/v2 de targets antiguos con punto inicial, como `.NETStandard,Version=v2.0`; documenta la validación de lockfiles reales de Ruby, Gradle y NuGet.

## 0.3.2 — 2026-10-08

- Agrega inventario offline de locks de Gradle modernos y antiguos por configuración, con origen desconocido y exclusión de OSV; detecta cobertura incierta, entradas inválidas y límites alcanzados.

## 0.3.1 — 2026-10-08

- Agrega inventario offline de NuGet `packages.lock.json` v3 con aliases de frameworks y overlays RID; mantiene origen desconocido y exclusión total de OSV.

## 0.3.0 — 2026-10-08

- Corrige la Action para instalar PyYAML desde un wheel de PyPI antes de auditar y verifica los informes realmente subidos en el smoke test.

- Agrega inventario offline de NuGet `packages.lock.json` v1/v2, con referencias por framework y overlays RID; el origen permanece desconocido y ningún paquete NuGet se envía a OSV.
- Automatiza wheel, sdist, SHA256SUMS y procedencia de releases, condicionados a los checks exitosos del SHA exacto en main.

- Agrega inventario offline de `Gemfile.lock` para RubyGems, separando registros, Git y rutas locales; las consultas OSV siguen siendo optativas y restringidas por origen.

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
