# Seguimiento Ruby — 9 de octubre de 2026

Se repitió la muestra Discourse del [informe de lockfiles](validation-lockfiles-2026-10-09.md): commit `7ee461ff2d3d8642575cda8788efb95441967210`, `Gemfile.lock` SHA-256 `5d496ef71e608d592884bd73eab5742445963b136d08d1704c0325407e121348`. Se conservaron los mismos archivos y no se ejecutaron Ruby, Bundler, Gemfile, scripts ni plugins.

## Causa

v0.3.3 exigía tres espacios en las entradas de `RUBY VERSION` y `BUNDLED WITH`. La muestra tiene dos espacios antes de `ruby 3.4.7p58` y `4.0.11`. Ambas secciones disparaban incomplete pese a conservar los 344 pares nombre/versión. Se acepta exactamente dos o tres espacios, manteniendo validación de contenido y unicidad de secciones. No se evalúan versiones de runtime ni requisitos de instalación.

## Resultado

Con el cambio, el inventario conserva los 344 pins sin omisiones ni extras y queda complete para los archivos seleccionados. Los orígenes son 286 registry-rubygems, 54 unknown y cuatro directory. Los pins con sufijo de plataforma permanecen unknown; rutas locales no se envían a OSV. La consulta sigue siendo optativa: esta validación no la activó. Al dejar de ser incompleto, los 286 pins con origen público reconocido pueden resultar elegibles si el usuario activa expresamente `--query-osv`; esto no prueba que sus nombres sean públicos.

Complete no demuestra el grafo instalado, la selección por plataforma ni ausencia de vulnerabilidades. El informe previo conserva el resultado histórico anterior a esta corrección. Nueve casos de regresión cubren ambas indentaciones y metadata inválida; las formas inválidas siguen incompletas y no conservan origen público consultable.
