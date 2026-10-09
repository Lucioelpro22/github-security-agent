# Validación de lockfiles reales — 9 de octubre de 2026

Se validaron archivos seleccionados de tres repositorios públicos, con commits fijados. No se ejecutaron sus proyectos, scripts, gestores ni plugins; no se instalaron sus dependencias y no se consultó OSV. Se usó v0.3.2 (`2060b1928b68e0a009b3a4948f14edde86360e80`) y se repitió la comparación con la corrección descrita abajo. No es un escaneo de todos los archivos de esos repositorios ni una auditoría de sus vulnerabilidades.

| Muestra | Commit | Entradas inventariadas | Resultado tras corrección |
|---|---|---:|---|
| discourse/discourse — Ruby | `7ee461ff2d3d8642575cda8788efb95441967210` | 344 | incomplete |
| pagopa/p4pa-workflow-hub — Gradle | `1463c9ff50a5c7c6a282e696e9642bbd1ddae870` | 220 | complete |
| bpwhelan/Jimakufin — NuGet | `1d5a2f679824a7988a73e4c053e9aa166f591567` | 94 | complete |

## Comparación

Ruby: se extrajeron independientemente las líneas de specs con cuatro espacios y nombre/versión entre paréntesis. Los 344 pares distintos coinciden. El parser conserva el estado incompleto ante formas no soportadas del lockfile; este resultado no prueba validación completa de referencias ni selección por plataforma. Los orígenes quedan directory/unknown y no se consultaron avisos.

Gradle: se separaron coordenadas y configuraciones de cada línea no comentada, excluyendo `empty=`. Los 220 pares distintos coinciden sin omisiones ni extras. Se incluyó `build.gradle.kts` como declaración compañera. Complete expresa la cobertura de estos archivos, no el grafo instalado ni todas las configuraciones del build; todos los orígenes permanecen desconocidos.

NuGet: se recorrieron con JSON los nodos de cada target de tres locks, excluyendo nodos Project. Tras la corrección coinciden los 57 pares distintos; el agente conserva 94 entradas porque distingue el lockfile de origen. Las tres declaraciones csproj compañeras se incluyeron sin ejecutarlas. Los orígenes siguen desconocidos; no se verificaron hashes, restricciones ni instalaciones.

## Problema reproducido y corregido

v0.3.2 rechazaba targets v1/v2 que empiezan con punto, como `.NETStandard,Version=v2.0`. En el lock raíz de Jimakufin omitía ocho entradas (siete pares no presentes en otros locks), conservaba 86 entradas y marcaba incomplete. Se permite un punto inicial opcional manteniendo límites de longitud, caracteres y RID. Con el cambio se inventarían las 94 entradas y no quedan diferencias. Tres pruebas de regresión cubren NETStandard, NETFramework y un overlay RID. No se amplía el acceso de red ni la elegibilidad para OSV.

## Evidencia y reproducción

[El registro JSON](validation-lockfiles-2026-10-09.json) conserva commits, rutas y SHA-256 de cada archivo leído, conteos, diferencias y errores. Obtener esos archivos desde el commit registrado y mantener sus rutas relativas en una carpeta aislada; ejecutar `github-security-agent audit-dependencies CARPETA --format json` sin `--query-osv`. Los manifests son datos y no deben ejecutarse. Los hashes permiten comprobar los bytes de la muestra, no la integridad de los paquetes.

Pasaron 405 pruebas Python, Ruff y mypy tras la corrección. La muestra es pequeña: un proyecto Ruby, uno Gradle y tres locks NuGet de un proyecto; no cubre locks Gradle antiguos, NuGet v2/v3, todos los orígenes ni exactitud estadística. Esos formatos mantienen pruebas sintéticas. El documento de validación del 6 de octubre conserva su contexto histórico.
