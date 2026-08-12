# Plan — Paridad de lenguajes (soporte de primera clase)

Go quedó con profundidad real: formato (gofmt), lint de AST (govet), semántica SSA (staticcheck), dependencias (trivy) y alcanzabilidad (govulncheck). Los demás lenguajes no. Este plan iguala esa profundidad donde tiene sentido — y dice explícitamente dónde **no**, porque añadir motores que duplican lo que ya hay es la sobre-ingeniería que este proyecto viene evitando.

## Qué significa "primera clase" — la matriz

Cinco dimensiones. Un lenguaje es de primera clase cuando las cinco están cubiertas o descartadas con razón.

Estado al 2026-08-12, después de P1 y P2:

| | Go | C# | Python | TS/JS | Java |
|---|---|---|---|---|---|
| **Formato** | gofmt ✅ | dotnet format ✅ | ruff ✅ | eslint/biome ✅ | ❌ |
| **Lint / AST** | govet + staticcheck ✅✅ | dotnetbuild ✅ | ruff ✅ | eslint/biome ✅ | ❌ |
| **Tipos** | compilado ✅ | dotnetbuild ✅ | ⚪ mypy (opcional) | tsc ✅ | ❌ |
| **Dependencias (SCA)** | trivy + govulncheck ✅✅ | dotnetvuln ✅ | trivy ✅ | trivy ✅ | trivy ✅ |
| **Reglas de la casa** | semgrep ✅ | semgrep ✅ | semgrep ✅ | semgrep ✅ | semgrep ✅ |

Trece motores. Go sigue siendo el único con análisis de alcanzabilidad (govulncheck) y semántica SSA (staticcheck) — esa profundidad extra existe porque el toolchain de Go la regala; en los demás lenguajes su equivalente es de pago o no existe.

## Lo que la medición cambió del plan original

Antes de escribir código se verificó qué cubre trivy de verdad, con manifiestos vulnerables reales:

| Manifiesto | Resultado |
|---|---|
| `package-lock.json` | 2 CVE ✅ |
| `pom.xml` | 7 CVE ✅ |
| `requirements.txt` | 46 CVE ✅ |
| `package.json` sin lockfile | **0 — no lo mira** |
| `app.csproj` sin `packages.lock.json` | **0 — no lo mira** |

Consecuencias, todas con dato detrás:

- **`pip-audit`, `npm audit` y `owasp-dependency-check` NO se implementan.** Trivy ya cubre esos tres ecosistemas. Serían tres herramientas más que instalar, tres dependencias de red y hallazgos duplicados con otro nombre. Y el caso que trivy no cubre —manifiesto sin lockfile— ya lo señala la regla `lockfile-ausente` del playbook, que pide justamente el lockfile que habilita el escaneo. El sistema ya es coherente.
- **`dotnet list package --vulnerable` SÍ se implementa**: es el único hueco real de SCA medido (un `.csproj` suelto es invisible para trivy, y en .NET el lockfile no es la norma).
- **Java se aplaza, no se descarta.** No hay toolchain de Java en la máquina de desarrollo, ningún repo enrolado lo usa, y su SCA ya está cubierto por trivy. Construir `javac`/SpotBugs/`google-java-format` sin un repo Java donde probarlos sería construir sobre fe — la primera lección de este proyecto fue que los motores sin verificar real fallan en silencio. Se retoma cuando exista el repo.

## Fases

### P1 — TypeScript/JavaScript: formato y lint 🟢
El hueco más grande del producto: TS/JS sólo tenía tipos (tsc) y reglas de la casa.
- [x] Motor `eslint` que corre **el linter que el repo ya configuró** (eslint o biome), detectado por su archivo de configuración
- [x] Si el proyecto no configura ninguno, el motor no aplica — imponer un estilo que el equipo no eligió convierte al agente en un obstáculo
- [x] Desempate **por nivel, no global**: en cada directorio biome gana a eslint (un `biome.json` aparece porque alguien migró y el `.eslintrc` viejo queda atrás semanas), pero un biome en la raíz no secuestra un `frontend/` que eligió eslint
- [x] Por archivo tocado, con caché cuya clave lleva la huella de la config **y de los lockfiles**: en eslint las reglas viven en los plugins que la config extiende, así que subir `@typescript-eslint` cambia los hallazgos con el `.eslintrc` intacto
- [x] Severidad error → bloquea (§7); warning → avisa

**Validado en el repo corporativo de la forma más contundente**: el motor cazó un `@typescript-eslint/no-unused-vars` en `UnifiedFeedTimeline.tsx` **cinco segundos después de que otro agente escribiera esa línea** (marca del archivo 10:05:46, corrida 10:05:51). Antes de eso, dos corridas seguidas dieron 0 hallazgos y la discrepancia parecía un bug de determinismo — era código vivo cambiando bajo los pies.

**Dos lecciones de Windows que costaron un fallo real cada una:**
- El límite de línea de comandos aquí **no es 32767**. Los binarios de node son shims `.cmd` (scripts batch), así que Windows los pasa por `cmd.exe`, que corta en **8191**. El motor nació con 30000 copiando la razón de semgrep (que invoca un `.exe` de verdad) y murió en el primer repo real con frontend: `The command line is too long`, el mensaje de cmd.exe, no de Go. Ahora 6000.
- `--no-warn-ignored` **rompe eslint 8**: lo rechaza y sale con 2, o sea que pasarlo habría convertido en fallo duro todos los repos con eslint 8 + `.eslintrc`, que son muchos. Los avisos de "archivo ignorado" se filtran al parsear, que funciona en cualquier versión.

### P2 — C#: compilador, analizadores Roslyn y CVEs de NuGet 🟢
- [x] `dotnetbuild`: errores del compilador y diagnósticos de los analizadores, con `--no-restore` (el hook no puede depender de la red) y degradación explícita si falta el restore — nunca "limpio" cuando en realidad fue "no pude mirar". Tres capas para distinguirlo: códigos fatales conocidos, red de seguridad por el texto `project.assets.json` (un nombre de archivo no se traduce, así que aguanta un código nuevo en un SDK futuro), y "salió mal sin un error legible"
- [x] `dotnetvuln`: `dotnet list package --vulnerable`, el hueco medido de SCA; gateado por cambio de manifiestos como govulncheck, con día UTC en la clave de caché
- [x] La huella de caché sigue los `ProjectReference` transitivos: sin eso, un acierto de `Api` escondería el error que `Core` acaba de introducir, porque `dotnet build` compila los dos

**El hallazgo que no estaba en el plan, y es lo más importante de esta fase**: un build incremental que MSBuild considera "al día" imprime **cero avisos**. O sea que si el desarrollador ya compiló en su IDE —lo normal—, un `dotnet build` aquí habría devuelto "limpio" **sin mirar nada**: la compuerta existiría en el papel y no en la realidad, como le pasó a `tsc` con los monorepos. Se resolvió con `-t:Rebuild`, y para que no sea destructivo la compilación vive en `obj/codeguard/` (vía `BaseIntermediateOutputPath`/`BaseOutputPath`, dejando `MSBuildProjectExtensionsPath` en el `obj` real porque ahí está el `project.assets.json` que `--no-restore` necesita). Comprobado: el `bin/Debug` del dev queda intacto y su build sigue "al día". Hay un test que corre dos veces seguidas y exige que el aviso siga apareciendo — es la prueba de que el falso "limpio" no puede volver.

**Trampas del formato, todas con test:**
- `-clp:NoSummary` **no surte efecto en `dotnet build`** (sí en `dotnet msbuild`): el resumen tras "Build FAILED." repite cada diagnóstico literal, así que sin deduplicar cada error contaría doble. Lo mismo con multi-target, que emite el aviso una vez por TFM.
- Un proyecto **limpio** se serializa sin `frameworks`, **idéntico** a uno que no se pudo analizar, y **ambos salen con código 0**: lo único que los separa es el array `problems`. Es el `tipoFatal` de semgrep otra vez, y tiene dos tests que son las dos caras de la moneda.
- Las vulnerabilidades traen **sólo severidad y URL**: el identificador GHSA se saca del último segmento de la URL y la pista no puede prometer una versión corregida porque el comando no la da.

**Límite honesto**: verificado contra el SDK real (10.0.204) sobre proyectos de juguete con errores, avisos y CVEs deliberados — pero **no contra un repo C# real**, porque ninguno de los repos enrolados tiene C#. Cuando aparezca uno, ese es el primer sitio donde mirar.

### P3 — Python: tipos opcionales ⚪
- [ ] `mypy` **opt-in por repo**: en código sin anotaciones es puro ruido, y sólo aporta donde el equipo ya invirtió en type hints. Ruff ya cubre formato y lint.

### P4 — Java: cuando haya un repo Java 🔒
- [ ] `google-java-format` (formato, el más barato)
- [ ] SpotBugs o `javac -Xlint` (calidad; ojo: exige el classpath completo, o sea invocar Maven/Gradle)
- [ ] SCA: **ya cubierto por trivy** (`pom.xml`, `build.gradle`) — no se añade nada

## Fuera de alcance — con razón medida

`pip-audit`, `npm audit`, `owasp-dependency-check` (duplican trivy, verificado con CVEs reales) · `-warnaserror` en C# (inundaría de bloqueantes un código existente) · imponer eslint/prettier donde el repo no los configuró.

## Bitácora

- **2026-08-12** — Plan creado a partir de la propuesta del usuario, ajustado con dos mediciones: la cobertura real de trivy por ecosistema (tres SCA propuestos resultaron redundantes, uno resultó hueco real) y la ausencia de toolchain Java. P1 y P2 arrancan en paralelo.

<!-- verificacion del refactor del daemon -->
