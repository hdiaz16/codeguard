# Plan — Paridad de lenguajes (soporte de primera clase)

Go quedó con profundidad real: formato (gofmt), lint de AST (govet), semántica SSA (staticcheck), dependencias (trivy) y alcanzabilidad (govulncheck). Los demás lenguajes no. Este plan iguala esa profundidad donde tiene sentido — y dice explícitamente dónde **no**, porque añadir motores que duplican lo que ya hay es la sobre-ingeniería que este proyecto viene evitando.

## Qué significa "primera clase" — la matriz

Cinco dimensiones. Un lenguaje es de primera clase cuando las cinco están cubiertas o descartadas con razón.

Estado al 2026-08-12, después de P1 y P2:

| | Go | C# | Python | TS/JS | Java |
|---|---|---|---|---|---|
| **Formato** | gofmt ✅ | dotnet format ✅ | ruff ✅ | eslint/biome ✅ | google-java-format ✅ |
| **Lint / AST** | govet + staticcheck ✅✅ | dotnetbuild ✅ | ruff ✅ | eslint/biome ✅ | pmd ✅ |
| **Tipos** | compilado ✅ | dotnetbuild ✅ | ⚪ mypy (opcional) | tsc ✅ | ❌ descartado |
| **Dependencias (SCA)** | trivy + govulncheck ✅✅ | dotnetvuln ✅ | trivy ✅ | trivy ✅ | trivy ✅ |
| **Reglas de la casa** | semgrep ✅ | semgrep ✅ | semgrep ✅ | semgrep ✅ | semgrep ✅ |

Dieciséis motores. Go sigue siendo el único con análisis de alcanzabilidad (govulncheck) y semántica SSA (staticcheck) — esa profundidad extra existe porque el toolchain de Go la regala; en los demás lenguajes su equivalente es de pago o no existe.

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
- **Java se aplazó hasta tener un JDK, y se hizo en cuanto lo hubo.** El motivo del aplazamiento nunca fue el diseño sino la verificación: construir motores sin un toolchain donde ejecutarlos era construir sobre fe, y la primera lección de este proyecto fue que los motores sin verificar real fallan en silencio. Con un JDK 21 en la máquina, P4 se hizo y se midió contra él (ver abajo).

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

### P4 — Java: formato y calidad 🟢
- [x] `javafmt`: **google-java-format 1.36.1**, un jar que sólo mira el fuente (ni compila ni necesita classpath). Comprueba, nunca reescribe. Formato bloquea (§7)
- [x] `javalint`: **PMD 7.26.0** con `rulesets/java/quickstart.xml` (124 reglas). Prioridad 1-2 → error bloqueante; 3-5 → aviso
- [x] Los dos se instalan por el mismo mecanismo que gitleaks y trivy: versión fijada y SHA-256 en `motores.json`, verificado antes y después de instalar. Si no hay JDK el paso se omite sin fallar, como el de los motores de Go
- [x] SCA: **ya cubierto por trivy** (`pom.xml`, `build.gradle`) — no se añade nada

**SpotBugs descartado con razón, no por gusto**: analiza *bytecode*, o sea que exige un proyecto compilado — un `mvn compile` con red y minutos por delante, que no cabe en el camino del commit. PMD analiza el fuente: parsea cada archivo y evalúa las reglas sobre el AST. Por lo mismo se descartó `javac -Xlint` como compuerta de tipos: necesitaría el classpath completo, o sea invocar Maven o Gradle. Java se queda sin compuerta de tipos y eso está dicho en la matriz, no escondido.

**Tres cosas que sólo se supieron midiendo:**
- **PMD sale con 1 y aun así escribe un JSON válido con `"files": []`** cuando le pasas un archivo que no existe. Confiar en el JSON en vez de en el código de salida habría anunciado "proyecto limpio" sin analizar nada — el fallo de semgrep otra vez. Sólo 0, 4 y 5 significan "PMD miró"; el 5 (errores recuperables) trae además las violaciones de los demás archivos, así que no es un fallo.
- **google-java-format conserva el final de línea dominante del archivo**, así que un archivo CRLF bien formateado ni aparece en `--dry-run`. Aun así hay segunda pasada por archivo señalado que compara normalizando a LF: es lo que garantiza que autocrlf no bloquee un commit, sin depender de que esa detección siga igual en la versión siguiente.
- **No se invoca `pmd.bat`, se invoca `java` directo.** Dos motivos: el `.bat` pasa por `cmd.exe` y hereda su límite de 8191 caracteres (la avería de P1), y sin java en el PATH imprime "No java executable found" y sale con 2 — un fallo normal para Go, sin el centinela `exec.ErrNotFound`, así que el orquestador diría "pmd:error" en vez de "falta: pmd".

**Límite honesto**: verificado contra un JDK 21.0.12 real sobre un proyecto de juguete con los tres casos (mal formateado, con violaciones, limpio), pero **no contra un repo Java real** — ninguno de los repos enrolados tiene Java. Y hoy no se puede usar el ruleset propio de un repo que ya tenga PMD cableado: correría quickstart igual, que contradiría la decisión de ese equipo. Es el primer sitio donde mirar cuando aparezca el repo.

## Fuera de alcance — con razón medida

`pip-audit`, `npm audit`, `owasp-dependency-check` (duplican trivy, verificado con CVEs reales) · `-warnaserror` en C# (inundaría de bloqueantes un código existente) · imponer eslint/prettier donde el repo no los configuró · SpotBugs y `javac -Xlint` en Java (exigen compilar el proyecto, que no cabe en un pre-commit).

## Bitácora

- **2026-08-12** — Plan creado a partir de la propuesta del usuario, ajustado con dos mediciones: la cobertura real de trivy por ecosistema (tres SCA propuestos resultaron redundantes, uno resultó hueco real) y la ausencia de toolchain Java. P1 y P2 arrancan en paralelo.
- **2026-08-12** — P4 hecho en cuanto hubo un JDK 21 en la máquina: `javafmt` (google-java-format 1.36.1) y `javalint` (PMD 7.26.0), instalados con hash fijado como gitleaks y trivy. Java pasa de dos casillas a cuatro; la de tipos queda descartada con razón. Con esto la matriz sólo tiene un hueco abierto: los tipos de Python, que son opt-in por diseño.
