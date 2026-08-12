# Plan — Paridad de lenguajes (soporte de primera clase)

Go quedó con profundidad real: formato (gofmt), lint de AST (govet), semántica SSA (staticcheck), dependencias (trivy) y alcanzabilidad (govulncheck). Los demás lenguajes no. Este plan iguala esa profundidad donde tiene sentido — y dice explícitamente dónde **no**, porque añadir motores que duplican lo que ya hay es la sobre-ingeniería que este proyecto viene evitando.

## Qué significa "primera clase" — la matriz

Cinco dimensiones. Un lenguaje es de primera clase cuando las cinco están cubiertas o descartadas con razón.

| | Go | C# | Python | TS/JS | Java |
|---|---|---|---|---|---|
| **Formato** | gofmt ✅ | dotnet format ✅ | ruff ✅ | ❌ **hueco** | ❌ |
| **Lint / AST** | govet + staticcheck ✅✅ | ❌ **hueco** | ruff ✅ | ❌ **hueco** | ❌ |
| **Tipos** | compilado ✅ | ❌ **hueco** | ⚪ mypy (opcional) | tsc ✅ | ❌ |
| **Dependencias (SCA)** | trivy + govulncheck ✅✅ | ❌ **hueco** | trivy ✅ | trivy ✅ | trivy ✅ |
| **Reglas de la casa** | semgrep ✅ | semgrep ✅ | semgrep ✅ | semgrep ✅ | semgrep ✅ |

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

### P1 — TypeScript/JavaScript: formato y lint 🔵
El hueco más grande del producto: TS/JS sólo tenía tipos (tsc) y reglas de la casa.
- [ ] Motor `eslint` que corre **el linter que el repo ya configuró** (eslint o biome), detectado por su archivo de configuración
- [ ] Si el proyecto no configura ninguno, el motor no aplica — imponer un estilo que el equipo no eligió convierte al agente en un obstáculo
- [ ] Por archivo tocado (no el proyecto entero), con caché que incluye la huella de la configuración
- [ ] Severidad error → bloquea (§7); warning → avisa

### P2 — C#: compilador, analizadores Roslyn y CVEs de NuGet 🔵
- [ ] `dotnetbuild`: errores del compilador y diagnósticos de los analizadores, con `--no-restore` (el hook no puede depender de la red) y degradación explícita si falta el restore — nunca "limpio" cuando en realidad fue "no pude mirar"
- [ ] `dotnetvuln`: `dotnet list package --vulnerable`, el hueco medido de SCA; gateado por cambio de manifiestos como govulncheck, con día UTC en la clave de caché

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
