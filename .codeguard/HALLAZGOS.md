# Hallazgos de CodeGuard

> **Estado: 9 bloqueante(s) pendiente(s)** · generado el 2026-08-09 00:46 · rulepack `2026.08.2`

## Instrucciones para el agente de código

Eres el agente encargado de resolver estos hallazgos. Reglas de trabajo:

1. **Atiende primero los BLOQUEANTES** — impiden hacer commit y el CI también los rechaza.
2. **Un hallazgo, un cambio, una verificación.** No agrupes correcciones no relacionadas.
3. **No suprimas la regla para callar el hallazgo** (nada de `// nolint`, `# noqa`,
   `@ts-ignore` ni añadir el fingerprint a la baseline). Corrige la causa.
4. **Verifica cada corrección** ejecutando lo que corresponda:
   - formato: `gofmt -w <archivo>` / `ruff format <archivo>` / `dotnet format`
   - tipos: `npx tsc --noEmit`
   - lint: `go vet ./...` / `ruff check <archivo>`
5. **Al terminar, ejecuta `codeguard report` otra vez.** El informe se regenera:
   lo resuelto pasa a la sección "✅ Resueltos" y, cuando no quede ningún
   bloqueante, el encabezado dirá **COMPLETADO**. Ese es el criterio de terminado —
   no tu impresión de haber terminado.
6. Si un hallazgo te parece un falso positivo, **no lo silencies**: anótalo en la
   sección "Discrepancias" al final y sigue con los demás.

---

## ⛔ Bloqueantes (9)

### 1. `require-concurrent-index-creation` — migrations/001_init.sql:43
<!-- fp:61a17959f372de542b7691c36e9ab5b2806ce7309778858de09f0bcfcd13cd4c -->

- [ ] **Pendiente** · pilar **datos** · motor `squawk` · severidad `error`

**Qué detectó:** Índice creado sin CONCURRENTLY: bloquea las escrituras mientras se construye

**Por qué importa:** Cambio de esquema con riesgo de lock o incompatibilidad. Pasar el lint no basta: aplica la migración con lock_timeout y statement_timeout configurados en Postgres.

**Cómo resolverlo:** Usa CREATE INDEX CONCURRENTLY. Tarda más y no puede ir dentro de una transacción, pero la tabla sigue aceptando escrituras.

**Archivo:** `migrations/001_init.sql` · **línea:** 43

### 2. `require-concurrent-index-creation` — migrations/001_init.sql:66
<!-- fp:61a17959f372de542b7691c36e9ab5b2806ce7309778858de09f0bcfcd13cd4c -->

- [ ] **Pendiente** · pilar **datos** · motor `squawk` · severidad `error`

**Qué detectó:** Índice creado sin CONCURRENTLY: bloquea las escrituras mientras se construye

**Por qué importa:** Cambio de esquema con riesgo de lock o incompatibilidad. Pasar el lint no basta: aplica la migración con lock_timeout y statement_timeout configurados en Postgres.

**Cómo resolverlo:** Usa CREATE INDEX CONCURRENTLY. Tarda más y no puede ir dentro de una transacción, pero la tabla sigue aceptando escrituras.

**Archivo:** `migrations/001_init.sql` · **línea:** 66

### 3. `require-concurrent-index-creation` — migrations/001_init.sql:67
<!-- fp:61a17959f372de542b7691c36e9ab5b2806ce7309778858de09f0bcfcd13cd4c -->

- [ ] **Pendiente** · pilar **datos** · motor `squawk` · severidad `error`

**Qué detectó:** Índice creado sin CONCURRENTLY: bloquea las escrituras mientras se construye

**Por qué importa:** Cambio de esquema con riesgo de lock o incompatibilidad. Pasar el lint no basta: aplica la migración con lock_timeout y statement_timeout configurados en Postgres.

**Cómo resolverlo:** Usa CREATE INDEX CONCURRENTLY. Tarda más y no puede ir dentro de una transacción, pero la tabla sigue aceptando escrituras.

**Archivo:** `migrations/001_init.sql` · **línea:** 67

### 4. `require-concurrent-index-creation` — migrations/001_init.sql:76
<!-- fp:61a17959f372de542b7691c36e9ab5b2806ce7309778858de09f0bcfcd13cd4c -->

- [ ] **Pendiente** · pilar **datos** · motor `squawk` · severidad `error`

**Qué detectó:** Índice creado sin CONCURRENTLY: bloquea las escrituras mientras se construye

**Por qué importa:** Cambio de esquema con riesgo de lock o incompatibilidad. Pasar el lint no basta: aplica la migración con lock_timeout y statement_timeout configurados en Postgres.

**Cómo resolverlo:** Usa CREATE INDEX CONCURRENTLY. Tarda más y no puede ir dentro de una transacción, pero la tabla sigue aceptando escrituras.

**Archivo:** `migrations/001_init.sql` · **línea:** 76

### 5. `require-concurrent-index-creation` — migrations/001_init.sql:128
<!-- fp:61a17959f372de542b7691c36e9ab5b2806ce7309778858de09f0bcfcd13cd4c -->

- [ ] **Pendiente** · pilar **datos** · motor `squawk` · severidad `error`

**Qué detectó:** Índice creado sin CONCURRENTLY: bloquea las escrituras mientras se construye

**Por qué importa:** Cambio de esquema con riesgo de lock o incompatibilidad. Pasar el lint no basta: aplica la migración con lock_timeout y statement_timeout configurados en Postgres.

**Cómo resolverlo:** Usa CREATE INDEX CONCURRENTLY. Tarda más y no puede ir dentro de una transacción, pero la tabla sigue aceptando escrituras.

**Archivo:** `migrations/001_init.sql` · **línea:** 128

### 6. `ruff-format` — spikes/s1-semgrep/generate_testrepo.py:1
<!-- fp:e3386511ff42e250ae91e2129854b7be692721d54088025c54352245fc7e2187 -->

- [ ] **Pendiente** · pilar **calidad** · motor `ruff` · severidad `error`

**Qué detectó:** Archivo sin formatear (ruff format)

**Por qué importa:** El formato inconsistente genera diffs ruidosos y discusiones sin valor.

**Cómo resolverlo:** Ejecuta `ruff format spikes/s1-semgrep/generate_testrepo.py` (es auto-corregible).

**Archivo:** `spikes/s1-semgrep/generate_testrepo.py` · **línea:** 1

### 7. `lockfile-ausente` — spikes/s3-foundry/go.mod:1
<!-- fp:c21104a820e69d31e859cedc7e4a7beabdf4a35162c0e3ea58236ce8f23685db -->

- [ ] **Pendiente** · pilar **seguridad** · motor `playbook` · severidad `error`

**Qué detectó:** go.mod cambió y el proyecto no tiene lockfile

**Por qué importa:** Sin lockfile cada instalación resuelve versiones por su cuenta: tu máquina, la de tu compañero y el CI pueden acabar con dependencias distintas, y una versión maliciosa recién publicada entra sola en el siguiente install.

**Cómo resolverlo:** Ejecuta `go mod tidy` y versiona el lockfile que genere (go.sum).

**Archivo:** `spikes/s3-foundry/go.mod` · **línea:** 1

### 8. `ruff-format` — spikes/s5-tsc-incremental/generate_project.py:1
<!-- fp:8c7f218e1413c26aaba732b09089df2cfd819b8fbfb7f9695c10018a5696ab6a -->

- [ ] **Pendiente** · pilar **calidad** · motor `ruff` · severidad `error`

**Qué detectó:** Archivo sin formatear (ruff format)

**Por qué importa:** El formato inconsistente genera diffs ruidosos y discusiones sin valor.

**Cómo resolverlo:** Ejecuta `ruff format spikes/s5-tsc-incremental/generate_project.py` (es auto-corregible).

**Archivo:** `spikes/s5-tsc-incremental/generate_project.py` · **línea:** 1

### 9. `I001` — spikes/s5-tsc-incremental/generate_project.py:3
<!-- fp:9802592b11420599450f45bb9115afb232f2fba99af80bf6aa295e746d3e245f -->

- [ ] **Pendiente** · pilar **calidad** · motor `ruff` · severidad `error`

**Qué detectó:** Import block is un-sorted or un-formatted

**Por qué importa:** Las reglas por defecto de Ruff (pyflakes + errores de sintaxis) son errores reales, no estilo.

**Cómo resolverlo:** Organize imports (auto-corregible con `ruff check --fix`).

**Archivo:** `spikes/s5-tsc-incremental/generate_project.py` · **línea:** 3

---

## Discrepancias

<!-- El agente anota aquí lo que considere falso positivo, con su razón.
     Un humano decide después: corregir la regla o aceptar el hallazgo. -->

---

## Contexto

- Deuda preexistente suprimida por la baseline: **10** (no bloquea; solo lo nuevo bloquea)
- Capas que no corrieron en este escaneo: ninguna
- Este informe lo genera `codeguard report` y se versiona con el repo.
