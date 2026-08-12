# Hallazgos de CodeGuard

> **Estado: 2 bloqueante(s) pendiente(s)** · generado el 2026-08-12 11:46 · rulepack `2026.08.2`

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

## ⛔ Bloqueantes (2)

### 1. `go-dinero-float` — internal/config/config.go:107
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `error`

**Qué detectó:** Importe monetario en float64. Usa int64 en centavos o shopspring/decimal.

**Archivo:** `internal/config/config.go` · **línea:** 107

### 2. `go-dinero-float` — internal/config/config.go:108
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `error`

**Qué detectó:** Importe monetario en float64. Usa int64 en centavos o shopspring/decimal.

**Archivo:** `internal/config/config.go` · **línea:** 108

---

## ⚠️ Avisos (64) — opcionales, no bloquean

### 1. `GO-2026-5970` — internal/store/store.go:59
<!-- fp: -->

- [ ] **Pendiente** · pilar **seguridad** · motor `govulncheck` · severidad `error`

**Qué detectó:** GO-2026-5970 alcanzable: el código llama a golang.org/x/text/unicode/norm.Transform (golang.org/x/text@v0.37.0). Infinite loop on invalid input in golang.org/x/text

**Por qué importa:** Cadena de suministro (OWASP A03 2025) con prueba de alcanzabilidad: no es sólo que la dependencia tenga un CVE — el grafo de llamadas demuestra que este código ejecuta la función vulnerable.

**Cómo resolverlo:** Actualiza golang.org/x/text de v0.37.0 a v0.39.0.

**Archivo:** `internal/store/store.go` · **línea:** 59

### 2. `complejidad-excesiva` — cmd/codeguard/graphcmd.go:25
<!-- fp:c29ecb77acbd312454b214019ebc81aa68b827ea7f28449bf86b24780cce477d -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** graphCmd tiene complejidad 24 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/graphcmd.go` · **línea:** 25

### 3. `complejidad-excesiva` — cmd/codeguard/hook.go:70
<!-- fp:8c75ec729fd1fd6d88b0e6a1ce49d0de23d44f9c3b7f34db2e2b483becaa8dc5 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** runPreCommit tiene complejidad 26 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/hook.go` · **línea:** 70

### 4. `complejidad-excesiva` — cmd/codeguard/initcmd.go:28
<!-- fp:97b28fbf95252a86d5592f167399567e36b35b8ce30894543b40944c6a1055fa -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** initCmd tiene complejidad 28 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/initcmd.go` · **línea:** 28

### 5. `complejidad-excesiva` — cmd/codeguard/main.go:69
<!-- fp:b948bc3a763ee5cb9fc4230b67847ab4996c75793f866d1f9d17135a85a61a6f -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** ciCmd tiene complejidad 17 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/main.go` · **línea:** 69

### 6. `parametros-excesivos-go` — cmd/codeguard/main.go:195
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** Más de 5 parámetros posicionales. Agrupa en un struct con nombres.

**Archivo:** `cmd/codeguard/main.go` · **línea:** 195

### 7. `complejidad-excesiva` — cmd/codeguard/reportcmd.go:33
<!-- fp:4e9c03ab5c9a0c396c1e07dcc712a3f9f6012fc3c760986bf7cf2f45bb4df3c1 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** reportCmd tiene complejidad 20 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/reportcmd.go` · **línea:** 33

### 8. `parametros-excesivos-go` — cmd/codeguard/reportcmd.go:216
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** Más de 5 parámetros posicionales. Agrupa en un struct con nombres.

**Archivo:** `cmd/codeguard/reportcmd.go` · **línea:** 216

### 9. `complejidad-excesiva` — cmd/codeguard/reportcmd.go:216
<!-- fp:ce497d09f621afc5f282b9fe851c58510bffeccc346d913688d19df26e858f19 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** construirInforme tiene complejidad 16 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/reportcmd.go` · **línea:** 216

### 10. `complejidad-excesiva` — cmd/codeguard/statscmd.go:13
<!-- fp:ba34f00ac867335d0aba3e2d78db49d62168a6c4f103e0340f8517aa13e7f92a -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** statsCmd tiene complejidad 21 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/statscmd.go` · **línea:** 13

### 11. `complejidad-excesiva` — cmd/codeguard/statuscmd.go:72
<!-- fp:829f9a6a08c7bf381c5ab670cece77e55534ed997b81109095cd9ec2cfc5382b -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** revisarRepo tiene complejidad 26 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/codeguard/statuscmd.go` · **línea:** 72

### 12. `complejidad-excesiva` — cmd/daemon/main.go:195
<!-- fp:7efbe2db8db83dd1757ac2753353dfd662878ff0fdac8537e986e1a7007541ac -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** main tiene complejidad 95 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `cmd/daemon/main.go` · **línea:** 195

### 13. `CVE-2026-56852` — go.mod:1
<!-- fp: -->

- [ ] **Pendiente** · pilar **seguridad** · motor `trivy` · severidad `warning`

**Qué detectó:** CVE-2026-56852 en golang.org/x/text@v0.37.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input

**Por qué importa:** OWASP A03 2025 (cadena de suministro): una dependencia con CVE conocido es superficie de ataque directa.

**Cómo resolverlo:** Actualiza golang.org/x/text de v0.37.0 a 0.39.0.

**Archivo:** `go.mod` · **línea:** 1

### 14. `complejidad-excesiva` — internal/codegraph/gograph.go:102
<!-- fp:8e80ce581c0b316a421b791839fff8826fdaae7144a24a4672b2bc2ccef5a722 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** BuildGo tiene complejidad 26 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/codegraph/gograph.go` · **línea:** 102

### 15. `parametros-excesivos-go` — internal/codegraph/gograph.go:203
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** Más de 5 parámetros posicionales. Agrupa en un struct con nombres.

**Archivo:** `internal/codegraph/gograph.go` · **línea:** 203

### 16. `complejidad-excesiva` — internal/codegraph/tsgraph.go:43
<!-- fp:dac858caae0950434b2015608978294dce927e7561a360a91da50f20cd9b5ff7 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** BuildTS tiene complejidad 30 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/codegraph/tsgraph.go` · **línea:** 43

### 17. `complejidad-excesiva` — internal/daemon/daemon.go:303
<!-- fp:57318db18df378f49fbf12a21889ebec1a4f9369fff32cfb8e250b80680a96d3 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Server.Analyze tiene complejidad 19 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/daemon/daemon.go` · **línea:** 303

### 18. `go-test-saltado` — internal/engines/govulncheck/govulncheck_test.go:170
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/govulncheck/govulncheck_test.go` · **línea:** 170

### 19. `go-test-saltado` — internal/engines/govulncheck/govulncheck_test.go:173
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/govulncheck/govulncheck_test.go` · **línea:** 173

### 20. `complejidad-excesiva` — internal/engines/linters/dotnetbuild_test.go:407
<!-- fp:81d64e9ac065f050e2656d0be7ce67c3388a25d1b8fba76eb177efe5b99587dd -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestIntegracionCompilaErroresYAvisosReales tiene complejidad 20 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/linters/dotnetbuild_test.go` · **línea:** 407

### 21. `go-test-saltado` — internal/engines/linters/dotnetbuild_test.go:409
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/dotnetbuild_test.go` · **línea:** 409

### 22. `go-test-saltado` — internal/engines/linters/dotnetbuild_test.go:412
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/dotnetbuild_test.go` · **línea:** 412

### 23. `complejidad-excesiva` — internal/engines/linters/dotnetvuln_test.go:157
<!-- fp:b1a8f40cb37c12325af46a2be94776dc6e90d360c342df6b3fad85854ec51271 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestCVEsDePaqueteDeclaradoMapeanSeveridadYPolitica tiene complejidad 19 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/linters/dotnetvuln_test.go` · **línea:** 157

### 24. `go-test-saltado` — internal/engines/linters/dotnetvuln_test.go:373
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/dotnetvuln_test.go` · **línea:** 373

### 25. `go-test-saltado` — internal/engines/linters/dotnetvuln_test.go:376
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/dotnetvuln_test.go` · **línea:** 376

### 26. `complejidad-excesiva` — internal/engines/linters/eslint.go:216
<!-- fp:1d52e67107764d49bb61aece4add0795938a3f54f5796cf197b407505c329c20 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** ESLint.correrProyectoJS tiene complejidad 18 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/linters/eslint.go` · **línea:** 216

### 27. `complejidad-excesiva` — internal/engines/linters/eslint_test.go:61
<!-- fp:1a6d951fc154314e0ddbecff3f7ecf8bab368ed092a6669ee33515ad953c62d1 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestHallazgosESLintMapeaSeveridadesYArreglos tiene complejidad 24 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 61

### 28. `complejidad-excesiva` — internal/engines/linters/eslint_test.go:201
<!-- fp:1e716b077b3a34ecaf499a787893e136a526df16b4c5e4bfd5d8aa005bbfc162 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestHallazgosBiomeMapeaSeveridadesYFormato tiene complejidad 21 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 201

### 29. `go-test-saltado` — internal/engines/linters/eslint_test.go:618
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 618

### 30. `go-test-saltado` — internal/engines/linters/eslint_test.go:622
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 622

### 31. `go-test-saltado` — internal/engines/linters/eslint_test.go:667
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 667

### 32. `go-test-saltado` — internal/engines/linters/eslint_test.go:671
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 671

### 33. `go-test-saltado` — internal/engines/linters/eslint_test.go:714
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 714

### 34. `go-test-saltado` — internal/engines/linters/eslint_test.go:718
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/linters/eslint_test.go` · **línea:** 718

### 35. `go-test-saltado` — internal/engines/proc/entorno_test.go:76
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/entorno_test.go` · **línea:** 76

### 36. `go-test-saltado` — internal/engines/proc/entorno_test.go:119
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/entorno_test.go` · **línea:** 119

### 37. `go-test-saltado` — internal/engines/proc/entorno_test.go:122
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/entorno_test.go` · **línea:** 122

### 38. `go-test-saltado` — internal/engines/proc/proc_test.go:54
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/proc_test.go` · **línea:** 54

### 39. `go-test-saltado` — internal/engines/proc/proc_test.go:76
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/proc_test.go` · **línea:** 76

### 40. `go-test-saltado` — internal/engines/proc/proc_test.go:98
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/proc_test.go` · **línea:** 98

### 41. `go-test-saltado` — internal/engines/proc/proc_test.go:108
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/proc_test.go` · **línea:** 108

### 42. `go-test-saltado` — internal/engines/proc/proc_test.go:130
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/proc/proc_test.go` · **línea:** 130

### 43. `complejidad-excesiva` — internal/engines/semgrep/semgrep.go:173
<!-- fp:9c85070b30ead023a94cfd19527cd568de02c1566d44bb2210b95f8e06743d56 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Engine.Run tiene complejidad 23 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/semgrep/semgrep.go` · **línea:** 173

### 44. `complejidad-excesiva` — internal/engines/semgrep/semgrep_test.go:358
<!-- fp:6806328d45035340e94df2f52fa01e011ede400c06e6b4e0ea837b156c1f3a94 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestCacheCicloCompletoConSemgrepReal tiene complejidad 17 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/semgrep/semgrep_test.go` · **línea:** 358

### 45. `go-test-saltado` — internal/engines/semgrep/semgrep_test.go:360
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/semgrep/semgrep_test.go` · **línea:** 360

### 46. `go-test-saltado` — internal/engines/semgrep/semgrep_test.go:363
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/semgrep/semgrep_test.go` · **línea:** 363

### 47. `complejidad-excesiva` — internal/engines/staticcheck/staticcheck_test.go:199
<!-- fp:de2b48210f5891a49786b8d93555b7cb9e0fb7bcc05d2a43948274b14dd5e4f4 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestIntegracionCazaBugsDemostrables tiene complejidad 17 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/staticcheck/staticcheck_test.go` · **línea:** 199

### 48. `go-test-saltado` — internal/engines/staticcheck/staticcheck_test.go:201
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/staticcheck/staticcheck_test.go` · **línea:** 201

### 49. `go-test-saltado` — internal/engines/staticcheck/staticcheck_test.go:204
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/staticcheck/staticcheck_test.go` · **línea:** 204

### 50. `go-test-saltado` — internal/engines/staticcheck/staticcheck_test.go:278
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/staticcheck/staticcheck_test.go` · **línea:** 278

### 51. `go-test-saltado` — internal/engines/staticcheck/staticcheck_test.go:281
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/engines/staticcheck/staticcheck_test.go` · **línea:** 281

### 52. `complejidad-excesiva` — internal/engines/trivy/trivy.go:87
<!-- fp:3a5e8184f69e86e27270fdaad22beabcf79cd96e17dcd78c6842d077342f4ca8 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Engine.Run tiene complejidad 17 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/engines/trivy/trivy.go` · **línea:** 87

### 53. `complejidad-excesiva` — internal/llm/anthropic.go:184
<!-- fp:d6e1304d15b4e458934f1402ef1fc6bdd64644bd3e1ef28b65fc353ed29ea3da -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Client.streamAnthropic tiene complejidad 25 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/llm/anthropic.go` · **línea:** 184

### 54. `complejidad-excesiva` — internal/llm/llm.go:235
<!-- fp:08b74d9165035d85394017beadf351e345ce59708536856aad540d1235a5e5c7 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Client.CompleteStream tiene complejidad 23 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/llm/llm.go` · **línea:** 235

### 55. `complejidad-excesiva` — internal/pipeline/pipeline.go:63
<!-- fp:bb83cbb7b17d04a99291ffd65f960dde29db9b9960d3e9f2a939ecfa9ccc8c2f -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Run tiene complejidad 30 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/pipeline/pipeline.go` · **línea:** 63

### 56. `complejidad-excesiva` — internal/pipeline/playbook.go:44
<!-- fp:f98b07d20a5033585d1eb6334c8bf2aff22b30a3d96b707cabb194910a4762b1 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** revisarLockfiles tiene complejidad 17 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/pipeline/playbook.go` · **línea:** 44

### 57. `complejidad-excesiva` — internal/shadow/shadow.go:52
<!-- fp:b7e0d291e498c143d171b9d0e0f34ed84f0632ec556195a033af470d7309aa4d -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** RiskScore tiene complejidad 18 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/shadow/shadow.go` · **línea:** 52

### 58. `complejidad-excesiva` — internal/shadow/shadow.go:141
<!-- fp:a23b797df7d2835607a9e5e3449de852fb1aa12e3d9397e20c25f605f621b1e2 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** Runner.Run tiene complejidad 20 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/shadow/shadow.go` · **línea:** 141

### 59. `parametros-excesivos-go` — internal/store/store_test.go:75
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** Más de 5 parámetros posicionales. Agrupa en un struct con nombres.

**Archivo:** `internal/store/store_test.go` · **línea:** 75

### 60. `complejidad-excesiva` — internal/store/store_test.go:258
<!-- fp:fe7a1fbc6f4206a329b18f210df38d96e6a04b63a5ee2af55fc5838d8f0ed6c3 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** TestFileCache tiene complejidad 18 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/store/store_test.go` · **línea:** 258

### 61. `todo-sin-ticket` — internal/store/sync_test.go:14
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** TODO/FIXME/HACK sin ticket. Formato: TODO(ABC-123): descripción.

**Archivo:** `internal/store/sync_test.go` · **línea:** 14

### 62. `complejidad-excesiva` — internal/store/sync_test.go:77
<!-- fp:1b014c3739f8f76aa03c90e16efff61aa97f068dd5535502d3da35d1874cfc19 -->

- [ ] **Pendiente** · pilar **calidad** · motor `playbook` · severidad `warning`

**Qué detectó:** cicloSync tiene complejidad 30 (el umbral es 15)

**Por qué importa:** Cada bifurcación multiplica los caminos posibles y las pruebas necesarias para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza de quien la lee y los errores se esconden en las ramas que nadie recorre.

**Cómo resolverlo:** Extrae las ramas independientes a funciones con nombre, o sustituye la cadena de condiciones por una tabla de despacho. Si la ramificación es esencial, deja el porqué en un comentario.

**Archivo:** `internal/store/sync_test.go` · **línea:** 77

### 63. `todo-sin-ticket` — internal/store/sync_test.go:153
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** TODO/FIXME/HACK sin ticket. Formato: TODO(ABC-123): descripción.

**Archivo:** `internal/store/sync_test.go` · **línea:** 153

### 64. `go-test-saltado` — internal/store/sync_test.go:198
<!-- fp: -->

- [ ] **Pendiente** · pilar **calidad** · motor `semgrep` · severidad `warning`

**Qué detectó:** t.Skip sin ticket asociado.

**Archivo:** `internal/store/sync_test.go` · **línea:** 198

---

## Discrepancias

- go-dinero-float sobre PriceInPerMTok/PriceOutPerMTok: son tarifas que escribe un humano, no dinero acumulado; la acumulacion ya es int64. Decision pendiente del equipo (ver baseline.txt).

---

## Contexto

- Deuda preexistente suprimida por la baseline: **0** (no bloquea; solo lo nuevo bloquea)
- Capas que no corrieron en este escaneo: ninguna
- Este informe lo genera `codeguard report` y se versiona con el repo.
