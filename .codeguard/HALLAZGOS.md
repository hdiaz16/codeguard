# Hallazgos de CodeGuard

> ## ✅ COMPLETADO — no quedan hallazgos bloqueantes
>
> Generado el 2026-08-08 18:48 · rulepack `2026.08.1`

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

## ✅ Resueltos desde el informe anterior (9)

- [x] 1. `gofmt` — cmd/codeguard/hook.go:1
- [x] 2. `gofmt` — cmd/codeguard/rulescmd.go:1
- [x] 3. `gofmt` — cmd/daemon/explain.go:1
- [x] 4. `gofmt` — internal/config/config.go:1
- [x] 5. `gofmt` — internal/engines/linters/dotnetformat.go:1
- [x] 6. `gofmt` — internal/engines/linters/exec.go:1
- [x] 7. `gofmt` — internal/pipeline/pipeline_test.go:1
- [x] 8. `gofmt` — internal/shadow/shadow.go:1
- [x] 9. `gofmt` — internal/store/store.go:1

---

## Discrepancias

<!-- El agente anota aquí lo que considere falso positivo, con su razón.
     Un humano decide después: corregir la regla o aceptar el hallazgo. -->

---

## Contexto

- Deuda preexistente suprimida por la baseline: **0** (no bloquea; solo lo nuevo bloquea)
- Capas que no corrieron en este escaneo: `falta:semgrep`, `falta:squawk`, `falta:trivy`
- Este informe lo genera `codeguard report` y se versiona con el repo.
