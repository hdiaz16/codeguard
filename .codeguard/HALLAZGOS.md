# Hallazgos de CodeGuard

> **Estado: 2 bloqueante(s) pendiente(s)** · generado el 2026-08-11 14:52 · rulepack `2026.08.2`

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

## Discrepancias

- go-dinero-float sobre PriceInPerMTok/PriceOutPerMTok: son tarifas que escribe un humano, no dinero acumulado; la acumulacion ya es int64. Decision pendiente del equipo (ver baseline.txt).

---

## Contexto

- Deuda preexistente suprimida por la baseline: **0** (no bloquea; solo lo nuevo bloquea)
- Capas que no corrieron en este escaneo: ninguna
- Este informe lo genera `codeguard report` y se versiona con el repo.
