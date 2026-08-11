# Plan — Motor a nivel avanzado

El veredicto del que nace este plan: detección **estándar** sólida, montada sobre una arquitectura **avanzada**, en madurez **temprana**. Este plan sube el primer eje y demuestra el tercero.

> **Regla de avance**: una fase no se abre hasta que la anterior cierra al 100% —criterio de cierre cumplido y verificado, no "casi". Es el mismo método de la semana de estabilización (F0–F5), que funcionó.

**Estado**: 🔵 F1 en curso — arrancó el 2026-08-11

---

## F1 — Candados de detección

**Objetivo**: dos piezas baratas que suben la detección un escalón, y un candado para que ninguna regla vuelva a vivir muerta —o a cazar de más— sin que el CI lo grite.

- [ ] **F1a** Corpus `semgrep --test`: cada una de las 118 reglas con ≥1 caso positivo (`ruleid:`) y ≥1 negativo (`ok:`) en `rulepacks/<ver>/semgrep/tests/`
- [ ] **F1a** Paso de CI que corre `--test` y tumba el job (junto al `--validate` existente)
- [ ] **F1a** Excepciones documentadas (reglas no testeables por `paths:` u otra limitación del framework) — meta: 0
- [ ] **F1b** Motor govulncheck (análisis de alcanzabilidad: sólo CVEs cuyo código vulnerable de verdad se llama): adaptador + tests con payload real capturado
- [ ] **F1b** Cableado en `daemon.Engines` — política como trivy: aviso en local, bloquea en CI
- [ ] **F1b** `engines.ps1` lo instala si hay toolchain de Go (sin toolchain no hay repos Go que analizar)
- [ ] **F1b** El CI lo instala en "Instalar motores"

**Criterio de cierre**: `semgrep scan --test` verde cubriendo todas las reglas; govulncheck reporta un hallazgo alcanzable en un fixture vulnerable y calla en uno sano; `go test ./...` verde; CI verde.

## F2 — Velocidad y semántica

- [ ] **F2a** `file_cache` incremental (§9 de la spec, tabla ya diseñada): veredicto por `sha256(archivo) + rulepack + config`; archivo sin cambios no corre motores
- [ ] **F2b** staticcheck como motor de Go (análisis SSA: bugs demostrables, no patrones de texto)

**Criterio de cierre**: segunda corrida de `codeguard report` en bds.portal baja de ~35 s a <5 s; staticcheck con tests y degradación limpia; cero regresiones en `go test ./...`.

## F3 — Calibración con datos reales

- [ ] `codeguard stats --precision`: precisión por regla desde la tabla `feedback`, lista para podar
- [ ] Protocolo §17 corriendo: 2+ semanas en sombra, 500+ hallazgos etiquetados — **es tiempo-calendario: arranca en paralelo desde ya, no espera a F2**
- [ ] Primera poda ejecutada: reglas <80% de precisión degradadas o retiradas, con el dato en la mano

**Criterio de cierre**: la precisión por regla se consulta con un comando; la primera poda está hecha y documentada.

## F4 — Operación

- [ ] Telemetría central (Postgres — fase 5 de la spec): precisión y bypass a nivel organización
- [ ] Capa LLM encendida (ya construida y verificada; se enciende **después** de calibrar, no antes)
- [ ] Comentarios de PR desde el SARIF que el CI ya genera (sin GitHub Advanced Security)

**Criterio de cierre**: un hallazgo hecho en cualquier máquina enrolada se ve en la telemetría central; un PR recibe comentarios del análisis.

## F5 — Distribución

- [ ] Firma de código (el certificado es trámite del usuario; el `.iss` ya tiene la línea prevista)
- [ ] Publicación en winget (actualización de flota resuelta)
- [ ] macOS/Linux cuando haya demanda real (el sandbox es lo único no portable)

---

## Fuera de alcance — a propósito

Motor de análisis propio (orquestar los mejores motores **es** la arquitectura correcta), reescribir el fingerprinting, ML para el score de riesgo, y semgrep Pro antes de que la calibración diga si hace falta.

## Bitácora

- **2026-08-11** — Plan creado. F1 arranca: corpus de pruebas + govulncheck.
