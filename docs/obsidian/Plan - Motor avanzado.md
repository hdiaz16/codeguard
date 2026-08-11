# Plan — Motor a nivel avanzado

El veredicto del que nace este plan: detección **estándar** sólida, montada sobre una arquitectura **avanzada**, en madurez **temprana**. Este plan sube el primer eje y demuestra el tercero.

> **Regla de avance**: una fase no se abre hasta que la anterior cierra al 100% —criterio de cierre cumplido y verificado, no "casi". Es el mismo método de la semana de estabilización (F0–F5), que funcionó.

**Estado**: 🟢 F1 cerrada (2026-08-11, CI verde) · 🔵 F2 en curso

---

## F1 — Candados de detección

**Objetivo**: dos piezas baratas que suben la detección un escalón, y un candado para que ninguna regla vuelva a vivir muerta —o a cazar de más— sin que el CI lo grite.

- [x] **F1a** Corpus `semgrep --test`: cada regla con ≥1 caso positivo (`ruleid:`) y ≥1 negativo (`ok:`) en `rulepacks/<ver>/testdata/` — **119/119** (118 + una nacida del split de curación)
- [x] **F1a** Paso de CI que corre `--test` y tumba el job (junto al `--validate` existente), más verificación de cobertura: ninguna regla sin caso positivo
- [x] **F1a** Excepciones documentadas — **0** (las 2 reglas no testeables estaban *muertas*; se curaron en vez de exceptuarse)
- [x] **F1b** Motor govulncheck: adaptador + tests con payload real capturado + integración de punta a punta bajo el sandbox
- [x] **F1b** Cableado en `daemon.Engines` — política como trivy: aviso en local, bloquea en CI; en el hook sólo corre al cambiar go.mod/go.sum
- [x] **F1b** `engines.ps1` lo instala si hay toolchain de Go (vía GOBIN al dir de motores)
- [x] **F1b** El CI lo instala en "Instalar motores"

**Criterio de cierre — CUMPLIDO**: `semgrep scan --test` verde cubriendo todas las reglas ✓ (91/91 checks, 119/119 con positivo); govulncheck reporta un hallazgo alcanzable en un fixture vulnerable y calla en uno sano ✓ (GO-2021-0113 presente, GO-2022-1059 filtrada); `go test ./...` verde ✓; CI verde ✓ (run 31531522460, todos los pasos incluido "Probar el rulepack").

**Botín inesperado de F1a** — el corpus destapó 5 defectos de reglas antes de estrenarse, todos curados y con test:
`python-except-pass` (AND imposible, muerta de nacimiento), `ts-dinero-float` (patrón que no parsea nada, muerta), `pii-en-telemetria` (pata python muerta → split `-py`), `ts-promesa-sin-await` (`pattern-not` que jamás suprimió: `.then().catch()` era falso positivo de fábrica), `ts-sql-concat` (concatenación con `+` y plantilla en `query` anuladas por el AND del regex y un `pattern-not` ancho).

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
- **2026-08-11** — F1 ejecutada en el día. govulncheck es el décimo motor (`ddd3979`): sólo hallazgos de nivel símbolo (alcanzabilidad probada), integración real bajo el sandbox. Corpus `--test` completo (`993797d`): 119/119 reglas con positivo y negativo, escrito por tres agentes en paralelo y consolidado; el CI ahora corre `--validate` + `--test` + cobertura obligatoria. El corpus pagó antes de nacer: 2 reglas muertas de nacimiento y 3 con defectos de fábrica, las cinco curadas y probadas. Lecciones de infraestructura: los fixtures viven en `testdata/` hermano de `semgrep/` (un yaml dentro del `--config` se parsea como reglas), los fixtures YAML se llaman `<stem>.test.yaml`, y el modo test ignora los filtros `paths:`. Falta: CI en verde para cerrar la fase.
- **2026-08-11** — **F1 CERRADA**: CI verde en el run 31531522460 con los tres candados del rulepack activos. Pendiente de operación (no bloquea fases): las reglas despertadas llegan a los repos enrolados con la próxima actualización del rulepack instalado; si producen hallazgos nuevos, el flujo es refrescar la baseline. F2 abre: file_cache incremental + staticcheck.
