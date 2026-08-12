# Plan — Motor a nivel avanzado

El veredicto del que nace este plan: detección **estándar** sólida, montada sobre una arquitectura **avanzada**, en madurez **temprana**. Este plan sube el primer eje y demuestra el tercero.

> **Regla de avance**: una fase no se abre hasta que la anterior cierra al 100% —criterio de cierre cumplido y verificado, no "casi". Es el mismo método de la semana de estabilización (F0–F5), que funcionó.

**Estado**: 🟢 F1 cerrada (2026-08-11) · 🟢 F2 cerrada (2026-08-12) · 🔵 F3 en curso — herramientas listas, el reloj corre con el uso real · 🟡 F4 en dos tercios (telemetría y PRs hechos; la capa LLM espera a F3)

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

- [x] **F2a** `file_cache` incremental (§9): contenido + rulepack + config → hallazgos. Por archivo para semgrep; por **huella de módulo** para govulncheck y staticcheck (la de govulncheck lleva el día UTC: la frescura de la DB de vulnerabilidades es parte del resultado). Con reglas rotas no se cachea; direccionado por contenido con reescritura de ruta; cableado en daemon, report, baseline y hook (CI pasa nil a propósito)
- [x] **F2b** staticcheck como onceavo motor (SSA: bugs demostrables); estrenó cazando el código muerto que dejó la propia reescritura de gofmt (U1000)
- [x] **Extra que la medición desenmascaró**: gofmt lanzaba un proceso por archivo CRLF (~6 s) — ahora es `go/format` en proceso (209 ms, sin binario que pueda faltar); el pipeline reporta el tiempo de cada motor; el informe ya no se analiza a sí mismo; la lectura del caché usa `json_each` porque `go-sql-concat-en-variable` bloqueó —con razón— la primera versión concatenada

**Criterio de cierre — CUMPLIDO** (medido en este repo, 192 archivos): `codeguard report` 36.8 s en frío → **2.0 s** en estado estable (−94%, criterio <5 s); desglose: semgrep 0 ms (ni se ejecuta), gofmt 209 ms, módulos ~300 ms, techo govet 2.1 s + trivy 1.3 s. staticcheck con 10 tests incl. integración monorepo real ✓; `go test ./...` 18 paquetes verdes ✓; CI verde ⏳. Queda por confirmar la medición en bds.portal cuando se reinstale allí la versión nueva.

## F3 — Calibración con datos reales

- [x] `codeguard stats`: precisión por regla desde `feedback` + **emisiones por regla** (el denominador real — la precisión sobre votos solos tiene sesgo de selección) + avance hacia el umbral del §17 (14 días / 500 hallazgos / votos)
- [ ] Protocolo §17 corriendo: 2+ semanas en sombra, 500+ hallazgos, votos con los botones del panel — **tiempo-calendario y manos del equipo; al 2026-08-12: 64 hallazgos en 2 días, 0 votos**
- [ ] Primera poda ejecutada: reglas <80% de precisión degradadas o retiradas, con el dato en la mano

**Criterio de cierre**: la precisión por regla se consulta con un comando ✓; la primera poda está hecha y documentada ⏳ (bloqueada por calendario, no por código — mientras corre el reloj pueden avanzar las piezas de F4 que no dependen de la calibración: comentarios de PR y la telemetría central; la capa LLM sí espera).

## F4 — Operación

- [x] Telemetría central (Postgres — fase 5): empuje incremental por marca de agua ULID, idempotente y reanudable; DSN en `CODEGUARD_TELEMETRY_DSN`; disparo oportunista del daemon (throttle 10 min) y `codeguard sync` a mano. Verificado con datos reales: 163 filas la primera corrida, 0 incrementales la segunda. **Pendiente honesto**: la validación contra Postgres real no corrió (Docker no responde en esta máquina); el test existe y se salta solo
- [ ] Capa LLM encendida (ya construida y verificada; se enciende **después** de calibrar, no antes)
- [x] Comentarios de PR desde el SARIF que el CI ya genera (sin GitHub Advanced Security) — probado con el PR #1: comentario creado y luego **actualizado** en la segunda corrida, sin duplicar

**Criterio de cierre**: un hallazgo hecho en cualquier máquina enrolada se ve en la telemetría central ✓ (mecanismo probado; falta un Postgres real donde apuntarlo — decisión de infraestructura del usuario); un PR recibe comentarios del análisis ✓. La capa LLM espera a la calibración (F3) a propósito.

## F5 — Distribución

- [ ] Firma de código (el certificado es trámite del usuario; el `.iss` ya tiene la línea prevista)
- [ ] Publicación en winget (actualización de flota resuelta)
- [ ] macOS/Linux cuando haya demanda real (el sandbox es lo único no portable)

---

## Fuera de alcance — a propósito

Motor de análisis propio (orquestar los mejores motores **es** la arquitectura correcta), reescribir el fingerprinting, ML para el score de riesgo, y semgrep Pro antes de que la calibración diga si hace falta.

## Bitácora

- **2026-08-12 (tarde)** — F4 en dos tercios y **v1.3.0 instalada**. Telemetría central viva (marca de agua ULID, 163 filas reales empujadas, 0 en la segunda corrida) y comentarios de PR probados en el PR #1 (creado → actualizado, sin duplicar). Tres huecos que sólo se ven usando el producto, corregidos: la versión era invisible (binario decía `0.1.0-fase1` mientras el instalador decía 1.2.0 — ahora `build-dist` la inyecta desde `setup.iss` y se ve en el menú del orbe, el log y `codeguard version`); el panel salía vacío tras reiniciar el daemon y se leía como "se perdieron mis repos" (ahora se siembra del registro); y **tsc llevaba enrolado sin correr JAMÁS** en monorepos (exigía tsconfig.json en la raíz) — al despertar, los repos con deuda de tipos necesitan refrescar baseline. trivy también cachea (era el piso de 4.3 s del segundo informe en bds.portal).

- **2026-08-11** — Plan creado. F1 arranca: corpus de pruebas + govulncheck.
- **2026-08-11** — F1 ejecutada en el día. govulncheck es el décimo motor (`ddd3979`): sólo hallazgos de nivel símbolo (alcanzabilidad probada), integración real bajo el sandbox. Corpus `--test` completo (`993797d`): 119/119 reglas con positivo y negativo, escrito por tres agentes en paralelo y consolidado; el CI ahora corre `--validate` + `--test` + cobertura obligatoria. El corpus pagó antes de nacer: 2 reglas muertas de nacimiento y 3 con defectos de fábrica, las cinco curadas y probadas. Lecciones de infraestructura: los fixtures viven en `testdata/` hermano de `semgrep/` (un yaml dentro del `--config` se parsea como reglas), los fixtures YAML se llaman `<stem>.test.yaml`, y el modo test ignora los filtros `paths:`. Falta: CI en verde para cerrar la fase.
- **2026-08-11** — **F1 CERRADA**: CI verde en el run 31531522460 con los tres candados del rulepack activos. Pendiente de operación (no bloquea fases): las reglas despertadas llegan a los repos enrolados con la próxima actualización del rulepack instalado; si producen hallazgos nuevos, el flujo es refrescar la baseline. F2 abre: file_cache incremental + staticcheck.
- **2026-08-12** — Instalador **v1.2.0** construido e instalado en esta máquina (actualización en sitio, 124 s — el extra son govulncheck y staticcheck instalándose vía go install; datos y BD preservados). `CodeGuard-Setup.exe` sha256 `1a211a1ee9f4d428a2b5bb1e45edfc8a376615789b76db1ad451873ec0a35ccb`. El daemon corre con caché y once motores; este mismo commit es su primera prueba.
- **2026-08-12** — **F2 CERRADA** (CI verde, run 31605086356). F3 abre con las herramientas listas: `stats` gana denominador (emisiones por regla) y medidor de avance del §17 — al abrir: 64 hallazgos en 2 días, 0 votos; la palanca son los botones útil/falso-positivo del panel. Instalador v1.2.0 para que el daemon corra con caché y los dos motores nuevos: la calibración debe acumular datos de la versión que se va a calibrar. Primer commit del día degradó semgrep por plazo (burst matutino del EDR + arranque frío, transitorio conocido; el log del daemon lo dice con todas sus letras).
- **2026-08-11** — F2 ejecutada el mismo día (`edb7e44`, `bd0aef8`). El caché de deterministas vive: por archivo (semgrep) y por huella de módulo (govulncheck con día UTC, staticcheck con lista de paquetes). staticcheck es el onceavo motor y estrenó cazando código muerto de la propia tanda. La medición guió todo: destapó los ~200 procesos de gofmt por CRLF (ahora `go/format` en proceso), el informe que se analizaba a sí mismo, y el timing por motor quedó como superficie de diagnóstico permanente. Reporte: 36.8 s → 2.0 s (−94%). Y el rulepack bloqueó mi primera versión de la lectura del caché (SQL concatenado) — el sistema vigilándose a sí mismo, dos veces en un día. Pendientes conocidos del repo (no de la fase): los dos `go-dinero-float` de config.go:107-108 (tarifas LLM en float64 — decisión del usuario: baseline o int64 micros).
