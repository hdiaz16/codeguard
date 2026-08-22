# Plan de calidad mundial — firmado por el consejo (2026-08-22)

Producto de dos debates del consejo de tres modelos (Claude + Kimi K3 + GPT 5.6,
ambos consultados a máximo esfuerzo con acceso de lectura al repo):
`pilar\debates\analisis-codeguard\` (matriz de madurez, 28 turnos) y
`pilar\debates\plan-calidad-mundial\` (este plan, 3 rondas con convergencia).
Toda afirmación técnica está anclada a archivo:línea verificado. Matriz de
madurez de partida: secretos 5 · motores 4 · paridad 3 · cadena de suministro 2
· sync 2 · calibración 3 · LLM 3 · repos hostiles 2 · instalador 3 · CI 1-2 ·
concurrencia 2 · flota 1.

## Reglas firmadas por los tres (mandan sobre los detalles)

1. **Ante cualquier duda, invalidar y re-analizar** — jamás servir una
   ubicación o veredicto adivinado.
2. **Fail-visible, nunca fail-open** — toda degradación se declara en el
   veredicto; ninguna se reduce a log.
3. Experimento instrumentado ANTES de arreglar lo que no se entiende (bug #8).
4. Mutación y fuzz en nightly curado; el gate de PR es determinista.
5. Prohibido añadir usos de APIs deprecadas durante una migración por tandas;
   el gate final es cero llamadores.

## W0 · CI que impide mentir [S-M] — TODO depende de esto

- Job REQUERIDO en `windows-latest`: `go test ./... -race -count=1 -shuffle=on`
  (mingw del runner destraba race en Windows; consenso: SIN build tags ahora —
  race debe cubrir daemon/ipc, donde viven las carreras; el split portable es
  deuda planificada de W6). Primer run = humo para confirmar gcc del runner.
- Clasificar los 7 fallos ambientales: fix (JDK21 en runner, TEMP sin alias
  8.3) o `t.Skip` con razón e issue. Nada de `continue-on-error` permanente.
- **runTool**: fix mínimo INMEDIATO del verde silencioso (`exec.go:17-44`:
  ExitError + 0 bytes = error, como su comentario promete) + fila «código
  desconocido + 0 bytes» en el test de contrato. Después, `ExecResult` tipado
  único (`{Stdout, Stderr, ExitCode, Started, TimedOut, Truncated}`) que
  reemplaza las 3 APIs (`exec.go:20/68/112`), migración por tandas empezando
  por semgrep/eslint/gitleaks.
- Nightly: mutación curada de invariantes (error→nil, degradado→limpio,
  firma inválida→válida, marca-no-avanza) + fuzz de parsers de motores.
- **Aceptación:** mutación `("", nil)` en runTool pone rojo un PR; race corre
  sobre todos los paquetes; checkout limpio pasa dos veces seguidas.

## W1 · Los datos no mienten [M-L]

- **Bug #8** (línea desactualizada servida por caché): experimento
  instrumentado primero — fixture de cambio solo-comentario con volcado de
  clave de caché; el disparador del hit AÚN no se explica (regla 3). Después,
  la síntesis firmada: (a) manifiesto de entradas del caché (motor+versión+
  config+rulepack digest) — cualquier digest distinto = miss; (b) para hits
  válidos con archivo desplazado, componente ÚNICO de re-hidratación
  (sustituye las 5 copias: semgrep.go:115, eslint.go:277, gofmt.go:72,
  javafmt.go:133, javalint.go:181) que re-mapea `Line` por match ÚNICO de
  `LineContent` en ventana ±N; match múltiple o ausente = invalidar y
  re-analizar. NO meter línea en la huella (finding.go:54-63 la excluye a
  propósito; es la feature que protege baselines).
- diff_cache LLM: re-`verify()` también en hits (`shadow.go:97-115`);
  versionar el verificador en la clave.
- **Veredicto único tipado** `AnalysisOutcome{clean|findings|degraded|failed}`
  consumido por hook, panel, stats y CI — cierra de una vez: [32] (`&&`/`||`),
  stats mintiendo sobre gitleaks degradado (`store_cache.go:163-176` +
  `statscmd.go:95-96`), «OK — 0 bloqueantes» antes del veredicto de garantía,
  «✗ baseline» con 0 supresiones.
- Huellas versionadas `:v2` (ventana dual 90 días, lectura v1+v2, escritura
  v2) — desbloquea #9 y todo fix futuro de huella.
- **Aceptación:** fixture comentario-solo → línea correcta o re-análisis,
  jamás línea vieja; hallazgo fuera-de-diff inyectado en caché LLM no se
  registra; snapshot tabular de todas las combinaciones de veredicto.

## W2 · El ciclo de vida no engaña [M]

- **[31]** `init` = RECONCILIACIÓN: verifica postcondiciones reales (hooks
  cableados, config parsea, daemon responde, BD migrada), repara idempotente,
  y solo entonces «enrolado». `codeguard doctor --json` expone lo mismo.
  Hooks ajenos se preservan/encadenan, jamás se sobreescriben.
- **[13]** handshake IPC real: `protocol_min/max + capabilities` al conectar
  (hoy se estampa y no se compara, `ipc.go:231-275`); sin intersección → no
  analiza y explica. Sin reinicio automático de un daemon desconocido.
- **[07]/[08]** UN migrador con lock inter-proceso (mutex nombrado en
  Windows/SQLite; advisory lock en PG), tabla `schema_version` con checksum
  (hoy no existe), espera acotada con diagnóstico. `IF NOT EXISTS` solo como
  defensa.
- **[17]** token de generación en prepararGrafo: una construcción vieja jamás
  reemplaza una nueva.
- `/VERYSILENT` arranca y verifica el daemon (decisión Héctor, consejo
  unánime: sí — «instalado pero inoperante» no es instalación).
- **Aceptación:** crash-injection tras cada paso de init → segunda corrida
  converge; 20 procesos contra BD vacía → un migrador, esquema idéntico;
  matriz IPC N/N−1/N−2 con comportamiento declarado.

## W3 · Cadena de confianza acotada y honesta [M]

- **Borrar `scripts/pre-receive.sh` YA** (self-DoS: invoca `verify-attestation`
  que no existe, `main.go:52-54`; con codeguard en PATH rechazaría el 100% de
  los pushes; sin él, es fail-open — lo peor de ambos mundos).
- **Integridad de rulepack SIN PKI** (consenso): digest SHA-256 del rulepack
  estampado en cada veredicto y comparado local↔CI; manifiesto de rulepack
  firmado con UNA clave de release (reutiliza `internal/manifest` con el fix
  fail-closed de `verifier.go:82-86` — clave malformada = rechazo, no
  aceptación). Escritura atómica: temporal + fsync + rename + last-known-good.
- `internal/attest` queda DESACTIVADO y sin promesa externa (ni borrado
  irreversible ni cableado): la attestation completa (enrolamiento de claves
  por dispositivo, rotación, revocación) es gate de FLOTA con el diseño ya
  debatido. Threat model de 1 página: dónde vive la clave de release, qué
  firma, cómo rota, qué pasa si el central cae.
- Pipeline de release: build → SBOM → hash → manifest firmado → publish.
  Authenticode se inserta entre build y hash CUANDO llegue el certificado
  (en trámite; fuera de la ruta crítica de solitario, bloqueante de flota).
  SLSA/provenance: gate de flota, no ahora (veto de Kimi aceptado: sin flota
  es teatro; GPT concedió que no bloquea solitario).
- **Aceptación:** rulepack adulterado (bit flip, truncado, replay de versión
  vieja, corte a media escritura) → rechazo + last-known-good; clave
  malformada → rechazo; `git grep verify-attestation` = 0.

## W4 · Frontera contra repos hostiles [S→L escalonado]

- **Fail-visible YA [S]:** si token/job/asignación fallan, el motor NO corre
  y la capa queda `degradada` en veredicto y stats (hoy continúa en silencio:
  `contener_windows.go:93-109`, `proc.go:93-114`).
- **Env-scrub [S-M]:** hijos con entorno mínimo por lista blanca MEDIDA por
  motor (sin HOME/APPDATA/proxies/NODE_PATH heredados salvo fixture que lo
  justifique — hoy se hereda casi todo: `entorno.go:42-76`).
- **Spike AppContainer/low-integrity [timebox 2 días]:** repo RO, scratch RW,
  sin red, para la clase «config ejecutable» (eslint con config JS:
  `eslint.go:59-74`; MSBuild con targets: `dotnetbuild.go:246-252`).
- Fixtures adversariales PERMANENTES: eslint.config.js y target MSBuild que
  intentan leer señuelo fuera del repo / escribir fuera de scratch / abrir
  red / escapar por hijo o junction → todo falla o la capa se declara
  degradada.
- **DECISIÓN HÉCTOR (única divergencia abierta del consejo):** en repos
  enrolados y uso solitario, ¿basta env-scrub + fail-visible (Kimi/Claude:
  el usuario confía en su propio repo) o los motores de config ejecutable se
  degradan sin aislamiento fuerte (GPT: una PR hostil mete eslint.config.js
  en un repo legítimo y el hook lo ejecuta)? Consenso sí existente: el
  aislamiento fuerte es requisito para repos NO enrolados y para FLOTA.

## W5 · Sync sin pérdida [L]

- **Outbox transaccional por evento** (modelo de GPT, aceptado por Kimi):
  secuencia monotónica propia creada en la MISMA transacción que cada
  alta/cambio (reemplaza `id > marca` que pierde ULIDs del mismo milisegundo,
  autoconfesado en `sync.go:145-149`); estados por evento
  `pending/retry/sent/quarantined`; clasificación de error (transitorio →
  backoff; dependencia → espera al padre; permanente → cuarentena con causa);
  ACK local solo tras commit central; una fila mala jamás congela el resto
  (hoy: aborta lote + congela marca + corta tablas posteriores,
  `sync.go:176,357-366`).
- Cuarentena VISIBLE: `codeguard sync --estado`, panel con edad/intentos/
  causa, `sync retry|discard` auditado (actor + motivo).
- **Aceptación:** veneno + 499 válidas → las 499 llegan; hija-antes-que-padre
  progresa al llegar el padre; kill antes/después de commit y de ACK →
  reenvío idempotente, jamás omisión ni duplicado semántico.

## W6 · Motores completos, paridad medible, calibración gobernada [M]

- Test permanente de red-bloqueada: TODO motor con red denegada → `degradada`,
  jamás «corrió sin hallazgos». Hueco de gofmt (archivo que no parsea sin
  go.mod) → degradada explícita.
- **Contrato de cobertura por motor:** declara archivos aplicables y estado
  completo/parcial; cero hallazgos solo significa limpio si miró TODO lo
  declarado.
- Motores nuevos (criterio de admisión firmado: superficie real + defecto
  único demostrado + offline + identidad fijable + sandbox compatible +
  presupuesto de latencia medido): **actionlint** (workflows ya son superficie
  con secretos), **shellcheck** (`scripts/`, `.githooks/` sin compuerta hoy),
  **PSScriptAnalyzer** (shop Windows). zizmor evaluar con corpus. NO por
  catálogo: Rust/clippy sin código Rust, hadolint sin contenedores.
- `.codeguard.lock` por repo (binario + rulepack digest + policy digest) leído
  por hook y CI → paridad MEDIBLE, skew visible con causa estructurada.
- `risk_score` se CONSERVA y se hace observable (consenso final: ya gobierna
  el gasto LLM en `shadow.go:57-68`; versionar fórmula, exponer distribución).
- Golden-files de contrato por motor; fuzz semanal de parsers; split de build
  tags de `internal/ipc` como deuda planificada (para portabilidad, no para
  race).
- Degradación PERSISTENTE: contador por capa (corridas consecutivas, primer/
  último fallo, causa) + panel que escala + P5 intacto (cero contenido).

## W7 · Flota y LLM canario [continuo tras W5]

- Rollout por anillos con health-check post-upgrade y rollback al último
  artefacto verificado; matriz N/N−1 probada.
- LLM canario: rotar claves (SOLO Héctor) → 1 repo con proxy de captura
  validando redacción P5 → 2 semanas canario/control → decisión de default.
  Jamás toca el veredicto bloqueante.
- Telemetría opt-in sin contenido; pseudonimización estable; retención y
  borrado probados.
- Piloto instrumentado (checklist de entrada: CI requerido, enrolamiento
  reconciliable, lock operativo, degradación medible; métricas de salida:
  FP/regla, bypasses, p95, discrepancias de paridad = 0 sin explicar).

## Decisiones reservadas a Héctor

1. **W4 solitario:** env-scrub en enrolados (rec. Kimi/Claude) vs degradar
   motores de config ejecutable sin aislamiento fuerte (veto GPT). ÚNICA
   divergencia abierta del consejo.
2. `/VERYSILENT` arranca daemon — consejo unánime: SÍ.
3. `risk_score` — consenso final: conservar y observar.
4. Lista final de motores nuevos (propuesta: actionlint, shellcheck,
   PSScriptAnalyzer).
5. Política break-glass del futuro pre-receive de flota: bypass firmado con
   expiración y auditoría, jamás bandera local permanente (rec. GPT).
6. Rotación de claves API (ANTHROPIC/FOUNDRY/AZURE — pendiente desde el 14) y
   ventana del piloto.

## Gates de «calidad mundial»

**Solitario:** CI requerido verde (test+race todo, dos corridas limpias
consecutivas); cero caminos conocidos donde timeout/truncamiento/sandbox
fallido/parser fallido/dependencia ausente produzcan «limpio» (test de clase,
no de instancia); bug #8 cerrado con fixture de regresión; rulepack con
integridad verificada; `init` converge tras crash-injection y `doctor` lo
prueba; mutación nightly sin sobrevivientes en invariantes core.

**Flota (además):** aislamiento fuerte operativo para config ejecutable;
attestation completa con ciclo de claves; `.codeguard.lock` con skew visible
<5 min; caos de sync (ULIDs desordenados + veneno + cortes) sin pérdida ni
duplicado; upgrade/rollback N/N−1 probado; piloto ≥10 repos/≥20 devs/14 días
con disponibilidad ≥99,9%, false-block ≤1%, cero enrolamientos fantasma, cero
contenido P5 en proxy/logs/telemetría; madurez ≥4 en todo, 5 en secretos,
cadena de confianza y contrato de veredicto.

## Orden firmado y estimación

W0 (S-M) → W1 (M-L) → W2 (M) → W3 (M) → W4 (S→L escalonado) → W5 (L) →
W6 (M) → W7 (continuo). W0-W2 son la fase «el sistema no se miente a sí
mismo»; W3-W5 «el sistema no confía sin verificar»; W6-W7 «el sistema escala
sin degradar la promesa».
