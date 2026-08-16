# Triaje de las 184 medias

Preparado para la fase de validación. **Es un mapa, no una excavación**: agrupa por causa
común y ordena por daño, pero NO valida caso por caso ni descarta nada. Las candidatas a
descarte se señalan para que la validación las mire primero y barato.

- **23 racimos** cubren **172** medias; las **12** restantes son las candidatas a descarte.
  172 + 12 = 184, sin solapes: ninguna media está en dos racimos y ninguna queda fuera
  (comprobado programáticamente, no a ojo).
- **12 candidatas a descarte** (6,5 %), muy por debajo del 34 % de falsos positivos que
  salió en las altas — porque en las medias hay mucho menos "puerto a Linux" y mucho más
  hallazgo verificable leyendo el archivo.
- Criterio de orden: **lo que hace que la herramienta MIENTA va primero**. Un falso "todo
  bien" es el peor fallo posible de un analizador; después lo que rompe al usuario;
  al final lo cosmético.

## Los tres primeros

| # | Racimo | Medias | Por qué primero |
|---|--------|--------|-----------------|
| 1 | **R1 — Fail-open: la capa no corre y el informe la da por revisada** | 17 | Es el fallo insignia del producto y el racimo más grande. H041 deja pasar un commit **sin revisar secretos**. |
| 2 | **R2 — Un fallo unitario aborta TODAS las demás unidades** | 3 | Pocas, pero cada una anula el análisis de todos los proyectos/módulos restantes. Radio de daño máximo por hallazgo. |
| 3 | **R3 — Cachés cuya clave no modela el dominio real** | 9 | El veredicto equivocado **persiste entre corridas** y es invisible. Es exactamente la avería de H014, ya confirmada y arreglada. |

R2 es en realidad una subespecie del daño de R1 y conviene atacarlos en la misma pasada.
Justo detrás quedan R4 (hallazgos válidos rechazados en Windows) y R5 (paridad y
fingerprint), que también son "mentira", no molestia.

---

# P0 — La herramienta miente

## R1 · Fail-open: la capa no corre y el informe la da por revisada — 17

`H041` `H106` `H038` `H121` `H092` `H151` `H149` `H114` `H125` `H086` `H052` `H031`
`H032` `H053` `H036` `H183` `H047`

Tres mecanismos, un solo desenlace: se devuelve `nil` donde hubo un fallo, y el
orquestador cuenta la capa como revisada y limpia.

- **El error de `gitdiff` se traga y la capa se queda sin archivos** — `H041` (¡el peor:
  `gitdiff.Staged` falla y el commit pasa sin revisar secretos!), `H106`, `H038`.
- **"Hubo salida por stdout ⇒ éxito"** — `H092`, `H151`, `H149` (este además descarta
  hallazgos YA decodificados del mismo stream).
- **Se da por limpio lo que no se miró** — `H114` (archivos no analizados se cachean como
  limpios), `H121` (`os.Stat` descarta el archivo por CUALQUIER error, incluido permisos),
  `H125` (un commit que sólo toca stubs `.pyi` no dispara mypy).
- **Errores de contexto degradados en silencio** — `H086`, `H052`, `H031`, `H032`, `H053`,
  `H036`, `H183`, `H047`.

**Fix único:** el proyecto ya tiene el mecanismo y ya lo validó dos veces — el centinela de
`exec.go` (H012) y `ErrUnavailable`, que la validación de H009 confirmó que **bloquea de
verdad** (`pipeline.go:102-106` → `Verdict=Block`; `hook.go:160-163` → `os.Exit(1)`). Una
pasada que convierta cada uno de estos `return nil` en el error envuelto correspondiente,
más un test por motor con la forma de `TestGoVetNoDaLimpioCuandoNoPudoCargar`. No hace
falta inventar política: hace falta aplicarla donde no está.

**Mata:** 17 medias. El mismo barrido alcanza buena parte de las **61 bajas** de la familia
"error silenciado" (114 hallazgos en total llevan esa marca en las tres severidades).

## R2 · Un fallo unitario aborta TODAS las demás unidades — 3

`H120` (PMD) `H132` (tsc) `H148` (staticcheck)

Un proyecto/módulo que falla corta el análisis de todos los demás, que quedan sin mirar y
sin decirlo. Es el fallo de H013 (el que acabo de arreglar en govet) pero con el radio
multiplicado por el número de unidades del repo.

**Fix único:** política compartida de **degradación por unidad**: el fallo de una unidad
degrada esa unidad y el resto se sigue analizando; el informe nombra la degradada. Los tres
motores tienen la misma estructura de bucle, así que es un helper y tres llamadas.

**Mata:** 3, pero cada una vale por todas las unidades del repo.

## R3 · Cachés cuya clave no modela el dominio real — 9

`H107` `H145` `H129` `H199` `H162` `H180` `H118` `H153` `H063`

Es **la misma avería que H014**, ya confirmada y arreglada esta noche en ruff. La clave
omite una entrada de la que sí depende el veredicto, y el caché sirve el resultado de otro
contexto — de forma persistente e invisible.

- **La clave ignora la ruta y el contenido idéntico colisiona** — `H107` (eslint) y `H145`
  (semgrep): mismo bug que H014 pero con el síntoma inverso, **duplican** hallazgos en vez
  de perderlos.
- **Falta una entrada del veredicto en la clave** — `H129` (versión del binario ruff),
  `H199` (la clave usa `cfg.LLM.Model` pero las llamadas usan `ModelFor(pillar)`),
  `H180` (la clave de dedupe omite el motor), `H162` (`string(rune(tamano))`).
- **La huella no corresponde a lo analizado** — `H153`: `SHA256De` hashea el árbol de
  trabajo, no la revisión del diff. La clave de TODO el caché por archivo miente.
- **Reproducción del acierto con datos obsoletos** — `H118` (LineContent viejo), `H063`.

**Fix único:** una función `clave*` por motor, construida en **un solo sitio** para lectura
y escritura (patrón `claveRuff` ya escrito en `ruff.go`), con la regla de revisión: *si el
veredicto depende de X, X va en la clave*. Y `H153` primero, porque envenena a los demás.

**Mata:** 9 medias + 3 bajas, sobre una alta ya cerrada que sirve de plantilla.

## R4 · Rutas: hallazgos válidos rechazados en Windows — 7

`H201` `H090` `H133` `H089` `H069` `H068` `H128`

- `H201`: `inDiff` no normaliza separadores y **rechaza hallazgos válidos** en Windows.
- `H090` + `H133`: `path.IsAbs` no reconoce `C:\...` (sólo hay 6 usos de `path.IsAbs` en
  todo el repo, así que el barrido es corto y completo).
- `H089`, `H069`, `H068`: rutas sin relativizar y conjuntos de "archivos activos" mal
  calculados.
- `H128`: la guarda del test sólo mira `../` y en Windows `filepath.Rel` devuelve `..\`,
  así que el test pasa en verde ante el bug que dice vigilar. **Ojo: es el inverso de las
  candidatas a descarte** — el auditor acertó aquí precisamente porque el objetivo es
  Windows.

**Fix único:** paquete hoja compartido de rutas, extendiendo `relTo`/`relDentroDe` de
`internal/engines/linters/exec.go` (que ya resuelve el caso 8.3 de H028), y prohibir
`path.IsAbs` sobre rutas del sistema operativo.

**Mata:** 7 medias + 7 bajas.

## R5 · Paridad y fingerprint: el informe no casa con el CI ni con la baseline — 4

`H115` `H202` `H181` `H113`

**Verificado en el código, no supuesto:** `ComputeFingerprint` es
`SHA256(RuleKey + "\x00" + File + "\x00" + TrimSpace(LineContent))`
(`internal/finding/finding.go:57-63`). Es decir, **`LineContent` entra en el fingerprint**.

`H115` (govet) y `H202` (shadow) rellenan `LineContent` con el **mensaje del motor**, no
con el contenido de la línea. Consecuencia: el fingerprint depende de un texto que cambia
al actualizar el linter o al reescribir un mensaje → **la baseline deja de suprimir y la
deuda ya aceptada reaparece de golpe**. `H181` es la misma inestabilidad por otra vía
(`files[0].Path` como ancla). `H113`: `gofmt` con `TrimRight` da "bien formateado" donde el
`gofmt` real marca → el hook dice limpio y el CI bloquea.

**Fix único:** una decisión de diseño para los cuatro — o `LineContent` se rellena leyendo
la línea real del archivo (un helper), o sale del fingerprint. Lo que no puede seguir es
que el campo se llame "contenido de la línea" y lleve otra cosa.

**Mata:** 4, y estabiliza la baseline entera.

## R6 · Supresión silenciosa: lo que se configura y no se aplica — 7

`H179` `H147` `H083` `H073` `H074` `H075` `H197`

Globs inválidos ignorados sin avisar (`H179` pipeline, `H147` squawk), `Unmarshal` no
estricto que se traga los typos de `config.yaml` (`H083`, la regla nueva no se aplica a
nada y nadie se entera), la baseline que silencia errores de apertura y nunca comprueba
`Scanner.Err()` (`H073`, `H074`), inyección de líneas en la baseline (`H075`) y globs
case-sensitive que infravaloran el riesgo (`H197`).

**Fix único:** validación **estricta en la carga** de la configuración —
`DisallowUnknownFields`/`KnownFields`, compilar los globs al cargar y fallar ruidosamente —
en vez de descubrirlo al usarlos. Precedente directo: el fallo de govulncheck que ESTADO.md
cita como "corrección invisible".

**Mata:** 7.

## R7 · Los tests que vigilan "no mentir" están apagados — 7

`H170` `H171` `H175` `H168` `H169` `H146` `H191`

Estos no son deuda cosmética de tests: son **los guardianes de P0 y no guardan nada**.
`H170`: un motor DEGRADADO nunca hace fallar la prueba de extremo a extremo. `H171`: "NO
APLICA" se deduce de `requiere != ""`, no de si el motor corrió. `H175`: la ruta "CI" de la
prueba de paridad **no corre en modo CI**. `H168`: código muerto que nunca detecta el
daemon muerto. `H191`: el test no detecta la fuga al entorno persistente que dice comprobar.

**Fix único:** una pasada sobre `extremo_a_extremo_test.go` y `paridad_test.go` que haga
que DEGRADADO sea fallo y que "corrió" se lea del resultado y no de la configuración.

**Mata:** 7, y devuelve la red de seguridad para todo lo demás de esta lista.

## R8 · El grafo miente — 7

`H039` `H040` `H076` `H077` `H078` `H079` `H081`

El comando promete que "un diagrama extraído del código nunca miente" y hoy: omite imports
de efecto lateral y dinámicos (`H039`), fusiona nodos distintos por colisión de ID
(`H040`), inventa nodos SQL a partir de prosa con la palabra "select" (`H076`), crea
aristas falsas entre paquetes por resolución por nombre simple (`H077`), colapsa
receptores genéricos a `?` (`H078`), etiqueta clases como métodos (`H079`) y descarta
funciones homónimas sin dejar rastro (`H081`).

**Fix único:** no hay uno solo, pero sí **una decisión única**: o se cualifica la
resolución (paquete + receptor, IDs con hash de la ruta completa) o se baja la promesa del
comando. Conviene tratarlo como un solo trabajo con un solo dueño.

**Mata:** 7.

## R9 · Determinismo y telemetría que no se puede usar — 7

`H188` `H172` `H187` `H208` `H209` `H054` `H155`

Orden de reglas SARIF no determinista (`H188`), huella arbitraria por iteración de mapa
(`H172`), `EndLine < StartLine` (`H187`), `started_at == finished_at` (`H208`),
`lines_changed` siempre 0 (`H209`), fechas que no parsean y producen `dias=0` engañoso
(`H054`), y `ProtocolVersion` que se envía y nunca se valida (`H155`: daemon viejo con hook
nuevo → veredictos con campos reinterpretados y nadie se entera).

**Fix único para el subgrupo de determinismo:** ordenar antes de emitir o hashear. El
precedente está en el propio `govet.go`, que ya ordena los paquetes "porque un orden de mapa
haría que la misma corrida produjera claves distintas — un caché que nunca acierta y que
además parece que funciona".

**Mata:** 7 medias + 6 bajas de la familia de determinismo.

---

# P1 — Rompe al usuario o corrompe estado

## R10 · Lecturas truncadas que parecen completas — 6
`H050` `H176` `H206` `H205` `H051` `H154`
`rows.Err()` / `Scanner.Err()` nunca comprobados, filas corruptas saltadas con `continue`,
`Scanner` sin buffer ampliado. **Fix único:** barrido de los 10 `.Next()` de `internal/`
(26 `.Err()` ya existen, así que el patrón correcto ya está establecido en el repo).
**Mata:** 6 medias + 7 bajas.

## R11 · `os.Exit` salta los defer — 4
`H043` `H033` `H035` `H048`
`H043` es el de daño real: se salta `cancel` y **`cerrarCache`**. **Fix único:** `RunE`
devuelve error y la traducción a código de salida se centraliza en `main`. 15 `os.Exit` en
`cmd/`, así que el barrido es acotado. **Mata:** 4 medias + 1 baja.

## R12 · Sin plazo ni tope — 7
`H042` `H152` `H156` `H158` `H161` `H062` `H056`
`H042` sube de categoría: **la compuerta de secretos corre sin deadline**. **Fix único:**
`proc.Correr` con plazo (ya existe), `io.LimitReader` en las dos lecturas de respuesta del
modelo, y TTL en las cachés de memoria. **Mata:** 7 medias + 6 bajas.

## R13 · PATH y registro de Windows — 5 · **el fix ya está escrito**
`H037` `H139` `H140` `H136` `H137`
Es **la misma causa raíz que H018/H019**, ya arreglada con `registry.ExpandString` (evidencia
real: 7 de 32 entradas del PATH de máquina salían corrompidas). Quedan los sitios que no
entraron en aquel fix: `GetStringValue` falla con `REG_EXPAND_SZ` (`H037`), `os.ExpandEnv`
expande con el entorno obsoleto (`H139`), variables de usuario sin expandir (`H140`),
`RefrescarPATH` no idempotente pese a documentarlo (`H136`) y — **el que importa** — el PATH
del registro se antepone y gana precedencia, así que un `git.exe` plantado en un directorio
de `HKCU\Environment` (escribible por cualquier proceso del usuario) se ejecuta antes que el
real (`H137`). **Racimo barato: el fix ya existe en el árbol, sólo hay que extenderlo.**
**Mata:** 5.

## R14 · Truncado por bytes que rompe UTF-8 — 2 medias, 11 en total
`H060` `H116`
Sólo 2 en medias, pero **9 más en bajas**: 11 sitios truncando por bytes en un producto que
emite en español. **Fix único:** un helper compartido de recorte seguro por runas y
sustituirlo en los 11 sitios. Es el racimo con mejor relación esfuerzo/hallazgos de toda la
lista, aunque su daño individual sea bajo.

## R15 · Concurrencia — 14 · **bloqueado por infraestructura**
`H057` `H059` `H065` `H084` `H177` `H184` `H198` `H200` `H207` `H101` `H112` `H134` `H135` `H058`
**Recomendación: no atacar este racimo todavía.** ESTADO.md ya documenta que **el CI no
ejecuta el detector de carreras en ningún workflow** y que esta máquina no puede correrlo
(`-race` exige cgo y no hay compilador de C). Arreglar 14 carreras sin poder verificarlas es
escribir 14 fixes de fe. El orden correcto es: primero la decisión de Héctor sobre `-race` en
los runners `windows-latest` (que sí traen gcc), después este racimo.

## R16 · Estado del usuario destruido o irrecuperable — 7
`H182` `H067` `H046` `H189` `H190` `H030` `H045`
`H182`: un USB desconectado o una unidad de red caída **desregistra el proyecto de verdad**.
`H067`: la prueba destruye una variable de entorno real del usuario. `H190`: `runtime.KeepAlive`
insuficiente en la bóveda de credenciales (punteros por `uintptr` que el GC deja de rastrear).
`H046`: append a `.gitattributes` sin salto de línea previo, que corrompe la regla que dice
proteger. **Mata:** 7.

## R17 · Orbe, ventana y panel — 6
`H070` `H071` `H072` `H061` `H085` `H164`
HWND cacheado que puede recortar una ventana ajena, `CombineRgn` fallido que deja el orbe
invisible (justo lo que su comentario dice evitar), fuga de objetos GDI, el tramo final del
razonamiento que nunca llega al panel, y el margen del deadline que puede **exceder** el
deadline pedido. **Mata:** 6.

## R18 · Complejidad subestimada — 3
`H166` `H167` `H080`
Funciones anidadas que destruyen el seguimiento de la externa, comillas tras barra escapada
que se tragan el resto de la línea (y con ella los `if`/`for` reales), y el cálculo de línea
O(n·m). Los dos primeros **pierden hallazgos**, así que este racimo roza P0. **Mata:** 3.

## R19 · Presupuesto y endpoint — 2
`H082` (`&&` en vez de `||`: con media tarifa configurada el coste se calcula por debajo del
real y `MonthlyBudgetUSD` deja pasar gasto que debía bloquear) y `H159`. **Mata:** 2.

---

# P2 — Seguridad de impacto acotado

## R20 · Un secreto sale de la máquina — 7
`H193` `H194` `H195` `H196` `H160` `H212` `H044`
Todos comparten desenlace: **un secreto viaja al modelo o a un log**. Tokens
`github_pat_` no cubiertos (`H193`), redacción nula de valores sin comillas (`H194`), caso
especial atado a un índice mágico `i == 6` (`H195`), aserciones que sólo verifican el prefijo
del secreto (`H196`, por eso los otros tres no se detectaron), API key enviada a endpoints sin
exigir HTTPS (`H160`), DSN con contraseña en mensajes de error (`H212`), `org-llm.yaml`
copiado verbatim a una config que se pide versionar (`H044`).
**Fix único:** una pasada sobre `internal/shadow/redact.go` con tests de tabla que asercen el
secreto COMPLETO ausente, no su prefijo. **Mata:** 7.

## R21 · Compuertas de seguridad con fugas — 10
`H095` `H178` `H088` `H097` `H064` `H049` `H131` `H130` `H104` `H105`
El más grave es `H095`: emparejamiento por prefijo en las excepciones de identidad, donde un
`Artefacto` vacío en el JSON hace que `HasPrefix` devuelva true siempre y **la excepción
cubra todos los motores** — un error de tecleo convertido en aceptación silenciosa dentro de
una compuerta fail-closed. `H178`: el invariante "los secretos nunca se degradan ni se
suprimen" depende de comparar la cadena `"gitleaks"`. `H049` (traversal vía `cfg.Rulepack`)
**está corroborado por una alta ya confirmada**: es el mismo vector que H007, donde el
coordinador aceptó que una config del repo puede redirigir al producto. **Mata:** 10.

## R22 · Almacenamiento y exportación — 5
`H204` (CSV injection) `H210` `H087` `H034` (ruta predecible / relativa si `LOCALAPPDATA`
está vacía) `H213` (DROP TABLE CASCADE contra un DSN arbitrario en un test).
**Nota anti-descarte importante:** `H210`/`H087`/`H034` parecen descartables por apoyarse en
"`LOCALAPPDATA` vacía, lo habitual fuera de Windows", pero **el coordinador ya aceptó esa
misma premisa al confirmar H007** ("si `LOCALAPPDATA` viene vacía, la ruta se vuelve relativa
al CWD y un repo ajeno puede colocar `codeguard/llm-local.yaml`"). Descartarlas ahora sería
incoherente con esa decisión. **Mata:** 5.

---

# P3 — Calidad de tests (no cambian el comportamiento del producto)

## R23 · Tests frágiles, vacuos o mal aislados — 26
`H157` `H165` `H110` `H109` `H192` `H141` `H142` `H138` `H211` `H126` `H098` `H099` `H100`
`H186` `H096` `H094` `H127` `H066` `H173` `H174` `H143` `H144` `H122` `H108` `H091` `H102`

Aserciones vacuas, errores ignorados en la prueba clave, indexado sin comprobar longitud
(panic en vez de fallo legible), escrituras en rutas fijas compartidas fuera de `t.TempDir`,
quoting frágil de `cmd /c` con rutas que llevan espacios. **Se arreglan en una sola pasada
mecánica**, pero van al final a propósito: ninguno cambia lo que el producto le dice al
usuario. La excepción ya está promovida a R7.

---

# Candidatas a descarte — 12

**No las he descartado.** Se señalan para que la validación las mire primero y barato,
aplicando la taxonomía que produjo los 10 falsos positivos de las altas.

## Criterio 1 — Windows-only (precedente: H001, H010, H016, H017) — 10

El producto es Windows-only por diseño declarado: README línea 3, instalador Inno Setup, CI
en `windows-latest`, componentes con build tag `windows`, ADR-09. En cada una de estas, **todo
el impacto descrito ocurre exclusivamente en Linux/macOS**.

| ID | Motivo |
|----|--------|
| `H103` | `filepath.ToSlash` es no-op en Linux. En Windows sí convierte: el bug no existe en el único objetivo. |
| `H111` | Las pruebas de integración se saltan "en CI Linux/macOS". El CI es `windows-latest`. |
| `H117` | Tests con semántica Windows sin guarda de plataforma. **Idéntico a H017**, que el coordinador reclasificó a falso positivo por coherencia. |
| `H119` | Aislamiento vía `LOCALAPPDATA`, "que sólo existe en Windows". |
| `H123` | Tests acoplados a rutas Windows, "pueden ser frágiles multiplataforma". |
| `H124` | Mismo caso que H119. |
| `H150` | Paths absolutos con backslash que "fallarían fuera de Windows". |
| `H185` | Depende de un FS insensible a mayúsculas. Windows siempre lo es. |
| `H093` | Premisa explícita: "si el CI corre en Linux (lo habitual)". Falsa aquí. Residuo real: un comentario que miente, no un fallo. |
| `H055` | "En Linux/macOS el binario se llamará `codeguard`". No hay Linux/macOS. |

## Criterio 2 — Condicional sin verificar los call sites (precedente: H015, H020, H024, H026) — 2

| ID | Motivo |
|----|--------|
| `H163` | "**Si** el tamaño llega de configuración o de entrada externa, es una vía de DoS". El auditor no verificó de dónde viene `tamano`; en las altas esta forma condicional dio 4 falsos positivos. Barato de resolver: mirar los llamadores de `Dibujar`. |
| `H203` | "**Si** 'destino' proviene de entrada de usuario". Proviene: es un comando de exportación de la CLI. Que el usuario sobrescriba su propio archivo con su propio comando no es un ataque. |

## Advertencias anti-descarte

Tres trampas donde el patrón "huele a Linux" pero el hallazgo es real:

- **`H128`** es el **inverso** del criterio 1: la guarda del test sólo mira `../` y en
  Windows `filepath.Rel` devuelve `..\`. El auditor acertó *porque* el objetivo es Windows.
- **`H210` / `H087` / `H034`** se apoyan en "`LOCALAPPDATA` vacía". Suena a criterio 1, pero
  **el coordinador ya aceptó esa premisa al confirmar H007**. Descartarlas sería incoherente.
- **`H049`** (traversal vía config del repo) es el mismo vector que H007, ya confirmado.

## Criterio 3 — firma inferida sin leerla (precedente: H002, H022)

**No encontré ninguna media que caiga aquí.** Los candidatos naturales (`H098`, `H099`,
`H100`, `H126`, `H186`: indexar sin comprobar longitud) describen código verificable de un
vistazo y no infieren ninguna firma. Lo digo explícitamente porque es un resultado, no un
olvido: esa causa produjo 2 de los 10 falsos positivos de las altas y aquí no se repite.

---

# Resumen para planificar

| Prioridad | Racimos | Medias | Nota |
|-----------|---------|--------|------|
| P0 — la herramienta miente | R1–R9 | 68 | Empezar aquí. R1+R2 en la misma pasada. |
| P1 — rompe al usuario | R10–R19 | 56 | R13 casi gratis; R15 bloqueado por `-race`. |
| P2 — seguridad acotada | R20–R22 | 22 | R20 es una sola pasada sobre `redact.go`. |
| P3 — calidad de tests | R23 | 26 | Pasada mecánica al final. |
| Candidatas a descarte | — | 12 | Validar primero: son baratas de resolver. |
| **Total** | **23 racimos** | **184** | 172 en racimos + 12 candidatas. Sin solapes. |

**Tres observaciones de método:**

1. **Cinco racimos ya tienen su fix escrito y validado en el árbol** (R1 con `ErrUnavailable`
   y el centinela de `exec.go`, R2 y R3 con lo aprendido en H013/H014, R4 con `relTo`, R13
   con `registry.ExpandString`). Son extensiones de trabajo ya hecho, no diseño nuevo: es por
   donde conviene empezar y por donde más barato sale.
2. **R7 antes que casi todo lo demás.** Los tests que deberían cazar las regresiones de P0
   están apagados; arreglar P0 sin ellos es arreglar a ciegas.
3. **R15 (concurrencia, 14 hallazgos) no se debería tocar** hasta que exista el detector de
   carreras en CI. Es la única dependencia externa del plan y la decide Héctor.
