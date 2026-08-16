# Verificación de conjunto de la remediación

**Qué es esto:** una revisión independiente de TODO el trabajo sin commitear, hecha para
responder si hay trabajo a medias, tests que no prueban nada, fallos reales, e interacciones
entre fixes que nadie miró.

> ## Segunda vuelta — lo que se arregló después de este informe
>
> El informe de abajo es la foto de las 07:38. Después, el coordinador arregló
> `store.DefaultPath()` y borró la sonda, y a mí se me asignaron cuatro cosas. Todas hechas y
> verificadas por sabotaje; el detalle está en la sección **7**.
>
> | Qué | Estado |
> |---|---|
> | El guardián de R7 ejercitaba 0 de 10 motores | **Arreglado** — ahora 10 de 10, en cualquier máquina |
> | `registry.path()` escribía el registro dentro del repo | **Arreglado** con `filepath.IsAbs` + test |
> | `warmup.warmListPath()`, misma clase | **Arreglado** con `filepath.IsAbs` + test |
> | `TestRunSinDiffSeSalta` sin control positivo | **Anclado** — control positivo y comprobación del motivo |
> | `TestTrayCambiosConcurrentes...` con aserción trivial | **Anclado** — no se pierde ni una emisión, ni se mezclan pares |
> | La interacción H041×H003 sin advertir | **Escrito** en `permitidas` |
> | El daemon zombi PID 26276 | **Se murió solo**; el defecto de `llm_test.go:305` sigue ahí |

## Instante y método de medición

| | |
|---|---|
| HEAD | `8589533` — "govet decia «limpio» cuando no habia podido analizar nada" |
| Instante congelado | **2026-08-15 07:38:53** |
| Estado en ese instante | 37 archivos modificados · 30 entradas sin trackear |
| Cómo se midió | copia completa del árbol de trabajo a un directorio temporal, más `.git` copiado aparte. **No se usó `git checkout` ni `git stash`.** |

**El árbol se movió mientras medía** (hay agentes trabajando). Al terminar había 38 modificados
y 32 sin trackear: se añadió `internal/engines/identidad/auditoria.go` y dos archivos de test.
**Todo lo que sigue describe el árbol de las 07:38, no el actual.** Los dos archivos nuevos no
están evaluados aquí.

Además de leer el código se hicieron **pruebas de mutación**: romper cada fix a propósito en una
copia y comprobar que su test se pone rojo. Es lo único que distingue un test que prueba algo de
uno que acompaña.

---

## 1. Trabajo a medias

### Lo que NO se encontró (y se buscó)

- **Cero fixes comentados.** Se revisaron las 3.483 líneas del diff buscando líneas añadidas que
  fueran código comentado. No hay ninguna. En particular, las tres líneas del pool de SQLite que
  el coordinador tuvo que descomentar (H029) **están aplicadas** en `internal/store/store.go`.
- **Cero marcas `XXX` / `TEMPORAL` / `FIXME` / `PENDIENTE` / `WIP`** en código de producción.
  La única aparición en todo el árbol `.go` es la cabecera del archivo sonda de abajo.
- **Cero imports sin usar** (Go no compila con ellos; `go build ./...` pasa limpio).
- **Cero código muerto.** `staticcheck -checks U1000` sobre todo el árbol: ninguna función
  declarada y nunca usada.
- **Cero tests debilitados.** Se revisaron los borrados en los 7 archivos de test ya existentes
  que se modificaron: seis son sólo adiciones; los dos con borrados
  (`internal/pipeline/daemon_test.go` y `extremo_a_extremo_test.go`) son la refactorización de
  R7, que **sustituye** `informe()` por `revisarInforme()` conservando los dientes — el estado
  `¡NO CAZÓ!` sigue produciendo `t.Errorf`.

### Lo que SÍ hay

| Qué | Dónde | Recomendación |
|---|---|---|
| **Archivo sonda de diagnóstico** con cabecera "ARCHIVO TEMPORAL DE DIAGNOSTICO - se borra antes de terminar", **sin una sola aserción** (sólo un `t.Logf`) | `cmd\codeguard\zz_sonda_rutaA_test.go` | **BORRAR.** No prueba nada y no puede fallar. |
| Variable acumulada y nunca leída (`ids = append(ids, f.ID)`), detectada por staticcheck SA4010 | `internal\store\concurrencia_test.go:139` | Limpiar. Resto de un uso que no se llegó a escribir. |
| `parser.ParseDir` está deprecada desde Go 1.25 y **no respeta build tags** | `cmd\codeguard\entornohijos_test.go:251` | Menor. Hoy no da falso positivo (producto Windows-only), pero el guarda podría señalar un archivo que nunca se compila. |

**Sobre `zz_valida_hookskip_temporal_test.go`: ese archivo NO EXISTE.** El único `zz_*` del
árbol es `zz_sonda_rutaA_test.go`. O se borró ya, o el nombre estaba mal en el encargo.

### Atribución de los archivos sin trackear

Todos se atribuyen a un hallazgo. No hay huérfanos:

- `internal\gitref\` → H009+H021 (paquete hoja compartido de validación de refs)
- `internal\instalacion\` → N001 (la copia única de `DirMotores`)
- `cmd\codeguard\git.go` → N002 (el constructor `gitCmd`)
- `remediacion\` → documentos de coordinación
- Los 27 `*_test.go` → uno por hallazgo, correspondencia clara por nombre

---

## 2. Tests: ¿prueban algo de verdad?

### 2.1 Resultado de las pruebas de mutación

Se rompió cada fix a propósito y se comprobó si su test lo detecta. **13 de 14 mutaciones
salieron rojas.** La que no, no es un fallo del test (ver nota).

| Fix roto a propósito | ¿El test lo detecta? |
|---|---|
| H029 · quitar `db.SetMaxOpenConns(1)` | **SÍ** — 52 de 192 escrituras fallan con `SQLITE_BUSY` |
| H027 · quitar la guarda de `opt.Diff == nil` | SÍ |
| N001 · quitar la guarda `dir == ""` de `herramientaJava` | SÍ |
| N001 · `DirMotores` sin la comprobación `IsAbs` | SÍ |
| N003 · quitar la guarda de `identidad.Verificar` | SÍ |
| H021 · quitar el `--` de `gitdiff.read` | SÍ |
| H007 · `RutaLLMLocal` sin `IsAbs` | SÍ |
| N002 · quitar la barrera de la bóveda en `proc.incorporar` | SÍ |
| Veredicto omitido · quitar la rama `Skipped` del hook | SÍ |
| Veredicto omitido · no copiar `resp.Reason` del daemon | SÍ |
| H041 · volver al `return nil` (fail-open) de `Staged` | SÍ |
| N002 · `gitCmd` con `Entorno()` en vez de `EntornoGit()` | SÍ |
| BD · volver a la guarda incompleta `dir != filepath.Join("", "codeguard")` | SÍ |
| H006 · reversión sin comparar generación | SÍ |
| H006 · no cancelar el timer anterior (`t.reset.Stop()`) | *verde — ver nota* |

*Nota sobre la única verde:* quitar el `Stop()` **no produce comportamiento incorrecto**, porque
el contador de generación ya invalida el callback viejo. Es redundancia defensiva, no la línea
que sostiene la corrección. El test tiene razón en no ponerse rojo.

### 2.2 Veredicto por archivo

**Ninguno de los ~27 archivos de test nuevos se salta en esta máquina.** Los 16 `SKIP` de la
suite son todos de tests de integración **preexistentes**, apagados por herramientas ausentes
(mypy, PMD, google-java-format, node_modules de juguete, Postgres).

| Archivo | Qué afirma probar | Veredicto |
|---|---|---|
| `cmd\codeguard\hook_test.go` | H041: índice corrupto ⇒ el hook NO deja pasar el commit | **Prueba de verdad.** Corre el hook en un proceso hijo y mira el exit code real, que es lo que lee git. Corrompe el índice de verdad. Contraparte: sin nada preparado sí pasa. |
| `cmd\codeguard\hook_omitido_test.go` | Un análisis omitido no se presenta como revisión | **Prueba de verdad.** Tres contrapartes (commit normal, repo no enrolado). |
| `cmd\codeguard\hook_motivo_test.go` | El motivo cruza el pipe hasta la terminal | **Prueba de verdad.** Daemon de mentira con `Degraded` vacío, que es la rama exacta del ✓ falso. Pipe único por proceso y prueba. |
| `cmd\codeguard\entornohijos_test.go` | Ningún hijo de la CLI recibe la clave | **Prueba de verdad, la mejor del lote.** Mira lo que llega al hijo (binario falso que vuelca su entorno), no la lista que preparamos. Incluye un guarda AST y **documenta honestamente sus seis escapes**. |
| `cmd\codeguard\rutadatos_test.go` | La BD nunca cae dentro del árbol de trabajo | **Prueba de verdad.** Tres valores de `LOCALAPPDATA` + contraparte. |
| `cmd\daemon\arranqueclave_test.go` | El arranque no deja la clave en `os.Environ()` | **Prueba de verdad.** Reproduce el orden real del arranque. |
| `cmd\daemon\clavefueradelentorno_test.go` | Guardar la clave no deja copias sueltas | **Prueba de verdad.** Verifica ida y vuelta en la bóveda. |
| `cmd\daemon\tray_test.go` | H006: un pass no revierte un estado posterior | **Prueba de verdad** salvo un caso (abajo). |
| `internal\config\llmlocal_test.go` | Un repo ajeno no secuestra el endpoint del modelo | **Prueba de verdad.** Monta el cebo dentro del repo y hace `t.Chdir`. |
| `internal\daemon\motivo_test.go` | El daemon rellena `Reason` | **Prueba de verdad.** Contra `Analyze` real. |
| `internal\engines\gitleaks\rango_test.go` | No se inyectan opciones en `--log-opts` | **Prueba de verdad.** Stub compilado que graba su `argv`; comprueba `ErrUnavailable`. |
| `internal\engines\identidad\sindirectorio_test.go` | Sin directorio no se verifica nada | **Prueba de verdad.** Señuelos en el CWD para distinguir "no encontró" de "no miró". |
| `internal\engines\linters\dirmotores_test.go` | Un repo ajeno no elige el jar que ejecutamos | **Prueba de verdad.** Incluye la variante del jar en la raíz, que es la que sobrevive a un arreglo a medias. |
| `internal\engines\linters\exec_test.go` | Un timeout no se reporta como éxito | **Prueba de verdad.** |
| `internal\engines\linters\ruff_test.go` | El caché de ruff no cruza rutas | **Prueba de verdad.** Distingue "lo analizó" de "se lo sirvió el caché" contando invocaciones. |
| `internal\engines\proc\entorno_secreto_test.go` | La bóveda no resucita secretos; `EntornoGit` conserva `GIT_*` | **Prueba de verdad.** Lanza un proceso real. |
| `internal\engines\proc\path_windows_test.go` | La expansión `%VAR%` respeta la sintaxis de Windows | **Prueba de verdad** con una salvedad (abajo). |
| `internal\gitdiff\comodin_test.go` | Un comodín no vacía el diff en silencio | **Prueba de verdad.** Control positivo ANTES del resto. 12 subcasos + contraparte con acentos. |
| `internal\gitdiff\refinvalida_test.go` | `Range` no da refs sin validar a git | **Prueba de verdad.** Comprueba además que no se escriba nada en disco. |
| `internal\gitdiff\entorno_test.go` | git no recibe la clave pero sí `GIT_INDEX_FILE` | **Prueba de verdad.** |
| `internal\gitref\gitref_test.go` | La tabla de refs válidas e inválidas | **Prueba de verdad.** Verificados los codepoints: el caso NFD es U+0301 real, distinto del NFC; el espacio duro es U+00A0 y el ideográfico U+3000. |
| `internal\instalacion\instalacion_test.go` | `DirMotores` es absoluta o es nada | **Prueba de verdad.** |
| `internal\ipc\motivo_test.go` | El motivo sobrevive al pipe y a una actualización a medias | **Prueba de verdad.** |
| `internal\orbe\orbe_test.go` | H023: el caché del orbe aguanta concurrencia | **Prueba de verdad** dentro de lo posible sin `-race`: el runtime de Go mata el proceso con "concurrent map read and map write" aunque no haya detector. Las pruebas de clave son deterministas. |
| `internal\pipeline\complejidad_test.go` | El constructor primario de C# no se traga sus métodos | **Prueba de verdad.** Exige el censo exacto, no sólo el recuento. |
| `internal\registry\identidadruta_test.go` | H028: no se duplica el mismo repo | **Prueba de verdad.** Comprueba que el arreglo quede EN EL ARCHIVO y que converja. |
| `internal\store\concurrencia_test.go` | H029: sin `SQLITE_BUSY` dentro del proceso | **Prueba de verdad**, demostrado por mutación. |
| `internal\pipeline\arnes_test.go` | R7: el arnés no absuelve de más | **Mixto — ver abajo.** |
| `internal\pipeline\opciones_test.go` | H027: `Diff` nil ⇒ Skipped | **Débil.** |
| `cmd\codeguard\zz_sonda_rutaA_test.go` | *(nada)* | **VACUO.** Sin aserciones. Borrar. |

### 2.3 Los tres tests que NO están bien

**a) `internal\pipeline\arnes_test.go` · `TestElArnesNoAbsuelveAUnMotorConSuDependenciaPresente`
— NO PUEDE CORRER, y no sólo por esta máquina.**

Es el guardián de R7 más importante: el que comprueba que el arnés no absuelva a un motor cuyo
requisito SÍ está. En esta corrida salió `SKIP` con "esta máquina no tiene ninguna de las
dependencias externas". Pero el problema es estructural, no de máquina:

- Para `trivy`, `govulncheck`, `dotnet-format`, `dotnet-build`, `dotnet-vuln`, la disponibilidad
  se lee de las variables de paquete `moduloResuelto` y `dotnetRestaurado`
  (`extremo_a_extremo_test.go:578` y `:599`), que **las rellena el test de extremo a extremo**.
  Como `arnes_test.go` va antes que `extremo_a_extremo_test.go` en orden alfabético de archivo,
  cuando el guardián corre esas dos variables valen `false` **siempre**, en cualquier máquina.
- Para `eslint` y `tsc`, la comprobación es `enElRepo(...)` sobre un `t.TempDir()` recién creado
  y vacío: nunca tendrá `node_modules`. También `false` siempre.

Quedan sólo `mypy`, `pmd` y `google-java-format`, que aquí no están instalados. **Resultado: el
guardián no ejercita ni uno de los diez motores de su lista.** Su contraparte
(`TestElArnesSiguePerdonandoAlMotorSinSuDependencia`) sí corre, así que la mitad "perdona bien"
está cubierta y la mitad "no absuelve mal" no.

**b) `internal\pipeline\opciones_test.go` · `TestRunSinDiffSeSalta` — débil.**

Detecta el bug (sin la guarda, `Run` entra en pánico), pero:
- No comprueba `res.Reason`, así que un Skipped por CUALQUIER otro motivo lo daría por bueno.
- No tiene control positivo: no hay un caso con `Diff` válido que devuelva algo distinto de
  `Skipped`. Un `Run` que devolviera `Skipped` siempre pasaría.

Es el test más flojo del lote. Arreglo barato: afirmar `res.Reason == "sin diff que analizar"` y
añadir el caso con diff.

**c) `cmd\daemon\tray_test.go` · `TestTrayCambiosConcurrentesNoSeTraban` — aserción trivial.**

Su única comprobación es `len(g.todas()) == 0`. Ocho goroutines × 200 iteraciones y luego "¿se
emitió algo?". Detecta un interbloqueo (por timeout de la suite) y nada más. El propio test lo
admite ("humo de concurrencia"), y la razón es real —esta máquina no puede correr `-race`—, pero
conviene saber que ahí no hay red.

**d) Menor · `internal\engines\proc\path_windows_test.go` · `TestPathVigenteNoIncrustaDolares`**
tiene dos `t.Skip` que dependen del registro de la máquina. Aquí corrió, pero en una máquina cuyo
PATH traiga un `$` se apagaría solo y en silencio. Los otros dos tests del archivo lo cubren con
datos fijos, así que el riesgo es bajo.

**e) Menor · `internal\gitref\gitref_test.go:44`** dice que el acento descompuesto "va escrito
con el escape a la vista". **No es cierto**: es un carácter combinante literal. El test es
correcto (verificado byte a byte), pero el comentario invita a que alguien "normalice" el archivo
y deje la prueba comprobando dos veces lo mismo sin que nadie lo note.

---

## 3. La suite

```
go build ./...   → limpio
go vet   ./...   → limpio
staticcheck      → 0 hallazgos de código muerto; 2 avisos menores, ambos en tests
```

### `go test ./...`

Dos corridas completas:

| Corrida | Condición | Resultado |
|---|---|---|
| 1 | copia sin `.git` | **24 paquetes ok, exit 0.** Los e2e se saltan por no encontrar la raíz del repo. |
| 2 | copia con `.git` (los e2e sí corren) | **23 ok, 1 FAIL** — `internal/pipeline`, 497 s |

**Un solo test rojo en todo el árbol:** `TestLaCapaLLMNoBloqueaAunqueElModeloInsista`. Tiene
**dos causas apiladas, las dos ajenas al código de producción**.

#### Causa 1 — un daemon zombi retiene el pipe (100% reproducible)

```
servidor IPC: open \\.\pipe\codeguard-verificacion-llm-TestLaCapaLLM...: Access is denied.
```

Cómo se determinó: enumerando los pipes con nombre del sistema y los procesos vivos.

- El pipe existe y lo retiene el **PID 26276**, `codeguard-daemon.exe`, arrancado el
  **2026-08-14 a las 23:36:13**, desde
  `C:\Users\HECTOR~1\AppData\Local\Temp\TestLaCapaLLMNoBloqueaAunqueElModeloInsista243100810\002\`
  — o sea, **un daemon filtrado por una corrida anterior de ese mismo test, anoche**.
- `llm_test.go:305` compone el nombre del pipe **sólo a partir del nombre del test**, sin PID ni
  sufijo aleatorio. El comentario dice "un pipe por prueba", y es cierto dentro de una corrida,
  pero no ENTRE corridas: basta que una muera a medias para que el test quede rojo para siempre.
- **`llm_test.go` no lo ha tocado esta remediación.** Es infraestructura de test preexistente.
  Los tests NUEVOS sí lo hacen bien: `hook_motivo_test.go:56` añade `os.Getpid()` al nombre.
- **Verificado sin tocar el sistema:** parcheando el nombre del pipe con el PID en una copia, el
  `Access is denied` desaparece.

> **Acción pendiente que no pude hacer:** matar el PID 26276 requiere un permiso que el sistema
> me denegó. Mientras ese proceso viva, ese test estará rojo en esta máquina pase lo que pase.

#### Causa 2 — trivy retiene `trivy.db` (intermitente, ~50%)

Con el pipe ya limpio, el test **pasa sus cuatro aserciones** y luego falla en la limpieza:

```
testing.go:1464: TempDir RemoveAll cleanup: unlinkat ...\004\trivy\db\trivy.db:
                 The process cannot access the file because it is being used by another process.
```

Tasa medida: 1 de 3 y 1 de 2 en corridas aisladas ⇒ **en torno al 50%**. Es exactamente el fallo
ajeno de Windows que ya estaba declarado. El cuerpo del test es correcto; lo que falla es
`t.TempDir()` al no poder borrar un archivo que trivy sigue abriendo.

#### NETSDK1045: ya no rompe nada, pero apaga tres motores

El SDK de .NET 8 sigue sin poder targetear net10.0 y el `dotnet restore` sigue fallando. **Pero
ya no hace fallar ningún test**: el arreglo de R7 lo absorbe correctamente — `dotnetRestaurado`
queda en `false`, se registra un `t.Logf` con el error completo, y `dotnet-build`,
`dotnet-format` y `dotnet-vuln` salen como "sin probar" / NO APLICA en vez de acusar a tres
motores sanos.

Eso es lo correcto, y conviene decir el precio en voz alta: **tres motores de C# no están
verificados en esta máquina** y nadie se enteraría por el color de la suite.

### Estabilidad

Repeticiones de los tests sensibles al tiempo, sobre la copia congelada:

| Paquete | Corridas | Resultado |
|---|---|---|
| `cmd/daemon` (bandeja, H006) | 6 | 6/6 PASS |
| `internal/orbe` (H023) | 6 | 6/6 PASS |
| `internal/store` (H029) | 4 | 4/4 PASS |
| `cmd/codeguard` (H041 + veredicto) | 3 | 3/3 PASS |
| `internal/gitdiff` + `internal/gitref` | 3 | 3/3 PASS |

**Ninguna intermitencia salvo la de `trivy.db` ya descrita.**

---

## 4. Interacciones entre fixes

### (a) `cmd\codeguard\hook.go` — H041 + N002 + veredicto omitido

Los tres conviven bien y el orden está pensado: la rama `Skipped` va **antes** que la de
`Degraded` (si fuera después no se alcanzaría nunca por el camino local, donde siempre hay
`daemon:offline`), y `progress` se declara antes de la primera compuerta para que H041 pueda
hablar. Dos cosas que nadie previó:

**A1 · H041 sube muchísimo lo que cuesta un error en la lista blanca del entorno.** *(riesgo
real, no un fallo hoy)*

`gitdiff.run` ahora fija `cmd.Env = proc.EntornoGit()` (H003/N002) **y** un fallo de
`gitdiff.Staged` ahora es `os.Exit(1)` (H041). Antes, si el entorno acotado rompiera a git, el
resultado era un `return nil` silencioso; **ahora es un commit bloqueado, en todas las máquinas y
en cada commit.** La lista de `permitidas` se revisó y parece suficiente para git (PATH,
SYSTEMROOT, USERPROFILE, HOME, HOMEDRIVE/HOMEPATH, APPDATA, LOCALAPPDATA, TEMP), así que no hay
avería a la vista — pero la consecuencia de equivocarse ahí ya no es degradación, es paro total.
Merece un comentario en `permitidas` que lo diga.

**A2 · Se dejó de avisar del daemon caído en el caso omitido.** *(menor, UX)*

La línea `if len(res.Degraded) > 0 && res.Verdict != pipeline.Skipped` silencia "capas no
revisadas". Está bien razonado, pero tiene un efecto lateral: con el daemon caído **y** análisis
omitido, el usuario ya no se entera de que el daemon está caído. Defendible (no se analizó nada
igualmente), pero es una pérdida de información que ninguno de los dos autores mencionó.

### (b) `internal\engines\proc\entorno.go` — H003 + N002

Limpio. `EntornoGit()` reutiliza `Entorno()` y le añade el prefijo `GIT_*`, pero **sin relajar el
secreto**: un `GIT_*` que la bóveda gestione se queda fuera igual, y hay test. El fail-open de
`secretoGestionado` ya no es mudo (`sync.Once` + `log`).

**B1 · Coste en el camino caliente.** *(observación, no fallo)* `secretoGestionado` hace una
lectura del Administrador de credenciales **por cada variable `GIT_*` y en cada llamada a
`EntornoGit()`**, y `EntornoGit()` se llama en cada invocación de git: dos en `Staged`, más
`arbolPreparado`, `gitRemote`, `gitBranch`. En un `git commit -a`, con ~8-10 `GIT_*` puestas por
git, salen del orden de 50-60 `CredRead` por commit. No se midió el impacto; el comentario del
código habla de "cuatro por análisis", que se queda corto. Un caché por proceso lo resolvería.

### (c) `internal\gitdiff\gitdiff.go` — H003 + H009/H021

**Es la interacción mejor resuelta de las cinco.** La firma de `read` cambió a
`read(repoRoot, banderas, revs)` precisamente para poder meter `--end-of-options` y `--` sólo
cuando hay argumentos posicionales que blindar, y `Staged` —el camino de cada commit— no los
recibe, así que no se le exige git 2.24. `Range` valida con `gitref` antes de componer.
No hay solape con el `cmd.Env`. Sin problemas.

### (d) `cmd\daemon\main.go` — H006 + refactorización de H003

**D1 · Queda una carrera residual, más estrecha que la original.** *(hallazgo real)*

`cambiar()` toma el candado, incrementa `gen`, rearma el timer, **suelta el candado** y sólo
entonces llama a `aplicar()`. Soltarlo antes de pintar es correcto y está bien justificado (los
setters de la bandeja son `InvokeSync` y colgarían la aplicación entera). Pero la consecuencia es
que **dos cambios de estado concurrentes pueden pintar en orden inverso a su generación**:

```
goroutine A: lock, gen=1, unlock ........................ aplicar("pass")   ← se ve esto
goroutine B:            lock, gen=2, unlock, aplicar("blocked")
```

El contador de generación protege la reversión del timer, que era el bug de H006 (una ventana de
15 segundos, fácil de alcanzar), pero no ordena dos `set`/`setPass` simultáneos (una ventana de
microsegundos). `revertirAIdle` tiene el mismo patrón.

Ningún test lo cubre: `TestTrayElPassNoRevierteUnEstadoPosterior` llama a los dos **en
secuencia**, y `TestTrayCambiosConcurrentesNoSeTraban` no comprueba el orden. Se cierra haciendo
que `aplicar` compare la generación, o serializando los pintados por un canal.

### (e) `internal\pipeline\pipeline.go` — H027 + veredicto omitido

Encajan bien y se refuerzan: `Diff == nil` produce `Skipped` con `Reason = "sin diff que
analizar"`, y el hook ahora imprime ese motivo en vez de firmar un ✓. Antes de los dos fixes ese
camino era un pánico; entre los dos, ahora es un mensaje correcto de punta a punta. Sin
conflictos.

---

## 5. Coherencia de criterio: la ruta que puede quedar relativa

Aquí está **el problema más serio del conjunto**, y es de coherencia, no de corrección.

### Los cuatro fixes que se pidió comparar

| Sitio | Contrato | ¿Igual? |
|---|---|---|
| `internal\instalacion.DirMotores()` | `""` o ruta absoluta | **La buena.** Paquete hoja propio, copia única, test propio, y cada consumidor guarda por su cuenta. |
| `internal\config.RutaLLMLocal()` | `""` o ruta absoluta | Mismo contrato, **implementación duplicada** línea por línea. |
| `cmd\codeguard.dirDatos()` | absoluta, o cae al temporal, o error | **Distinto a propósito y bien argumentado** (telemetría, P4, conserva la elección previa del temporal). Su predicado es además el más limpio: sólo `IsAbs`. |
| `internal\engines\identidad.Verificar()` | guarda de consumidor sobre `dirMotores == ""` | Capa distinta, y el sitio correcto: el invariante es de la función, no de sus dos llamadores. |

Las tres primeras comparten una **redundancia**: `instalacion` y `config` comprueban `base == ""`
*y además* `!IsAbs(...)`. La primera comprobación no hace falta —`IsAbs` ya la cubre, porque
`Join("", "x")` no es absoluta— y `dirDatos` lo hace bien con sólo `IsAbs`.

### Lo que nadie miró: quedan CINCO sitios de la misma clase sin arreglar

La lección declarada en `instalacion.go` es *"una sola copia es lo que impide que el arreglo se
quede a medias"*. Se aplicó a `DirMotores` (2 copias → 1) y **no se generalizó**. Barrido de todo
el árbol:

| Sitio | Patrón | Consecuencia |
|---|---|---|
| **`internal\store\store.go:498` `DefaultPath()`** | `base == ""` → `TempDir()`, **sin `IsAbs`** | **El más grave.** Es la MISMA base de datos que arregló `dirDatos()`, por la otra puerta. La usan `cachecmd`, `daemoncmd`, `statscmd`, `synccmd` y `escritorio.go`. Con `LOCALAPPDATA="   "` o relativa, `dirDatos()` manda al temporal y `DefaultPath()` a `.\   \codeguard\codeguard.db`: **dos bases de datos distintas**, una de ellas dentro del repo del usuario. El fix arregló un llamador y dejó el agujero para el siguiente, que es literalmente la lección de N001. |
| `internal\registry\registry.go:27` `path()` | igual, sin `IsAbs` | `repos.json` puede acabar dentro del repo analizado. Llamado desde `initcmd`, `install.go`, `statuscmd` (CLI ⇒ CWD = el repo). **`registry.go` se modificó en esta remediación (H028) y esto se quedó al lado.** |
| `internal\daemon\warmup.go:23` `warmListPath()` | igual, sin `IsAbs` | `warm-repos.txt` relativo. Menor: corre en el daemon, cuyo CWD no es el repo analizado. **`warmup.go` también se modificó en esta remediación.** |
| `internal\daemon\warmup.go:70` | `filepath.Join(Getenv("LOCALAPPDATA"), "trivy", ...)` **sin guarda alguna** | Ya declarado como pendiente en ESTADO.md. Corrijo su gravedad a la baja: corre en el daemon, así que la ruta relativa NO se resuelve contra el repo analizado. |
| `cmd\daemon\main.go:263` `abrirLog()` | `base == ""` → no hace nada, sin `IsAbs` | Menor: el log del daemon. |

**Falso positivo que descarté:** `internal\daemon\daemon.go:150` y `:177` componen candidatos de
rulepack con `LOCALAPPDATA` sin `IsAbs`, pero `RulepackDir` ya pone
`filepath.Join(repoRoot, "rulepacks", version)` **como primer candidato por diseño** (vendoreado).
El repo ya gana por la puerta principal, así que ahí no hay agujero nuevo.

### Recomendación

1. **La buena es `internal\instalacion`**, por la forma: paquete hoja, copia única, test propio.
2. Ampliarla a un helper del estilo `instalacion.RutaLocal(sub ...string) string` con el
   predicado de `dirDatos` (sólo `IsAbs`), y **hacer que `store.DefaultPath()`,
   `registry.path()` y `warmup.warmListPath()` pasen por él.** Mientras `store.DefaultPath()`
   siga como está, el fix de la BD está a medias.
3. `dirDatos()` puede conservar su desenlace propio (caída al temporal): está razonado y es
   correcto para telemetría.

---

## 6. Resumen de acciones

**Bloqueante para dar la remediación por cerrada**

1. `store.DefaultPath()` conserva el bug que `dirDatos()` arregló, sobre la misma BD. Cerrarlo.
2. `registry.path()`, misma clase, en un archivo que esta remediación tocó.

**Debe hacerse antes de commitear**

3. Borrar `cmd\codeguard\zz_sonda_rutaA_test.go` (sonda de diagnóstico sin aserciones).
4. Arreglar `TestElArnesNoAbsuelveAUnMotorConSuDependenciaPresente`: hoy no ejercita ni un motor.
5. Reforzar `TestRunSinDiffSeSalta` (comprobar `Reason` + control positivo).

**Debe decidirse**

6. El daemon zombi PID 26276 mantiene rojo un test; hay que matarlo (no tuve permiso).
7. Añadir el PID al nombre del pipe en `llm_test.go:305` para que no vuelva a pasar.
8. La carrera residual del orden de pintado en `trayState` (D1).

**Anotar y seguir**

9. `permitidas` es ahora crítica: un error ahí bloquea todos los commits (A1).
10. Coste de `CredRead` en el camino del commit (B1).
11. Tres motores de C# sin verificar en esta máquina por NETSDK1045.
12. `internal\store\concurrencia_test.go:139`: variable acumulada y nunca leída.
13. `gitref_test.go:44`: el comentario miente sobre cómo está escrito el acento descompuesto.

---

## 7. Segunda vuelta: los arreglos y su demostración

Todo lo de esta sección se hizo **test primero** y se verificó **por sabotaje**: romper el
código a propósito y comprobar que la prueba se pone roja. Un guardián que no sabes hacer
fallar a voluntad no vale más que el apagado.

### 7.1 El guardián de R7: de 0 a 10 motores

**La evidencia del "antes"**, medida antes de tocar nada, con una sonda temporal:

```
moduloResuelto=false  dotnetRestaurado=false
  trivy                depDisponible=false
  govulncheck          depDisponible=false
  dotnet-vuln          depDisponible=false
  dotnet-format        depDisponible=false
  dotnet-build         depDisponible=false
  eslint               depDisponible=false
  tsc                  depDisponible=false
  mypy                 depDisponible=false
  pmd                  depDisponible=false
  google-java-format   depDisponible=false
TOTAL EJERCITADOS: 0 de 10
```

Y la prueba de que es **estructural y no de esta máquina**: pidiendo el e2e PRIMERO en la línea
de comandos, Go lo sigue ejecutando DESPUÉS del guardián, porque el orden es el de registro
—alfabético por archivo— y no el de `-run`:

```
=== RUN   TestElArnesNoAbsuelveAUnMotorConSuDependenciaPresente
    arnes_test.go:158: esta máquina no tiene ninguna de las dependencias externas
=== RUN   TestElSistemaCompletoEstaCableado
```

**El arreglo va a la causa.** El guardián preguntaba a la máquina; su trabajo es probar la
**tabla de decisión** de `revisarInforme`. Se extrajo la pregunta a un punto de sustitución
—`faltaLaDependencia` en `extremo_a_extremo_test.go`— y los dos guardianes la fijan con
`conLaDependencia(t, presente)`. La lista de motores sale ahora de `violaciones()` y no de una
lista a mano, así que un motor nuevo entra solo. Y quedarse sin motores que ejercitar ya no es
`t.Skip`, es `t.Fatal`: un skip no se lee en la salida y por eso este bug sobrevivió una
remediación entera.

**El "después":**

```
motores ejercitados con la dependencia presente: 10 ([google-java-format pmd mypy trivy
  govulncheck eslint tsc dotnet-vuln dotnet-format dotnet-build])
motores ejercitados con la dependencia ausente:  10 (los mismos)
```

**Sabotajes, todos detectados:**

| Sabotaje | Resultado |
|---|---|
| El bug original de R7: `case falta:` → `case v.requiere != "":` (absolver por DECLARAR) | **ROJO en los 10 subtests**, uno por motor |
| Revertir el punto de sustitución y volver a preguntar a la máquina | ROJO |
| `faltaLaDependencia` degenerado a `return false` | ROJO |
| `faltaLaDependencia` degenerado a `return true` | ROJO |
| El degradado sin dependencia que culpar deja de poner rojo | ROJO |
| `¡NO CAZÓ!` deja de poner rojo | ROJO |

El tercero y el cuarto los caza `TestElValorPorDefectoPreguntaALaComprobacionDeVerdad`, añadido
justo para eso: el precio de un punto de sustitución es que el camino real deje de ejercitarse,
y sin esa prueba alguien podría dejar el valor por defecto mintiendo con los dos guardianes en
verde.

### 7.2 Las otras dos puertas de la ruta relativa

`registry.path()` y `warmup.warmListPath()` pasan a `filepath.IsAbs` con la misma semántica que
`store.DefaultPath` y `dirDatos`: absoluta, o el temporal, o `""`. Devolver `""` es seguro
porque **todos** los llamadores ya trataban el fallo como best-effort (los `ReadFile`/`Open`
devuelven error y `Load`/`Remove`/`WarmAll` lo tratan como "no hay archivo"; los `WriteFile`
llevan `_ =` declarado).

Tests nuevos, escritos **antes** del arreglo y confirmados rojos:

```
--- FAIL: TestElRegistroNuncaSeEscribeDentroDelArbolDeTrabajo/valor_relativo
        el registro se escribió dentro del árbol de trabajo: [datos]
--- FAIL: TestElRegistroNuncaSeEscribeDentroDelArbolDeTrabajo/punto
        el registro se escribió dentro del árbol de trabajo: [codeguard]
--- FAIL: TestLaListaDePrecalentamientoNuncaSeEscribeEnElDirectorioDeTrabajo/valor_relativo
--- FAIL: TestLaListaDePrecalentamientoNuncaSeEscribeEnElDirectorioDeTrabajo/punto
```

Los dos llevan contraparte: con un `LOCALAPPDATA` legítimo el registro y la lista tienen que
seguir funcionando, o el arreglo se "conseguiría" no escribiendo nunca.

**Detalle que conviene saber:** el caso `"   "` NO fallaba, pero por accidente — Windows rechaza
un componente hecho sólo de espacios y fallaba el `MkdirAll`. Es la misma casualidad que el
coordinador ya había notado en `dirDatos`. Escapar de la guarda y que te salve el sistema
operativo no es lo mismo que estar protegido, y por eso el caso se deja en la tabla.

**Precisión sobre `warmListPath`, para no inflar la gravedad:** lo llama el daemon, cuyo
directorio de trabajo NO es el repo analizado, así que el archivo no aterrizaba en el árbol del
usuario. Se arregla porque es la misma clase de bug y porque "el CWD del daemon nunca será un
repo" es justo la suposición que deja de ser cierta sin que nadie lo note.

### 7.3 Los dos tests débiles, anclados

**`TestRunSinDiffSeSalta`** ahora comprueba el motivo (no sólo el veredicto) y que no se
confunda con el otro `Skipped` temprano; y se le añadió el control positivo que faltaba,
`TestConDiffDeVerdadRunNoSeSalta`.

| Sabotaje | Resultado |
|---|---|
| `Run` devuelve `Skipped` SIEMPRE | **ROJO** (antes pasaba con nota) |
| El diff ausente cuenta la historia del repo no enrolado | **ROJO** |

**`TestTrayCambiosConcurrentesNoSeTraban`** → `...NoSePierdenNiSeMezclan`. La aserción `len != 0`
pasaba habiendo perdido 1.599 de 1.600 emisiones. Ahora exige las dos propiedades que rompe un
candado mal puesto: que no se pierda **ninguna** emisión, y que el par (estado, tooltip) llegue
entero —una combinación que nadie escribió sólo puede salir de una lectura partida—.

| Sabotaje | Resultado |
|---|---|
| `aplicar` pinta el estado con un tooltip ajeno | **ROJO** |
| Se pierde una emisión de cada dos | **ROJO** |

Queda **escrito en el propio test** lo que NO cubre: el orden de pintado de dos cambios
simultáneos (la carrera residual D1). Un test que declara su alcance vale más que uno que
aparenta cubrirlo todo.

### 7.4 La advertencia de la interacción H041×H003

Escrita en `permitidas` (`internal\engines\proc\entorno.go`): quitar de esa lista una variable
que git necesite ya no produce una degradación silenciosa sino un **commit bloqueado en todas
las máquinas y en cada commit**, porque el hook falla cerrado (H041) y git corre con el entorno
acotado (H003/N002). Ninguno de los dos autores lo escribió.

### 7.5 Estado de la suite tras estos cambios

`go build ./...`, `go vet ./...` y `staticcheck -checks U1000` limpios (confirma además que
quitar `depDisponible`, ya sin uso, no dejó huérfanos).

En la corrida completa apareció **un fallo nuevo y ajeno**, distinto de los ya conocidos:
`TestLoQueViajaAlModeloVaRedactado` no pudo compilar su binario con
`package internal/profilerecord is not in std` y `open ...\go-build\83\...: The system cannot
find the path specified` — la caché de compilación de Go corrompida por muchos `go build`
simultáneos (míos y de los demás agentes). **Aislado, pasa.** No es del producto ni de estos
cambios.

Y una novedad buena: **el daemon zombi PID 26276 ya no existe** y no queda ningún pipe
`codeguard-*` ocupado, así que `TestLaCapaLLMNoBloqueaAunqueElModeloInsista` vuelve a pasar. El
defecto de fondo sigue sin arreglar —`llm_test.go:305` compone el nombre del pipe sólo con el
nombre del test— y volverá a morder en cuanto una corrida muera a medias otra vez.

---

## Lo que NO se verificó

- Los dos archivos que aparecieron después de las 07:38 (`identidad\auditoria.go` y dos tests).
- `-race`: esta máquina no tiene cgo. Los tres data races corregidos (H004, H005, H023) **no se
  han verificado con detector**, sólo por construcción y por pruebas de humo.
- Los `dist\*.ps1` y el CI, fuera del alcance encargado.
