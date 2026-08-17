# Remediación auditoría K3 — estado

Actualizado: 2026-08-15, madrugada. **Todo SIN COMMITEAR.** 73 archivos tocados, `go build` y `go vet` limpios.

## Método (no negociable)
1. Validar contra el código real antes de actuar. 2. Fix de causa raíz, jamás parche. 3. Test PRIMERO. 4. Implementador + validador adversarial INDEPENDIENTE. 5. Nada se cierra sin veredicto aprobado.

---

## Resultado sobre la auditoría original

De las **29 altas**: 10 eran falsos positivos, 1 ya estaba corregida, y las **18 restantes están cerradas y validadas** por un agente distinto del que las arregló.

H003 · H004 · H005 · H006 · H007 · H009 · H011 · H012 · H013 · H014 · H018 · H019 · H021 · H023 · H025 · H027 · H028 · H029

Más **H041** (catalogada "media", en la práctica el peor fallo del informe): un error de git dejaba pasar el commit **sin revisar secretos**, con stderr vacío. Reproducido con un almacén de objetos dañado: el commit **se creaba con credenciales de AWS dentro**. Cerrada y validada.

### Falsos positivos (10)
H001 H002 H010 H015 H016 H017 H020 H022 H024 H026. La causa más repetida: el auditor asumió soporte Linux/macOS que este producto no declara. H017 lo reclasifiqué yo por coherencia con esa misma regla.

---

## Hallazgos NUEVOS — no estaban en la auditoría, los encontramos trabajando

| | Qué es | Estado |
|---|---|---|
| **N001** | **Ejecución de código** desde un repo hostil: un `.jar` plantado en el árbol se ejecutaba al analizarlo | cerrado y validado |
| **N002** | 10 procesos heredaban el entorno completo con la API key (no 6); dos lanzan `python -c`, que la entrega a código arbitrario | cerrado y validado |
| **N003** | `codeguard repair` **firmaba como legítimos** binarios que traía el repo analizado | cerrado y validado |
| **N004** | La demo del menú **tapa bloqueos reales** durante 12 s y deja la bandeja mintiendo | en curso |
| **N005** | Un secreto **añadido y quitado en dos commits** nunca se escanea y queda en el historial | en curso |
| **UI** | El orbe se ponía **VERDE** por un análisis que no ocurrió (4 superficies) | arreglado, **falta validación independiente** |

**N005 es el más humano de todos**: no hace falta un atacante. Commiteas una credencial, te das cuenta, la quitas en el commit siguiente — y nunca se escanea. La causa: la etapa 0 decide si hay trabajo mirando el diff de **árboles**, mientras la compuerta de secretos escanea el **historial**. El conjunto pequeño decide por el grande.

---

## ⚠️ ACCIONES QUE DEPENDEN DE TI

1. **ROTA `ANTHROPIC_API_KEY` y `FOUNDRY_API_KEY`.** Estaban en texto plano en tu registro, las heredaban procesos hijos, y existía un camino por el que **bastaba clonar un repositorio** para que un `codeguard config --probar` mandara la credencial al servidor del atacante. Verificado con un listener local: llegó la clave real, 91 caracteres de cabecera.
2. **Mata el proceso 26276** (`codeguard-daemon.exe`, arrancado anoche 23:36 desde un `%TEMP%`). Es un daemon filtrado por una corrida de tests que retiene un pipe; mientras viva, un test está rojo aquí pase lo que pase. No tiene estado que perder. La causa raíz ya está asignada.
3. **El CI no ejecuta el detector de carreras** en ningún workflow, y esta máquina no puede correrlo (falta compilador de C). Los tres fixes de concurrencia (H004, H005, H023) están demostrados por comportamiento observable pero **nunca certificados con `-race`**. Activarlo puede sacar a la luz carreras preexistentes y poner el pipeline en rojo: por eso no lo toqué.
4. **`dist\install.ps1`** sigue escribiendo la clave en texto plano en el registro en cada instalación con `-ApiKey`, regenerando la precondición que acabamos de cerrar.

---

## Lo que enseñó el proceso

**H009 necesitó TRES rechazos.** Cada vuelta apareció una clase que la anterior no veía: la opción (`--output=`), el pathspec con comodín (`*`), la diferencia simétrica (`.`). Y ninguna se detectó leyendo código: **las tres salieron de compilar el binario y atacarlo**. La cuarta (N005) ni siquiera pasa por el texto del rango.

**Dos validaciones me corrigieron a mí.** Audité cuatro bucles de SQLite cuando había seis. Y concluí que un caso era inofensivo midiéndolo **sólo en historial lineal**, que es el único escenario donde el fallo no se ve — la misma trampa que dejó pasar las dos validaciones anteriores.

**Lo que hizo la diferencia fue la prueba de mutación**: romper cada arreglo a propósito para comprobar que los tests lo cazan. Así se descubrió que el guardián de R7 —el test que existe para que ningún motor se dé por probado sin correr— **no ejercita ni uno de sus diez motores, en ninguna máquina**.

---

## En curso ahora

N005 (la cuarta puerta) · el guardián vacuo de R7 + dos rutas relativas más · los tests del motivo · N004 + el daemon zombi.

## Pendiente
Las 184 medias (triaje hecho: 23 racimos, ver `TRIAJE-MEDIAS.md`) y las 248 bajas. **R15 (14 hallazgos de concurrencia) queda congelado hasta que haya `-race`**: arreglarlos sin poder verificarlos serían 14 fixes de fe.

Detalle completo de la verificación cruzada en `VERIFICACION-CONJUNTO.md` (326 líneas, con las pruebas de mutación).

---

## 🔴🔴 N007 — LO MÁS GRAVE DE TODA LA REMEDIACIÓN. Requiere tu decisión.
**Un repositorio puede APAGAR las 119 reglas de la casa** vendoreando su propio `rulepacks/<misma-version>/`, y el hook lo presenta como limpio. Medido sobre el mismo archivo con una inyección SQL de manual:

| | rulepack | resultado |
|---|---|---|
| control | el de la casa (instalado) | **EXIT 1** — BLOQUEADO, 2 hallazgos |
| ataque | el vendoreado en el repo | **EXIT 0** — 0 hallazgos |

Y con el daemon vivo el desarrollador lee: `formato/lint/tipos/reglas/migraciones ✓` / `listo — commit permitido`. **Ni una palabra de que las reglas de la casa no corrieron.** No hace falta atacante: basta clonar el repo, o que alguien añada un directorio para saltarse la compuerta.
Lo revelador: el hook ya avisa a gritos cuando el rulepack **falta** ("las reglas de la casa NO se aplicaron"), y **no avisa cuando lo sustituyen** — que es peor, porque no deja rastro.

**Dictamen del validador (no implementado, es decisión de producto):** el vendoreado hay que conservarlo, resuelve un fallo real y documentado. Lo indefendible es la **prioridad incondicional y muda**. Dos cambios lo cierran sin perder lo que lo justificó: (1) usar el vendoreado sólo cuando el instalado NO tiene esa versión — el caso que lo motivó; (2) **decirlo en el veredicto** cuando se use. Si ambos existen con el mismo número, es una colisión de versiones y debería ganar el de la organización: el número es una promesa de paridad con el CI, y ahí dos artefactos distintos se llaman igual.

## N006 — CORREGIDO: la hipótesis era peor que la realidad
Sí se cuela un `<!-- fp:… -->` y `leerFingerprintsPrevios` lo relee, pero **NO suprime hallazgos**: los actuales se recalculan del análisis, no del informe. El efecto real es una entrada de más en "Resueltos desde el informe anterior". Tras el saneado el atacante ya no controla el título. Cierre pendiente opcional: anclar `fpRe` a fin de línea.

## Señalado, sin tocar
`internal\shadow\shadow.go:193` mete `f.Message` en el **prompt del LLM**: un rulepack vendoreado puede escribir instrucciones al modelo. Inyección de prompt, no de terminal; acotado porque el modelo nunca bloquea, pero puede envenenar lo que la sombra marca como "verificado".

## Pendientes menores anotados
- `internal\pipeline\llm_test.go:305` compone el nombre del pipe sin PID (el zombi murió solo, el defecto sigue).
- `f.Message` de los hallazgos sin sanear en la salida del hook (asignado, pendiente de reporte).
- `dist\uninstall.ps1` no borra la credencial de la bóveda al desinstalar.

## 🟠 N008 — el bloqueo por secreto no deja rastro (lo encontró Héctor probando la instalación)
Medido con la v1.9.3 instalada, dos commits en el mismo repo enrolado:
- **Commit limpio** → el daemon lo analiza y lo registra (`gofmt`, `semgrep`, la sombra en el log).
- **Commit BLOQUEADO por un secreto** → el daemon **no recibe nada**. Log vacío, panel sin cambio, y `codeguard stats` responde *"sin hallazgos registrados todavía"* después de haber bloqueado una credencial de AWS.

**Causa:** la etapa 1 (secretos) corre EN EL PROCESO DEL HOOK y sale con `os.Exit(1)` en cuanto bloquea, sin avisar al daemon ni persistir el run.

**Por qué importa:** el evento más valioso que produce el producto —"impedí que una credencial entrara al repo"— es el único que no queda registrado. Consecuencias: el orbe no refleja un bloqueo activo; no hay métrica de cuántas veces la compuerta te ha salvado (justo lo que justifica la herramienta ante un equipo); y si el desarrollador no ve esa salida en la terminal (scroll, IDE, CI), no queda constancia en ninguna parte.

Es la misma familia que el resto: la superficie que el usuario mira no cuenta lo que de verdad pasó. **Sin arreglar.**

## 🟠 N009 — enrolar un repo no aparece en el panel (lo encontró Héctor)
`codeguard init` escribe `repos.json` y **no avisa al daemon**: `cmd\codeguard\initcmd.go` no tiene ni una llamada por el pipe (grep de `ipc.Call`: cero). El log del daemon está vacío a la hora del init.
El panel sólo relee el registro al abrirse (`escritorio.go:451`, evento `panel-ready` → `mostrarContextoActivo` → `sembrarDesdeRegistro`), y esa función además **sólo siembra cuando no hay contexto activo** — así que con un proyecto ya en pantalla, el repo recién enrolado puede no aparecer ni reabriendo.

**Efecto para el usuario:** enrolas un repo, el comando dice "LISTO", y el agente no lo muestra. Sin explicación ni forma de saber si funcionó.

Misma familia que N008: el producto hace el trabajo y la superficie que el usuario mira no se entera. Arreglo natural: que `init` avise por el pipe (ya existe el patrón: `codeguard config` llama a `open-config`), o que el panel refresque el registro al mostrarse en vez de sólo al arrancar en frío. **Sin arreglar.**

## 🟠 N010 — el instalador instala un motor que esta máquina no puede ejecutar
Medido en la instalación real (v1.9.3):
```
java -jar google-java-format-1.36.1-all-deps.jar --version
UnsupportedClassVersionError: class file version 65.0 (Java 21),
this Java Runtime only recognizes up to 61.0   ← JDK 17 instalado
```
El instalador **verificó el checksum del publicador** y lo dio por bueno; nunca comprobó que el jar **arranque** con el JDK presente. Y `codeguard engines` lo lista como `✓ coincide con el binario publicado` — cierto y a la vez engañoso: coincide, pero no corre.

**Efecto:** el formateo de Java queda degradado de forma PERMANENTE y silenciosa en esta máquina. No es un fallo transitorio que se arregle en el commit siguiente. El aviso del pipeline sí lo nombra (`google-java-format:error`), pero nada dice que la causa sea la versión del JDK ni que no vaya a arreglarse sola.

**Arreglo natural:** que la instalación de un motor incluya una comprobación de arranque (`--version`), no sólo de hash; y que si falla, el motivo lo diga (versión de JDK insuficiente) en vez de dejarlo como un error genérico. Los motores de Java del manifiesto deberían además declarar su JDK mínimo.
**Sin arreglar.**

### Nota de contraste (esto NO es un defecto)
`dotnet-build` y `dotnet-vuln` también fallaron, pero con un mensaje ejemplar: explican que falta `dotnet restore`, y **justifican por qué el hook usa `--no-restore`** (el restore va a la red y el camino del commit no puede depender de ella). Es accionable y honesto — el contraste con N010 muestra qué falta en el otro.

## 🔴 N011 — la compuerta de migraciones NUNCA se dispara (lo destapó la demo de Héctor)
`codeguard init` sobre un repo con SQL detecta el lenguaje (`languages: [go, python, sql, typescript]`) e instala squawk (v2.62.0, funcionando)… pero deja **`paths.migrations: []` VACÍO**. Sin rutas que vigilar, la compuerta `migration_unsafe: block` no se dispara jamás.

Medido: un `db/002_moneda.sql` con `ALTER TABLE pedidos DROP COLUMN total;` y `ADD COLUMN ... NOT NULL` sin default —peligrosas de manual— **pasó con "listo — commit permitido"**. En el log del daemon squawk no aparece: no corrió.

**Por qué es grave más allá del motor:** en los pesos de riesgo del propio config, `touches_migration: 30` es **el factor MÁS ALTO** — por encima de tocar rutas sensibles (25) o de que el código venga de una IA (20). El sistema declara las migraciones lo más delicado que existe y no está mirando ninguna.

**Causa raíz (medida, no leída):** la detección de `init` pedía la palabra literal `"migration"` DENTRO de la ruta (`cmd/codeguard/initcmd.go:58`). Contra los layouts que existen de verdad eso fallaba en **6 de 8**:

| layout | antes | ahora |
|---|---|---|
| `db/002_moneda.sql` (el caso medido) | `[]` | `db/*.sql` |
| `db/migrate/…` (Rails) | `[]` | `db/migrate/{*,**/*}.sql` |
| `sql/V1__init.sql` (Flyway) | `[]` | `sql/*.sql` |
| `schema/001_init.sql` | `[]` | `schema/{*,**/*}.sql` |
| `002_moneda.sql` en la raíz | `./*.sql` — **no casa con nada** | `*.sql` |
| `prisma/migrations/<ts>/migration.sql` | un glob por carpeta EXISTENTE: la migración de mañana nacía sin vigilar | `prisma/migrations/**/*.sql` |
| `supabase/migrations/…` | ya funcionaba | igual |
| `migrations/001.sql` | ya funcionaba | igual |

**Arreglado en tres sitios, porque el silencio estaba en tres:**
1. `internal/migraciones` (paquete nuevo) — la detección de verdad, compartida por `init` y el pipeline para que no puedan discrepar. Reconoce directorios que declaran esquema y nombres versionados (`001_`, `20240101_`, Flyway `V1__`/`U1__`/`R__`). **No** vigila `.sql` al bulto: las consultas de sqlc y los modelos de dbt quedan fuera a propósito, y lo que queda fuera se REPORTA.
2. `cmd/codeguard/statuscmd.go` — el chequeo del pilar datos se saltaba entero cuando la lista venía vacía, o sea que **el único sitio que podía delatarlo callaba justo en el caso roto**. Ahora con SQL y lista vacía sale en rojo.
3. `internal/pipeline` — `init` sólo arregla los repos que nazcan de ahora; el repo donde se midió el fallo YA estaba enrolado. Si un commit toca algo que parece una migración y ningún glob lo cubre, el veredicto lo dice: `capas no revisadas: squawk:migracion-sin-vigilar`.

**Verificado de punta a punta** (repo nuevo, `db/002_moneda.sql`, el mismo DDL de manual):
- con la lista bien: `BLOQUEADO: 2 problema(s)`, `EXIT=1`, **el commit no se creó** — `ban-drop-column` y `adding-required-field` nombrados.
- con la lista vacía a la fuerza (simulando un repo ya enrolado): pasa —no puede hacer otra cosa— pero deja de mentir: `— PARCIAL`, `commit permitido sobre lo que SÍ se revisó`, `capas no revisadas: squawk:migracion-sin-vigilar`, y el log nombra el archivo. Antes: `migraciones ✓` / `listo — commit permitido`.
- `codeguard status`: `✗ datos  hay SQL y paths.migrations está vacío → migration_unsafe no vigila nada`.

**Prueba de mutación: 4 de 4 cazadas** — quitar el glob de la raíz del árbol, devolver el `./*.sql` roto, aceptar cualquier `.sql` como migración, y calcular el aviso sin publicarlo en el veredicto.

### El arreglo de N011 rompió otras tres cosas, y las rompió de verdad

Un validador adversarial las midió y yo confirmé la primera por separado antes de leer su informe. Todas son daño **causado por rellenar `paths.migrations`**: mientras la lista estaba vacía, los defectos de alrededor no costaban nada porque squawk no corría jamás.

**1 · Los repos que no son PostgreSQL pasaron de "sin cobertura" a "bloqueados".** `init` escribía `migrations_dialect: postgres` a ciegas. Medido: un `CREATE INDEX` legal en SQLite salió **BLOQUEADO exigiendo `CONCURRENTLY`** —sintaxis que en SQLite no existe—, y en MySQL salieron **79 hallazgos, todos `syntax-error`**, presentados como "problemas que el CI también rechazaría". El arreglo propuesto era imposible de aplicar: el peor tipo de bloqueo.
→ `internal/migraciones/dialecto.go` deduce el motor del propio DDL, **sólo con pruebas positivas** y descartando comentarios y cadenas (si no, documentar «aquí no usamos AUTO_INCREMENT» apagaría la compuerta). Sin marca se queda en postgres: no adivina, que era la objeción legítima del comentario original.
→ `squawk`: un `syntax-error` deja de ser un hallazgo del código. Se colapsa a **un aviso por archivo, no bloqueante** (`dialecto-no-postgres`), porque no habla del SQL sino de que el parser no supo leerlo.
Verificado: SQLite y MySQL detectados; deuda `data` de 2 y de 9-11 → **0**; sus commits pasan; y el control positivo, **PostgreSQL con `DROP COLUMN` + `ADD COLUMN NOT NULL`, sigue bloqueando**.

**2 · Vigilaba de más.** `test/fixtures/001_datos.sql` entraba en la lista y tocarlo daba EXIT=1 por `ban-drop-table` — sobre un fixture que existe justamente para crear y tirar tablas. Igual con semillas, volcados, informes numerados por año y las consultas de sqlc.
→ Veto de directorios que no son esquema, que gana **incluso dentro de un árbol de migraciones**. De paso entraron Flyway con puntos (`V1.1__`) y `structure.sql`/`schema.sql`.

**3 · Rojo permanente con remedio imposible.** Un repo de sólo consultas salía `✗ datos` para siempre y el remedio propuesto —`init --force`— vuelve a dejar la lista vacía, porque esas consultas no son migraciones.
→ `status` sólo avisa si existe un archivo que `migraciones.Parece()`, y lo nombra. Medido: repo sqlc → `todo en orden`; repo con `db/001_init.sql` y lista vacía → ✗ señalando el archivo.

**CERRADO**, pendiente de que el validador ataque los arreglos nuevos (sobre todo el detector de dialecto: clasificar mal un PostgreSQL real le apagaría la compuerta en silencio, que es peor que el bloqueo que se acaba de quitar).

### Segunda ronda: los arreglos de arriba rompieron OTRAS cuatro cosas

El mismo validador atacó lo recién escrito y acertó en las cuatro. Todas medidas con repos de juguete y binario compilado, ninguna encontrada leyendo código.

**a · Un archivo decidía por todo el repo, y lo apagaba en silencio.** `Dialecto()` devolvía a la primera marca, así que un repo que migró de MySQL a PostgreSQL y conservó el volcado viejo entre sus migraciones quedaba marcado como MySQL entero: `DROP COLUMN` + `ADD COLUMN NOT NULL` sobre una migración PostgreSQL de verdad **pasó con EXIT=0**, y `status` lo remataba con un ✓ verde. De los dos errores posibles este es el peor: bloquear de más se ve y se arregla con una línea; no vigilar no se ve nunca.
→ Con marcas de **más de un motor** no se decide nada y manda el valor por defecto, que deja la compuerta encendida. Se añadieron marcas de PostgreSQL sólo para poder DETECTAR el conflicto, y se descartaron a propósito `SERIAL`, `RETURNING` y `USING BTREE|HASH`: existen en MySQL, MariaDB y SQLite, y habrían provocado conflictos falsos que reintroducen el bloqueo.

**b · El veto se comía migraciones de producción.** Hasura numera `migrations/<fuente>/<ver>_<nombre>/up.sql` y llamarle `analytics` a una fuente es el layout canónico; también caían `supabase/migrations/reports/…` y un monorepo con un servicio llamado `docs`. Medido: un `DROP COLUMN` que antes bloqueaba pasó con EXIT=0, y callaban a la vez `init`, `status` y el aviso del pipeline.
→ Veto en **dos niveles**: lo que nombra CONTENIDO (seeds, fixtures, dumps, queries, tests…) descarta siempre; lo que nombra un ÁREA (docs, reports, analytics, models) sólo descarta si no hay un directorio de migraciones por encima. Y `Globs` llama a `Parece` para que las dos superficies no puedan discrepar.

**c · Dejé entrar un `DROP COLUMN`.** Al volver no bloqueante el `syntax-error` se abrió un agujero de segundo orden: cuando squawk no parsea un archivo **deja de evaluar el resto**, así que un typo bastaba para que la sentencia destructiva no se mirara nunca. Antes lo frenaba el propio error de sintaxis; después no lo frenaba nada.
→ Vuelve a **bloquear** con regla `migracion-ilegible`: uno por archivo en vez de 79, y con las dos salidas reales (arreglar la sintaxis / declarar el motor). Verificado: `DROP COLUMN` + `SELCT 1` → BLOQUEADO.

**d · El SQLite idiomático sin marcas sigue sin detectarse** —no tiene ninguna, como el esquema de este propio repo—, así que puede seguir cayéndole squawk encima.
→ No se puede resolver detectando. La escapatoria va pegada al `FixHint` de **todo bloqueante** de squawk: «si esto no es PostgreSQL, declara `paths.migrations_dialect`». El bloqueo deja de ser imposible de arreglar, que era el daño real.
→ Y `status` ya no dice «✓ datos · squawk no aplica» sino «el pilar datos **NO revisa nada** en este repo»: no aplicar no es estar protegido.

**Trampa de método, anotada porque casi me come:** el gancho ejecuta `codeguard.exe` desde `git config codeguard.binpath`. Compilar con otro nombre y medir da resultados del binario VIEJO. Un caso de V3 salió «correcto» por eso; repetido con el binario bueno, seguía roto.

### Tercera ronda, y el cambio de diseño que la cerró

El validador volvió a acertar en todo, y dos de sus hallazgos eran regresiones introducidas veinte minutos antes:

- **`NVARCHAR(n)` es MySQL legal** (sinónimo de `VARCHAR(n) CHARACTER SET utf8`) y disparaba la marca de SQL Server; **`jsonb()` es función nativa de SQLite desde la 3.45**. Cada una provocaba un conflicto falso en un repo de un solo motor, y el conflicto devolvía PostgreSQL: **el bloqueo con consejo imposible, de vuelta por la puerta de atrás**.
- **PostgreSQL moderno no deja ninguna huella** (`bigint GENERATED BY DEFAULT AS IDENTITY`, `varchar`, `timestamp`), así que un volcado heredado ganaba por no tener rival y el `DROP COLUMN` pasaba con EXIT=0.
- `migracion-ilegible` **bloqueaba PostgreSQL válido**: salida de `pg_dump` (`COPY … FROM stdin`), meta-comandos de psql, marcadores `${schema}` de Flyway. Ahí las dos salidas del mensaje no aplicaban.
- Las **semillas nombradas como archivo** (`20240103_seed_datos.sql`, convención de Supabase/dbmate/goose) bloqueaban por `ban-drop-table`.

**Decisión de producto de Héctor, y es la que cierra la clase entera:** `init` **avisa pero nunca decide**. Siempre escribe `migrations_dialect: postgres` —lo único que garantiza que la capa siga revisando— y, si el DDL tiene marcas de otro motor, lo dice nombrando el archivo. Cuando además hay marcas de PostgreSQL, lo añade («puede ser un volcado heredado»), que es lo que permite distinguir un repo MySQL de un legado.

El razonamiento: una detección que ACIERTA ahorra una línea de configuración; una que FALLA apaga una capa entera en silencio con un ✓ verde encima. No es una apuesta simétrica. Tres rondas de heurística lo demostraron — y con esto no queda heurística que pulir, porque ya no hay nada que decidir.

Los arreglos de las marcas se mantienen igualmente: ahora sólo afectan al RUIDO del aviso, no a la corrección.

### Lo que queda abierto de ese informe
- `init --force` mete en la baseline un `ban-drop-column` preexistente **sin nombrar la regla**: queda amnistiado en silencio. El resumen sólo dice «data 8».
- Migraciones reales aún fuera: **sqitch** (`deploy/`, `revert/`, `verify/`), `sql/updates/`.
- **El daemon instalado no tiene el aviso**: la cadena `migracion-sin-vigilar` no está en su binario, así que con el agente vivo el commit sigue diciendo «listo — commit permitido». No existe hasta reinstalar.

---

## Punto de corte de la sesión (2026-08-15, tarde)

**Cerrado en esta última tanda** (yo implemento, un validador adversarial me discute):
- Señal visible al enrolar: el panel se abre de verdad (`InvokeAsync(mostrarPanel)`; emitir `panel-show` a secas no abría nada Y dejaba el orbe mudo), respeta `ui.auto_open_panel: never`, y el "sin análisis todavía" vive en `tooltipDelOrbe` para que lo digan igual el enrolamiento, el switch-repo y el sembrado. Test nuevo con los tres casos.
- **N010 cerrado en las dos superficies**: la instalación comprueba que el motor ARRANCA (no sólo su hash) y `codeguard engines` estrena el estado `identidad.NoArranca` — ni ✓ ni ✗ — sin tocar el código de salida, que en el CI es compuerta de cadena de suministro.
- **Regresión propia detectada por el validador y corregida**: `codeguard repair` no conocía `NoArranca`, caía en `default` y salía con 1 — y `dist\instalar-motores.ps1` propaga ese código al asistente, así que **el instalador habría cerrado EN FALLO por un JDK viejo**, con un mensaje sobre gitleaks, y por algo que `repair` no puede arreglar nunca (reinstalar da el mismo jar con el mismo hash). Verificado: `repair` sale 0 y avisa.
- Tres defectos que sólo se ven midiendo: falso "arranca" por `$LASTEXITCODE` heredado del comando anterior; diagnóstico cortado a 80 columnas (el ancho de la consola del asistente, no el de la terminal del desarrollador); y acusar al motor cuando el roto es el `java` del sistema.

**PENDIENTE INMEDIATO:** N011 (la compuerta de migraciones nunca se dispara) — sin empezar.

**ALCANCE NUEVO pedido por Héctor**, en la memoria del proyecto: pruebas a escala real (el código lo escribirá una IA), UI/UX del agente mucho más rica (stack visible, repos bien organizados, historial de resueltos, orbe con función adaptativa, motores elegidos a la vista, progreso en vivo) e instalador guiado que explique qué se va a instalar.
