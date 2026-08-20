# CodeGuard

**El commit que no debe entrar, no entra.**

Agente local de análisis pre-commit para Windows. Se mete en el gancho de
pre-commit de git y revisa tu cambio **antes** de que llegue al repositorio.
Corre motores deterministas en tu máquina y bloquea sólo lo que el CI también
rechazaría.

No es un linter más: es la promesa de que si el commit pasa aquí, pasa allá.

```
CodeGuard  secretos ✓
CodeGuard  formato/lint/tipos/reglas/migraciones ✗
CodeGuard    [gha-action-sin-sha] .github/workflows/ci.yml:7  Acción anclada por etiqueta, no por SHA
CodeGuard    [lockfile-ausente] package.json:1  package.json cambió y el proyecto no tiene lockfile
CodeGuard    [orm-raw-interpolado-ts] src/api.ts:2  Consulta cruda del ORM con plantilla interpolada
CodeGuard    [cookie-sin-httponly] src/api.ts:3  Cookie de sesión sin httpOnly
CodeGuard  BLOQUEADO: 4 problema(s) que el CI también rechazaría  (4.6 s)
```

---

## Los cinco principios

Mandan sobre cualquier decisión de diseño.

| | |
|---|---|
| **P1** | Sólo lo determinista bloquea. Lo que bloquea aquí, bloquea en el CI. |
| **P2** | El modelo aconseja y **jamás** bloquea. |
| **P3** | El veredicto se explica: regla, archivo, línea, por qué importa y qué hacer. |
| **P4** | El agente no secuestra el trabajo. Si algo falla, degrada y avisa; no impide commitear. |
| **P5** | Nada que parezca una credencial sale a la red. La redacción ocurre antes de cualquier llamada. |

---

## El recorrido de un commit

Lo que pasa entre que escribes `git commit` y que el commit existe.

**Etapa 0 · Elegibilidad.** Antes de analizar hay que decidir si hay algo que
analizar. Un merge, un revert, un cambio que sólo toca rutas excluidas o un
repo sin enrolar salen por aquí, y el motivo viaja como texto hasta la
terminal. La distinción importa: una decisión de configuración del equipo no
se anuncia igual que una avería.

**Etapa 1 · Secretos.** gitleaks corre *en el proceso del gancho y sin red*,
antes de que nada salga de tu máquina. Es la única capa **fail-closed**: si no
puede correr, el commit se detiene. Un análisis que no pudo mirar credenciales
no está en condiciones de decir que no hay ninguna.

**Etapa 2 · Deterministas.** Los motores que aplican al cambio corren en
paralelo. Quién va a mirar se decide *antes* de lanzar a nadie, porque el
denominador del progreso —«3 de 9»— tiene que existir desde el primer
instante. Cada capa publica su estado en cuanto termina. Un motor que falla no
bloquea: degrada y lo dice.

**Etapa 2b · Forma del cambio.** Lockfiles, tamaño del cambio y complejidad por
función. No dependen de ningún binario de terceros ni de la red, así que corren
siempre.

**Etapa 7 · Consolidación.** Se deduplica por archivo, línea y regla, y se
ordena por severidad. Antes se aplican la baseline (sólo lo nuevo bloquea) y la
auto-calibración. Si queda un bloqueante, el gancho sale con código 1 y **el
commit no llega a existir**.

Y en el CI corre **el mismo binario** con **el mismo rulepack**. La paridad no
es una promesa de la documentación: es que es el mismo programa leyendo las
mismas reglas.

---

## Qué te vigila

Una compuerta de secretos y **16 motores deterministas**. De un cambio concreto
sólo corren los que aplican: si no tocaste Go, gofmt no se ejecuta — y eso se
llama *no aplica*, que no es lo mismo que *no corrió*.

De esos 16, el instalador trae **9** (semgrep, squawk, ruff, mypy, trivy,
govulncheck, staticcheck, google-java-format y PMD); **gofmt** corre dentro del
propio CodeGuard; y los **6** restantes —`go vet`, `tsc`, `eslint` y los tres de
.NET— usan la cadena de herramientas que ya tienes. En `tsc` y `eslint` es
deliberado: se usa la versión **de tu proyecto**, que es la que corre en el CI.
Instalar la nuestra rompería la paridad en vez de defenderla. Si a tu repo le
falta alguna, el análisis lo dice en vez de dar un ✓ sobre una capa que no miró.

| Motor | Pilar | Qué mira | Bloquea |
|---|---|---|---|
| **gitleaks** | seguridad | Secretos en lo preparado. En el CI, el historial del rango | ⛔ siempre · *fail-closed* |
| **semgrep** | seguridad | Las 130 reglas de la casa del rulepack fijado | ⛔ severidad ERROR |
| **trivy** | seguridad | Dependencias con CVE conocido | ⚠️ local · ⛔ CI |
| **govulncheck** | seguridad | CVEs de Go **con alcanzabilidad**: si tu código llama al símbolo | ⚠️ local · ⛔ CI |
| **dotnet list package** | seguridad | CVEs de NuGet, el hueco que trivy no cubre sin lockfile | ⚠️ local · ⛔ CI |
| **squawk** | datos | Migraciones PostgreSQL con riesgo de tirar producción | ⛔ |
| **staticcheck** | calidad | Semántica SSA sobre los paquetes tocados | ⛔ severidad error |
| **gofmt** · **go vet** | calidad | Formato canónico y errores de alta certeza en Go | ⛔ |
| **ruff** | calidad | Formato y lint de Python | ⛔ errores reales |
| **mypy** | calidad | Tipos en Python, si el repo ya lo configuró | ⛔ |
| **tsc** | calidad | Tipos y compilación de TypeScript | ⛔ |
| **eslint** · **biome** | calidad | Estilo de TS/JS, con las reglas **del repo** | ⛔ |
| **dotnet format** | calidad | Formato de C# | ⛔ |
| **dotnet build** | calidad | Que el C# compile | ⛔ |
| **google-java-format** | calidad | Formato de Java, sin compilar ni classpath | ⛔ |
| **PMD** | calidad | Calidad de Java sobre el AST | ⛔ severidad error |

Dos decisiones que explican el resto:

- **eslint no impone estilo.** Corre el linter que el repo *ya* configuró y
  aplica **sus** reglas. Un proyecto que no configura ninguno queda fuera:
  hacer fallar un commit por una convención que el equipo no eligió convierte
  al agente en un obstáculo, y un obstáculo se desinstala.
- **squawk sólo corre contra PostgreSQL.** Es lo que declara
  `paths.migrations_dialect`. Contra otro motor no produce falsos positivos
  benignos: produce hallazgos bloqueantes cuyo arreglo rompe el esquema.

Y tres reglas que no miran el contenido de un archivo sino la **forma** del
cambio: lockfile desincronizado, complejidad ciclomática por función y cambios
por encima de lo revisable.

### Las compuertas

Versionadas con el repositorio, en el bloque `gates` de la configuración.

| Compuerta | Por defecto |
|---|---|
| `secrets` | `block` — y *fail-closed*: si no puede correr, bloquea |
| `format` · `compile` · `lint_error` · `semgrep_error` | `block` |
| `migration_unsafe` | `block` |
| `cve_critical` | `warn_local_block_ci` — avisa en tu máquina, bloquea en el CI |
| `llm` | `never_block` — no es un valor que se pueda subir |

**Auto-calibración:** una regla con suficientes votos de *falso positivo* en un
repositorio baja sola a aviso. gitleaks queda fuera de ese mecanismo, siempre.

---

## El orbe

Vive en la esquina de la pantalla y cambia de clima según el estado. Los
cambios se funden en ~0,8 s: nunca saltan. Prohibido por diseño: modales,
sonidos, notificaciones emergentes, robarte el foco.

| Estado | Clima | Susurro |
|---|---|---|
| `idle` | Niebla serena | «de guardia» |
| `working` | Ventisca brillante | «revisando tu cambio» |
| `pass` | Verde salvia luminoso | «puedes seguir» |
| `blocked` | Granito ferroso latiendo | «espera, hay algo» |
| `degraded` | Piedra arenisca apagada | «hay un hueco en la revisión» |
| `offline` | Montaña dormida | «sin modelo, reglas al día» |

Del orbe sale el **panel**, con el veredicto, la paridad con el CI, los
bloqueantes en acordeón y las capas que no pudieron mirar. Cada hallazgo lleva
el código señalado, por qué importa y cómo arreglarlo.

La cabecera enumera **todas** las capas, no sólo las que fallaron. Existe
porque «corrió y no encontró nada» y «no corrió» llegaban a la pantalla
idénticos — el mismo silencio que este producto existe para no producir:

| Estado de capa | Qué significa |
|---|---|
| `corrio` | Miró. El número de hallazgos dice qué encontró, cero incluido |
| `no-aplica` | No había nada de su tipo en el cambio |
| `degradada` | Tenía que mirar y no pudo |
| `ausente` | No está instalado: configuración, no avería |

Un **explorador 3D** mapea el repositorio a nivel de función: quién llama a
quién, qué consulta sale de dónde y dónde cayeron los hallazgos del último
análisis. Todo local, sin navegador.

---

## Instalación

Sin permisos de administrador, para el usuario actual.

```
CodeGuard-Setup.exe              # asistente gráfico
CodeGuard-Setup.exe /VERYSILENT  # reparto masivo
```

O con el script clásico:

```powershell
powershell -ExecutionPolicy Bypass -File dist\install.ps1
```

Instala binarios y motores bajo `%LOCALAPPDATA%\CodeGuard`, añade esas rutas al
`PATH` del usuario, deja el daemon arrancando con la sesión y queda registrado
en «Aplicaciones instaladas» con su desinstalador.

**Verifica cada motor descargable contra el SHA-256 que publicaron sus autores,
antes de extraerlo.** Los de Python (semgrep, squawk, ruff, mypy) llegan por
pip con las firmas de PyPI, y los de Go por `go install`.

> Abre una terminal nueva después de instalar: el `PATH` se hereda al arrancar
> el proceso.

### Enrolar un repositorio

Lo hace **una sola persona, una vez**. El resto del equipo queda enrolado con
un `git pull`.

```powershell
codeguard init
```

Detecta los lenguajes sobre los archivos que git ya rastrea, reconoce las
migraciones, propone las exclusiones del stack, escribe
`.codeguard/config.yaml`, instala los tres hooks y genera la baseline para que
lo preexistente no bloquee. **Nadie escribe YAML.**

Después, versiona `.codeguard/` y `.githooks/`. Quien haga `git pull` sólo
necesita `codeguard install` para activar los hooks en su copia.

---

## Comandos

| | |
|---|---|
| `init` | Enrola el repo: config + hooks + baseline + registro |
| `install` | Sólo los hooks, para quien recibe la config por `git pull` |
| `status --todos` | Verifica el enrolamiento de todos los repos de la máquina |
| `report` | Genera `.codeguard/HALLAZGOS.md` para un agente de codificación |
| `baseline` | Regenera la supresión de lo preexistente |
| `stats` | Precisión por regla según el feedback del equipo |
| `graph --deep` | Abre el explorador 3D del repo |
| `ci --base X` | Lo que corre en GitHub Actions, con salida SARIF |
| `engines` | Verifica la identidad de los motores y su contención |
| `repair` | Revisa y repara dependencias y rulepack |
| `config` | Configura el modelo (proveedor, endpoint, clave) |
| `rules suggest` · `forget` · `sync` · `version` | |

`git commit --no-verify` existe y no es hacer trampa: el commit pasa y
`post-commit` lo registra como *bypass*. Es una señal de producto, no un
castigo — un repositorio con muchos bypass está diciendo que alguna regla
molesta más de lo que ayuda.

---

## Si te bloquea un secreto

El gancho detiene el commit ahí mismo y avisa al agente: el orbe se pone en
rojo y el panel se abre con **el archivo y la línea** de cada secreto.

**El panel te dice dónde, nunca qué.** Viajan el repositorio, la rama, cuántos
secretos se frenaron y dónde están; nunca el hallazgo completo, que es el que
lleva la credencial dentro. No es una limitación técnica: un panel se comparte
por pantalla, y el valor ya lo tienes tú en tu editor.

> **Rota la credencial primero.** Borrarla del historial no la invalida.

Un secreto no se puede silenciar: no entra en la baseline y no baja a aviso por
el feedback del equipo.

---

## El modelo es opcional y se elige

La capa de consejo corre **después** de responderle al gancho, así que su
latencia nunca toca tu commit, y **jamás bloquea**.

Habla el dialecto de OpenAI y el de Anthropic, con preajustes para Azure AI
Foundry, OpenAI, Anthropic, OpenRouter, Groq, DeepSeek, Ollama y LM Studio. Los
dos últimos corren en la propia máquina: el código no sale de ahí.

La API key **nunca** se escribe en un archivo de CodeGuard — la configuración
guarda sólo el nombre de la variable de entorno que la contiene, y la clave vive
en el Administrador de credenciales de Windows.

---

## Contención

Los motores son binarios de terceros que corren sobre tu código en cada commit,
así que corren acotados:

- **Entorno por lista de permitidos**, no de prohibidos — una lista de
  prohibidos deja pasar el siguiente secreto que alguien añada. La clave del
  modelo no llega a ningún motor.
- **Token restringido** — sin privilegios salvo el de recorrer directorios.
- **Job object** — mueren con el plazo junto a todos sus hijos, con tope de
  memoria y de procesos, y sin acceso al portapapeles, al escritorio ni a
  ventanas ajenas.
- **Identidad verificada** — SHA-256 contra lo que publicaron sus autores.

Acota el proceso, el entorno y los privilegios; **no aísla el sistema de
archivos**: un motor accede a los archivos con los permisos de tu usuario.

El instalador todavía no está firmado. Mientras el certificado esté en trámite,
un EDR puede marcarlo como sospechoso — y con razón.

---

## Construir

```powershell
go build ./...
go test ./...
powershell -ExecutionPolicy Bypass -File tests\suite.ps1   # e2e, necesita el daemon vivo
```

Las pruebas que lanzan los linters **de verdad** necesitan proyectos de juguete
con las dependencias ya instaladas, y sin apuntarlas se saltan solas — si ves
`SKIP` en las de integración, es esto y no un test roto:

```powershell
$env:CODEGUARD_TOY_JS = "<dir con toy-eslint y toy-biome>"   # npm install hecho
$env:CODEGUARD_TOY_TS = "<proyecto con typescript>"
$env:CODEGUARD_TOY_PY = "<dir para el proyecto de mypy>"     # se prepara solo
```

Go 1.26 · Wails v3 · SQLite sin cgo · sin dependencias de red en tiempo de
análisis.

El **sitio de producto** vive en [`sitio/`](sitio/) — portada, demo animada y la
documentación completa:

```
cd sitio && npm install && npm run dev     # http://localhost:5175
```

---

## Estado

Funciona de punta a punta y se usa a diario en varios repositorios. Lo que
falta antes de repartirlo a un equipo grande está documentado sin adornos:
mayor cobertura de tests unitarios, un piloto con varios desarrolladores para
calibrar la tasa de falsos positivos, y un certificado de firma de código.

| | |
|---|---|
| Rule pack | 2026.08.2 — 130 reglas propias |
| Motores | 16 deterministas + la compuerta de secretos |
| Hook | ~5,2–5,6 s en un repo Go/SQL; 10,6 s cuando `tsc` compila el proyecto |
