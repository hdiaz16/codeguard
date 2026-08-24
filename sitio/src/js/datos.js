/* ══════════════════════════════════════════════════════════════════════════
   La fuente única de verdad del sitio.

   TODO lo que hay aquí sale del repositorio. Cada bloque lleva de dónde:

     · MOTORES        internal/daemon/daemon.go → Engines(), con los comentarios
                      que explican por qué está cada uno; y los Name() de
                      internal/engines/**.
     · ETAPAS         internal/pipeline/pipeline.go
     · ESTADOS        cmd/daemon/frontend/widget.html (WHISPERS y TITULOS)
     · CAPAS          internal/capas/capas.go
     · COMANDOS       cmd/codeguard/*.go (Use, Short, Long y las banderas)
     · COMPUERTAS     el bloque `gates` que escribe `codeguard init`
     · PRINCIPIOS     README.md

   Nada de esto se redactó "para que suene bien". Si una cifra no se pudo
   medir en el repo, no está.
   ══════════════════════════════════════════════════════════════════════════ */

/** Rulepack fijado hoy en la config que genera `codeguard init`. */
export const RULEPACK = "2026.08.3";

/**
 * Reglas propias del rulepack fijado. Contadas, no recordadas:
 *   rulepacks/2026.08.3/semgrep> awk '/^[[:space:]]*-[[:space:]]+id:/{n++} END{print n}' *.yaml
 * → 161
 */
export const REGLAS_PROPIAS = 161;

/* ── La compuerta de secretos: etapa 1, aparte de las demás ─────────────── */
export const SECRETOS = {
  id: "gitleaks",
  nombre: "gitleaks",
  pilar: "seguridad",
  etapa: "Etapa 1 — compuerta de secretos",
  lenguajes: ["todos"],
  mira: "Secretos en lo que está preparado para commitear. En el hook escanea el índice (--staged); en el CI, el historial del rango (--log-opts base..head).",
  bloquea: "Siempre, y es la única capa fail-closed: si no puede correr, el commit se detiene. Un análisis que no pudo mirar credenciales no puede decir que no hay ninguna.",
  porque:
    "Corre en el proceso del hook y offline, antes de que nada toque la red (P5). Sus hallazgos no admiten baseline ni degradación por feedback: un secreto viejo sigue siendo un secreto vivo.",
  origen: "lo instala CodeGuard · descarga verificada por SHA-256",
  cache: "sin caché — se mira siempre",
  destacado: true,
};

/* ── Los 19 motores de la etapa 2, en el orden en que los devuelve Engines() */
export const MOTORES = [
  {
    id: "semgrep",
    nombre: "semgrep",
    pilar: "seguridad",
    lenguajes: ["Go", "Python", "TS/JS", "C#", "Java"],
    mira: `El rulepack de la casa: ${REGLAS_PROPIAS} reglas propias fijadas en la versión ${RULEPACK} — inyección, deserialización insegura, JWT sin verificar, CORS abierto, SQL por concatenación, XSS, path traversal, SSRF.`,
    bloquea: "Las reglas de severidad ERROR bloquean; las de WARNING avisan. La compuerta es `semgrep_error: block`.",
    // Aquí NO se cuenta cómo se resuelve el rulepack ni qué pasaría si el
    // orden fuera otro. El agujero está cerrado, pero describir la mecánica
    // con la que se abría —y decir que está medida— es escribirle el guion a
    // quien venga a buscarla. Lo publicable es la garantía, no el forcejeo.
    porque:
      "Mandan siempre las reglas instaladas; el rulepack del repositorio se usa como respaldo, y cuando se usa, el análisis lo dice. Esa es la mitad de la paridad con el CI: mismas reglas, misma versión, mismo binario.",
    origen: "lo instala CodeGuard · pip",
    cache: "por archivo",
  },
  {
    id: "squawk",
    nombre: "squawk",
    pilar: "datos",
    lenguajes: ["SQL (PostgreSQL)"],
    mira: "Migraciones con riesgo de tirar producción: bloqueos de tabla, columnas NOT NULL sin default, índices sin CONCURRENTLY.",
    bloquea: "Sí — `migration_unsafe: block`. Sólo sobre los archivos que cubre `paths.migrations`.",
    porque:
      "Sólo corre si `paths.migrations_dialect` es postgres, porque squawk parsea PostgreSQL y nada más. Contra SQLite o MySQL no produce falsos positivos benignos: produce hallazgos BLOQUEANTES cuyo arreglo rompe el esquema. El caso que lo destapó fue el propio repo de CodeGuard, al que squawk exigía un CREATE INDEX CONCURRENTLY que en SQLite no existe.",
    origen: "lo instala CodeGuard · pip",
    cache: "sin caché",
  },
  {
    id: "trivy",
    nombre: "trivy",
    pilar: "seguridad",
    lenguajes: ["manifiestos y lockfiles"],
    mira: "Dependencias con CVE conocido, a partir de los manifiestos y lockfiles del repo.",
    bloquea: "Un CVE crítico AVISA en local y BLOQUEA en el CI (`cve_critical: warn_local_block_ci`).",
    porque:
      "En local no actualiza su base de datos: bajar la base de vulnerabilidades en mitad de un commit no cabe en el presupuesto del hook. En el CI sí.",
    origen: "lo instala CodeGuard · descarga verificada por SHA-256",
    cache: "por archivo",
  },
  {
    id: "govulncheck",
    nombre: "govulncheck",
    pilar: "seguridad",
    lenguajes: ["Go"],
    mira: "Vulnerabilidades de Go con alcanzabilidad: no si el CVE está en tu go.sum, sino si tu código llama al símbolo afectado.",
    bloquea: "Igual que trivy: avisa en local, bloquea en el CI.",
    porque:
      "trivy dice «el CVE está en tu go.sum»; govulncheck demuestra si el código lo llama. En el hook sólo corre cuando cambian las dependencias — recorre el módulo entero y el presupuesto del hook no está para eso.",
    origen: "lo instala CodeGuard · go install (se compila)",
    cache: "por proyecto",
  },
  {
    id: "staticcheck",
    nombre: "staticcheck",
    pilar: "calidad",
    lenguajes: ["Go"],
    mira: "Semántica SSA sobre los paquetes tocados: bugs demostrables en el flujo real de los valores, no patrones de texto.",
    bloquea: "El lint de severidad error bloquea, la misma política que go vet.",
    porque:
      "Es la diferencia entre buscar una forma en el texto y seguir el valor. Compila el módulo, así que su primera corrida en frío es la cara; después entra desde el caché.",
    origen: "lo instala CodeGuard · go install (se compila)",
    cache: "por proyecto",
  },
  {
    id: "gofmt",
    nombre: "gofmt",
    pilar: "calidad",
    lenguajes: ["Go"],
    mira: "Formato canónico de Go.",
    bloquea: "Sí — `format: block`. Es auto-corregible, así que el arreglo es un comando.",
    porque: "Aplica a cualquier cambio que toque un .go.",
    origen: "va DENTRO de CodeGuard · usa go/format, no el binario",
    cache: "por archivo",
  },
  {
    id: "govet",
    nombre: "go vet",
    pilar: "calidad",
    lenguajes: ["Go"],
    mira: "Los errores de alta certeza de Go: verbos de Printf que no casan, locks copiados, etiquetas de struct mal escritas.",
    bloquea: "Sí. Es la política de referencia: lo que vet marca, el CI también lo rechaza.",
    porque: "Alta certeza significa que casi no tiene falsos positivos, y por eso puede bloquear.",
    origen: "tu cadena de herramientas · tu instalación de Go",
    cache: "por archivo",
  },
  {
    id: "ruff",
    nombre: "ruff",
    pilar: "calidad",
    lenguajes: ["Python"],
    mira: "Formato y lint de Python.",
    bloquea: "Los errores reales (familias E4/E7/E9/F) bloquean; el resto avisa.",
    porque: "Aplica a cualquier cambio que toque un .py, sin pedirle configuración al repo.",
    origen: "lo instala CodeGuard · pip",
    cache: "por archivo",
  },
  {
    id: "mypy",
    nombre: "mypy",
    pilar: "calidad",
    lenguajes: ["Python"],
    mira: "Tipos en Python — la última casilla que le faltaba al lenguaje: ruff ve formato y lint, y nadie veía los tipos.",
    bloquea: "Sí, cuando aplica.",
    porque:
      "Sólo aplica si el repo YA configuró mypy (mypy.ini, [mypy] en setup.cfg o [tool.mypy] en pyproject.toml). Imponer comprobación de tipos a un equipo que no la eligió sería puro ruido.",
    origen: "lo instala CodeGuard · pip",
    cache: "por proyecto — mypy sigue los imports, no analiza archivos sueltos",
  },
  {
    id: "tsc",
    nombre: "tsc",
    pilar: "calidad",
    lenguajes: ["TypeScript"],
    mira: "Errores de tipos y de compilación de TypeScript.",
    bloquea: "Sí — `compile: block`.",
    porque:
      "Se usa el tsc DEL PROYECTO, y eso es lo que defiende la paridad: si CodeGuard trajera el suyo, un repo que compila con la 4.9 se analizaría aquí con la 5.9 y daría errores distintos a los del CI. Compila el proyecto entero por el cambio de un archivo, así que sin caché cada informe de un monorepo con frontend pagaría la compilación completa. Y si sale con error sin un solo diagnóstico, la capa se marca como no revisada: eso no es «está limpio», es «no compiló».",
    origen: "tu cadena de herramientas · el node_modules del repo",
    cache: "por proyecto",
  },
  {
    id: "eslint",
    nombre: "eslint · biome",
    pilar: "calidad",
    lenguajes: ["TS/JS"],
    mira: "Formato y estilo de TS/JS, que hasta aquí no tenían nada — tsc sólo ve tipos.",
    bloquea: "Sí, con las reglas del repo. Si el repo no configuró ninguna herramienta, la capa no aplica.",
    porque:
      "NO IMPONE ESTILO: corre el eslint o el biome que el repo YA configuró y aplica SUS reglas, no las nuestras. Hacer fallar un commit por una convención que el equipo no eligió convierte al agente en un obstáculo, y un obstáculo se desinstala. El hallazgo viaja con el nombre de la herramienta real para que el dev sepa quién le habla.",
    origen: "tu cadena de herramientas · el node_modules del repo",
    cache: "por archivo, con la huella de la configuración dentro de la clave",
  },
  {
    id: "dotnet-format",
    nombre: "dotnet format",
    pilar: "calidad",
    lenguajes: ["C#"],
    mira: "Formato y estilo de C#.",
    bloquea: "Sí — `format: block`.",
    porque: "Sólo mira el formato: la compilación es trabajo del motor siguiente.",
    origen: "tu cadena de herramientas · tu SDK de .NET",
    cache: "por archivo",
  },
  {
    id: "dotnet-build",
    nombre: "dotnet build",
    pilar: "calidad",
    lenguajes: ["C#"],
    mira: "Que el C# compile. Hasta que existió, un `; expected` en un .cs llegaba entero al CI.",
    bloquea: "Sí — `compile: block`.",
    porque:
      "Compila el .csproj tocado, nunca la solución, con --no-restore y -t:Rebuild. Por eso el caché por huella de proyecto no es un lujo: es lo que evita pagar la compilación en cada informe.",
    origen: "tu cadena de herramientas · tu SDK de .NET",
    cache: "por proyecto",
  },
  {
    id: "dotnet-vuln",
    nombre: "dotnet list package --vulnerable",
    pilar: "seguridad",
    lenguajes: ["C#"],
    mira: "CVEs de paquetes NuGet, el hueco que trivy no cubre.",
    bloquea: "Crítico avisa en local y bloquea en el CI, igual que trivy y govulncheck.",
    porque:
      "Sin packages.lock.json, trivy no encuentra NADA en un .csproj — verificado. En el hook sólo corre cuando cambian los manifiestos, porque este comando sí restaura y sí va a la red.",
    origen: "tu cadena de herramientas · tu SDK de .NET",
    cache: "por proyecto",
  },
  {
    id: "google-java-format",
    nombre: "google-java-format",
    pilar: "calidad",
    lenguajes: ["Java"],
    mira: "Formato de Java, que hasta aquí no tenía nada: el lenguaje sólo contaba con las reglas de la casa y las dependencias.",
    bloquea: "Sí — `format: block`.",
    porque:
      "Sólo mira el fuente: no compila ni necesita classpath, que es lo que lo hace apto para el camino del commit. La discusión sobre dónde va la llave se pagaba entera en la revisión.",
    origen: "lo instala CodeGuard · descarga verificada, si hay JDK",
    cache: "por archivo — el formateador no tiene configuración, así que el mismo contenido da siempre el mismo veredicto",
  },
  {
    id: "pmd",
    nombre: "PMD",
    pilar: "calidad",
    lenguajes: ["Java"],
    mira: "Calidad de Java sobre el AST: el go vet / staticcheck del otro lado.",
    bloquea: "Sí, con las reglas de severidad error.",
    porque:
      "PMD y no SpotBugs porque SpotBugs analiza bytecode y exigiría compilar el proyecto, que no cabe en el presupuesto del hook. Caché por archivo y no por proyecto: PMD evalúa cada archivo por su cuenta, así que tocar 1 de 200 cuesta 1.",
    origen: "lo instala CodeGuard · descarga verificada, si hay JDK",
    cache: "por archivo",
  },
  {
    id: "actionlint",
    nombre: "actionlint",
    pilar: "seguridad",
    lenguajes: ["GitHub Actions"],
    mira: "Workflows de GitHub Actions: inyección de shell por expresiones `${{ }}` sin comillas, permisos del GITHUB_TOKEN más amplios de lo necesario, sintaxis que sólo se ve al fallar el job.",
    bloquea: "Sus errores bloquean (§7): actionlint no hace nits de estilo, caza con alta certeza.",
    porque:
      "La cadena de CI es superficie de ataque real y hasta aquí nadie la miraba. Sólo aplica si el cambio toca .github/workflows/*.yml; sin la herramienta la capa queda ausente, no inventa un limpio.",
    origen: "descargable · go install (github.com/rhysd/actionlint)",
    cache: "por archivo",
  },
  {
    id: "psscriptanalyzer",
    nombre: "PSScriptAnalyzer",
    pilar: "calidad",
    lenguajes: ["PowerShell"],
    mira: "Scripts .ps1: bugs de sintaxis, credenciales en claro, prácticas peligrosas — instaladores y automatización con privilegios.",
    bloquea: "Los errores (sintaxis, bugs reales) bloquean; los avisos de estilo se dicen sin bloquear.",
    porque:
      "Sólo aplica si el cambio toca .ps1; necesita pwsh (o Windows PowerShell) y el módulo PSScriptAnalyzer, y sin ellos degrada a ausente. Se le pasan los objetivos sin interpolarlos como código: la ruta viaja como dato, jamás como comando.",
    origen: "tu PowerShell + módulo PSScriptAnalyzer",
    cache: "por archivo",
  },
  {
    id: "shellcheck",
    nombre: "shellcheck",
    pilar: "calidad",
    lenguajes: ["Shell (sh/bash)"],
    mira: "Scripts .sh/.bash: bugs de comillas y word-splitting que sólo muerden el día que un path lleva un espacio.",
    bloquea: "Sus errores bloquean; los avisos (SC2086 y demás, que shellcheck rankea info/warning) se dicen sin bloquear.",
    porque:
      "Sólo aplica si el cambio toca .sh/.bash; sin la herramienta degrada a ausente. Los .sh de despliegue, hooks y CI corren con privilegios y hasta aquí no los miraba nadie.",
    origen: "descargable · gestor del SO (p. ej. winget/apt/brew)",
    cache: "por archivo",
  },
];

/* ── Reglas que no miran el contenido de un archivo sino la FORMA del cambio.
      Corren siempre, sin motor externo y sin red (etapa 2b del pipeline). ── */
export const REGLAS_DE_FORMA = [
  {
    nombre: "lockfile desincronizado",
    que: "El manifiesto cambió y el lockfile no lo acompaña — o el proyecto no tiene lockfile.",
  },
  {
    nombre: "complejidad ciclomática",
    que: "Por función, a partir del umbral de `max_complexity` (15 por defecto). Nunca bloquea: partir una función es decisión de quien la escribe.",
  },
  {
    nombre: "tamaño del cambio",
    que: "Cambios por encima de lo revisable. Por encima de `max_diff_lines` (2000) el análisis degrada a sólo-secretos y lo dice.",
  },
];

/* ── Las etapas del embudo (internal/pipeline/pipeline.go) ──────────────── */
export const ETAPAS = [
  {
    n: "0",
    nombre: "Elegibilidad",
    resumen: "Decidir si hay algo que revisar.",
    detalle:
      "Se salta el análisis si el repo no está enrolado, si no hay diff, si es un merge o un revert, o si todos los archivos tocados están excluidos. El motivo viaja como texto hasta el hook, que lo usa para elegir el tono: una decisión de configuración del equipo no se anuncia igual que una avería.",
  },
  {
    n: "1",
    nombre: "Secretos",
    resumen: "La única compuerta fail-closed.",
    detalle:
      "gitleaks corre en el proceso del hook, offline, antes de que nada toque la red. Si no puede correr, el commit se detiene: es la única ruta de error que bloquea. Los secretos no se suprimen con la baseline ni se degradan por el feedback del equipo.",
  },
  {
    n: "2",
    nombre: "Deterministas",
    resumen: "Los 19 motores, en paralelo.",
    detalle:
      "Se decide QUIÉN va a mirar antes de lanzar a nadie, porque el denominador del progreso («3 de 9») tiene que existir desde el primer instante. Cada motor que termina publica su estado en vivo, desde su propia goroutine. Un motor que falla NO bloquea: degrada y se dice.",
  },
  {
    n: "2b",
    nombre: "Forma del cambio",
    resumen: "Lo que ningún motor externo mira.",
    detalle:
      "Lockfiles, tamaño del cambio y complejidad por función. No dependen de ningún binario de terceros ni de la red, así que corren siempre — incluso con el diff degradado a sólo-secretos.",
  },
  {
    n: "7",
    nombre: "Consolidación",
    resumen: "Un veredicto, explicado.",
    detalle:
      "Se deduplica por (archivo, línea, regla) y se ordena por severidad y luego por archivo y línea. Antes de eso se aplican la baseline (sólo lo nuevo bloquea) y la auto-calibración (una regla con exceso de falsos positivos en ESTE repo baja a aviso — gitleaks jamás). Si queda un bloqueante, el veredicto es BLOQUEADO.",
  },
];

/* ── Los seis estados del orbe. Textos literales de widget.html ─────────── */
export const ESTADOS = [
  {
    id: "idle",
    nombre: "De guardia",
    clima: "Niebla serena",
    susurro: "de guardia",
    titulo: "De guardia — cada commit pasa por aquí antes de entrar",
    cuando: "Sin trabajo.",
  },
  {
    id: "working",
    nombre: "Revisando",
    clima: "Ventisca brillante",
    susurro: "revisando tu cambio",
    titulo: "Revisando tu cambio",
    cuando: "Mientras corren las capas. La burbuja va diciendo cuántas llevan.",
  },
  {
    id: "pass",
    nombre: "Pasó",
    clima: "Verde salvia luminoso",
    susurro: "puedes seguir",
    titulo: "El commit pasó todas las compuertas",
    cuando: "Commit aprobado y completado. El verde y el commit son el mismo instante.",
  },
  {
    id: "blocked",
    nombre: "Bloqueado",
    clima: "Granito ferroso latiendo",
    susurro: "espera, hay algo",
    titulo: "Commit detenido — hay problemas que el CI también rechazaría",
    // Llega por dos caminos: el veredicto de las capas deterministas, y el
    // aviso de la compuerta de secretos —que corre en el proceso del gancho y
    // avisa con el repo, la rama, cuántos y dónde, nunca con el valor—.
    cuando: "El commit no existe. Persiste hasta que abras el panel.",
  },
  {
    id: "degraded",
    nombre: "Con un hueco",
    clima: "Piedra arenisca apagada",
    susurro: "hay un hueco en la revisión",
    titulo: "Hueco en la revisión — no todo se pudo mirar",
    cuando: "Alguna capa no corrió pudiendo hacerlo. Es lo único cierto en los tres caminos que llevan aquí.",
  },
  {
    id: "offline",
    nombre: "Sin modelo",
    clima: "Montaña dormida",
    susurro: "sin modelo, reglas al día",
    titulo: "Sin conexión al modelo — las reglas deterministas siguen aplicándose",
    cuando: "Sin daemon o sin red. Las compuertas no dependen del modelo.",
  },
];

/* ── El vocabulario de una capa (internal/capas/capas.go) ───────────────── */
export const ESTADOS_CAPA = [
  { id: "corrio", nombre: "corrió", que: "Miró. El número de hallazgos dice qué encontró, cero incluido." },
  { id: "no-aplica", nombre: "no aplica", que: "No había nada de su tipo en el cambio." },
  { id: "degradada", nombre: "degradada", que: "Tenía que mirar y no pudo." },
  { id: "ausente", nombre: "ausente", que: "No está instalado: configuración, no avería." },
];

/* ── Las compuertas, tal como las escribe `codeguard init` ──────────────── */
export const COMPUERTAS = [
  { clave: "secrets", valor: "block", que: "Secretos en el cambio. Fail-closed: si la compuerta no puede correr, bloquea." },
  { clave: "format", valor: "block", que: "gofmt, ruff, dotnet format, google-java-format, eslint/biome." },
  { clave: "compile", valor: "block", que: "tsc y dotnet build." },
  { clave: "lint_error", valor: "block", que: "go vet, staticcheck, ruff, mypy, PMD — severidad error." },
  { clave: "semgrep_error", valor: "block", que: "Las reglas de la casa con severidad ERROR." },
  { clave: "migration_unsafe", valor: "block", que: "squawk sobre las rutas de `paths.migrations`." },
  { clave: "cve_critical", valor: "warn_local_block_ci", que: "trivy, govulncheck y dotnet-vuln: avisan en tu máquina, bloquean en el CI." },
  { clave: "llm", valor: "never_block", que: "El modelo aconseja y jamás bloquea. No es configurable hacia arriba." },
];

/* ── Los comandos. Use / Short / banderas salen de cmd/codeguard/*.go ───── */
export const COMANDOS = [
  {
    id: "init",
    uso: "codeguard init",
    corto: "Enrola este repo: detecta lenguajes y genera .codeguard/config.yaml + hooks + baseline",
    grupo: "Enrolamiento",
    detalle:
      "Un solo comando hace el enrolamiento completo. Detecta los lenguajes sobre los archivos que git ya rastrea, reconoce las migraciones, propone las exclusiones que correspondan al stack (node_modules, obj/, *.designer.cs…), escribe la config, instala los tres hooks y genera la baseline para que lo preexistente no bloquee. Al terminar registra el proyecto, así que aparece en el panel sin esperar al primer commit.",
    banderas: [{ f: "--force", que: "regenerar aunque ya exista config" }],
    notas: [
      "Falla si el repo no tiene todavía ningún archivo de un lenguaje soportado: haz el primer commit y vuelve a correrlo.",
      "Si hay .sql que no reconoció como migraciones lo dice EN VOZ ALTA, porque si no la compuerta de migraciones queda apagada sin que nada lo anuncie.",
      "El dialecto de las migraciones siempre se escribe `postgres` y la detección sólo informa: acertar ahorra una línea de configuración, y errar apaga una capa entera en silencio.",
    ],
    despues: "Versiona `.codeguard/` y `.githooks/`: el resto del equipo queda enrolado con un `git pull`.",
  },
  {
    id: "install",
    uso: "codeguard install",
    corto: "Instala los hooks de CodeGuard en el repo actual (core.hooksPath)",
    grupo: "Enrolamiento",
    detalle:
      "Sólo los hooks. Es el comando de quien recibe la config por `git pull` y no necesita regenerar nada: `init` ya lo llama por dentro.",
    banderas: [],
  },
  {
    id: "status",
    uso: "codeguard status [--todos]",
    corto: "Verifica el enrolamiento: config, hooks, baseline, rulepack y paridad",
    grupo: "Enrolamiento",
    detalle:
      "Revisa punto por punto que el repo esté de verdad enrolado y, cuando algo falta, imprime el comando que lo arregla. Con `--todos` recorre cada proyecto registrado en la máquina.",
    banderas: [{ f: "--todos", que: "revisar todos los proyectos registrados en esta máquina" }],
  },
  {
    id: "forget",
    uso: "codeguard forget [ruta]",
    corto: "Quita un proyecto de la lista del agente (no toca el repo)",
    grupo: "Enrolamiento",
    detalle:
      "Deja de mostrar un proyecto en el panel y en el explorador. No desinstala nada ni toca el repositorio: los hooks siguen donde estén. Para desenrolarlo del todo hace falta `git config --unset core.hooksPath` y borrar `.githooks/` y `.codeguard/`. Un proyecto cuya carpeta ya no existe se olvida solo; esto es para los que siguen en disco.",
    banderas: [],
  },
  {
    id: "report",
    uso: "codeguard report [--avisos] [--deuda]",
    corto: "Genera .codeguard/HALLAZGOS.md para que un agente de código los resuelva",
    grupo: "Trabajo diario",
    detalle:
      "Escanea el repo completo y escribe un informe con instrucciones precisas, pensado para entregárselo a un agente de codificación. Lo importante es que es re-ejecutable: al volver a correrlo marca como RESUELTOS los que ya no aparecen. Y no declara terminado lo que no revisó — `COMPLETADO` exige que no queden bloqueantes y que todas las capas hayan corrido; si no, dice `PARCIAL` con qué faltó.",
    banderas: [
      { f: "--avisos", que: "incluir también los hallazgos no bloqueantes" },
      { f: "--deuda", que: "detallar la deuda aceptada por la baseline (hallada pero suprimida)" },
    ],
  },
  {
    id: "baseline",
    uso: "codeguard baseline",
    corto: "Escanea el repo completo y suprime los hallazgos preexistentes (solo lo nuevo bloqueará)",
    grupo: "Trabajo diario",
    detalle:
      "Enrolar un repo con años encima no puede significar arreglarlo entero antes del próximo commit. La baseline guarda la huella de lo que ya existía para que no bloquee, y a partir de ahí sólo lo nuevo cuenta. Los secretos nunca entran en la baseline.",
    banderas: [],
  },
  {
    id: "stats",
    uso: "codeguard stats [--all]",
    corto: "Precisión por regla según el feedback del equipo (la palanca de calibración)",
    grupo: "Trabajo diario",
    detalle:
      "Cada hallazgo del panel tiene un botón de útil y otro de falso positivo. Esto es lo que se hace con esos votos: la precisión regla por regla. Es también la entrada de la auto-calibración — una regla con suficientes votos y demasiados falsos positivos en un repo baja sola a aviso.",
    banderas: [{ f: "--all", que: "agregar el feedback de todos los repos" }],
  },
  {
    id: "graph",
    uso: "codeguard graph [--deep] [--out RUTA]",
    corto: "Grafo del repo: --deep abre el explorador interactivo a nivel de función",
    grupo: "Trabajo diario",
    detalle:
      "Sin banderas escribe el grafo del repositorio. Con `--deep` abre el explorador interactivo a nivel de función: quién llama a quién, qué consulta sale de dónde y dónde cayeron los hallazgos del último análisis. Corre local, sin navegador.",
    banderas: [
      { f: "--deep", que: "explorador interactivo a nivel de función (WebGL)" },
      { f: "--out RUTA", que: "ruta de salida (por defecto docs/obsidian/ o docs/)" },
    ],
  },
  {
    id: "rules",
    uso: "codeguard rules suggest",
    corto: "Propone reglas Semgrep a partir de las convenciones escritas del repo (CLAUDE.md...)",
    grupo: "Trabajo diario",
    detalle:
      "Lee las convenciones que el repo ya tiene escritas y propone reglas que las hagan cumplir. La propuesta es una propuesta: la revisión humana es obligatoria antes de que ninguna regla entre al rulepack.",
    banderas: [],
  },
  {
    id: "ci",
    uso: "codeguard ci --base COMMIT [--head HEAD]",
    corto: "Analiza el rango base..head (modo CI / sombra)",
    grupo: "Integración continua",
    detalle:
      "El mismo binario que corre en tu máquina, con el mismo rulepack. De ahí sale la paridad: no es una promesa, es que es el mismo programa. Sale con código 1 si hay bloqueantes, y puede escribir SARIF para la pestaña de seguridad de GitHub.",
    banderas: [
      { f: "--base COMMIT", que: "commit base (requerido)" },
      { f: "--head COMMIT", que: "commit head (por defecto HEAD)" },
      { f: "--format sarif", que: "formato de salida" },
      { f: "--out ARCHIVO", que: "archivo de salida" },
      { f: "--repo DIR", que: "directorio dentro del repo (por defecto .)" },
      { f: "--shadow", que: "modo sombra: registra pero nunca falla el job" },
    ],
    notas: [
      "En el CI la compuerta de secretos escanea el HISTORIAL del rango, no el diff de árboles: un secreto añadido en un commit y borrado en el siguiente sigue en el historial, y eso es exactamente contra lo que existe un escáner por historial.",
      "Los CVE críticos, que en local avisan, aquí bloquean.",
    ],
  },
  {
    id: "engines",
    uso: "codeguard engines [--auditar]",
    corto: "Verifica que los motores instalados sean los que publicaron sus autores",
    grupo: "Mantenimiento",
    detalle:
      "Compara el SHA-256 de cada motor descargable contra los hashes publicados por sus autores en los checksums de cada release. Los motores de Python (semgrep, squawk, ruff, mypy) no aparecen: los instala pip contra PyPI con sus propias firmas, no los distribuimos nosotros.",
    banderas: [{ f: "--auditar", que: "escanea con trivy los motores que repartimos y falla si hay crítico o alto sin aceptar" }],
  },
  {
    id: "repair",
    uso: "codeguard repair",
    corto: "Verifica y repara las dependencias del agente (gitleaks, semgrep...)",
    grupo: "Mantenimiento",
    detalle:
      "El comando al que te manda el hook cuando una compuerta no pudo correr. Revisa qué motores faltan o están rotos y los repone.",
    banderas: [],
  },
  {
    id: "doctor",
    uso: "codeguard doctor [--json] [--global]",
    corto: "Verifica las postcondiciones reales: repo, daemon y base de datos (sólo observa, no repara)",
    grupo: "Mantenimiento",
    detalle:
      "Observa las verdades del enrolamiento (config, hooks, baseline, rulepack), el daemon por el pipe con su versión, y el esquema de la base sin migrarla. Y escala la degradación crónica: una capa que lleva varias corridas seguidas sin cubrir del todo se marca recurrente (2) o persistente (5, o 2 durante más de 24 h), siempre con el contador y desde cuándo — no sólo un color.",
    banderas: [
      { f: "--json", que: "salida JSON versionada (para el instalador y la flota)" },
      { f: "--global", que: "sólo la máquina (daemon, BD); omite los chequeos de repo" },
    ],
  },
  {
    id: "confiar",
    uso: "codeguard confiar [--si] [--revocar]",
    corto: "Confía en la configuración ejecutable de este repo (eslint.config.js, targets de MSBuild, plugins de mypy)",
    grupo: "Mantenimiento",
    detalle:
      "Algunos motores ejecutan configuración o binarios DEL REPOSITORIO —eslint.config.js, un target de MSBuild, un plugin de mypy—. Ejecutar código no confiado del repo es un hueco real (se midió: alcanza fuera del árbol), así que por defecto esos motores NO corren hasta que confías en el repo una vez. El default es seguro; confiar es un opt-in explícito, atado al repo y su huella, guardado fuera del repositorio.",
    banderas: [
      { f: "--si, -y", que: "confiar sin la confirmación interactiva" },
      { f: "--revocar", que: "retirar la confianza de este repo" },
    ],
  },
  {
    id: "lock",
    uso: "codeguard lock [--update]",
    corto: "Genera o valida .codeguard.lock: la prueba de que tu máquina y el CI analizarían igual",
    grupo: "Integración continua",
    detalle:
      "Una foto de las entradas que DECIDEN el veredicto: versión de codeguard, rulepack (nombre + digest del árbol), config, baseline y fórmula de riesgo. Si tu entorno no corresponde a lo que el repo fijó, el análisis no tendría paridad. El CI rechaza ese desajuste ANTES de analizar; el gancho local sólo lo declara —bloquear al dev por una foto de coherencia le enseñaría el reflejo --no-verify—. Regenerar sin cambios da bytes idénticos, así que `--update` no ensucia el diff.",
    banderas: [{ f: "--update", que: "(re)genera y escribe el lock en vez de validarlo" }],
  },
  {
    id: "config",
    uso: "codeguard config [--ver] [--probar]",
    corto: "Abre la configuración del modelo que aconseja",
    grupo: "Mantenimiento",
    detalle:
      "El modelo aconseja y nunca bloquea, así que cambiarlo no altera qué reglas se aplican ni la paridad con el CI. Tu elección se guarda fuera del repositorio: no viaja en ningún commit ni cambia la configuración del equipo.",
    banderas: [
      { f: "--ver", que: "mostrar la configuración actual en la terminal" },
      { f: "--probar", que: "hacer una llamada real al modelo configurado" },
      { f: "--guardar-clave VAR", que: "guarda en el Administrador de credenciales la clave que se lea por la entrada estándar" },
    ],
  },
  {
    id: "sync",
    uso: "codeguard sync",
    corto: "Empuja la telemetría local al Postgres central (precisión y bypass a nivel organización)",
    grupo: "Mantenimiento",
    detalle: "Para equipos que quieren ver la precisión y los bypass agregados de toda la organización, no sólo de una máquina.",
    banderas: [],
  },
  {
    id: "daemon",
    uso: "codeguard daemon",
    corto: "Arranca el daemon (servidor del pipe)",
    grupo: "Mantenimiento",
    detalle: "Normalmente no hace falta: el instalador lo deja arrancando con la sesión.",
    banderas: [],
  },
  {
    id: "hook",
    uso: "codeguard hook pre-commit | prepare-commit-msg | post-commit",
    corto: "Puntos de entrada de los hooks de git (los invocan los shims de .githooks)",
    grupo: "Mantenimiento",
    detalle:
      "No se llaman a mano. `pre-commit` es el que revisa; `prepare-commit-msg` sella el trailer Codeguard-Run-Id en el mensaje; `post-commit` registra el commit, incluido el que pasó con `--no-verify`.",
    banderas: [],
  },
  {
    id: "version",
    uso: "codeguard version",
    corto: "Versión del binario",
    grupo: "Mantenimiento",
    detalle: "Un `dev` aquí delata un binario compilado a mano en vez del instalado.",
    banderas: [],
  },
];

/* ── Los cinco principios, literales del README ─────────────────────────── */
export const PRINCIPIOS = [
  { id: "P1", texto: "Sólo lo determinista bloquea. Lo que bloquea aquí, bloquea en el CI." },
  { id: "P2", texto: "El modelo aconseja y jamás bloquea." },
  { id: "P3", texto: "El veredicto se explica: regla, archivo, línea, por qué importa y qué hacer." },
  { id: "P4", texto: "El agente no secuestra el trabajo. Si algo falla, degrada y avisa; no impide commitear." },
  { id: "P5", texto: "Nada que parezca una credencial sale a la red. La redacción ocurre antes de cualquier llamada." },
];

/** Los veinte nombres, para la lista de "esto te vigila". */
export const NOMBRES_MOTORES = [SECRETOS, ...MOTORES].map((m) => m.nombre);

/* ── El cambio que reconstruye la demo ───────────────────────────────────
   Se escribe aquí, y no suelto en la demo, porque la lista de capas tiene
   que ser CIERTA para estos archivos. Un cambio de TypeScript y SQL no
   enciende gofmt ni mypy, y enseñar diecinueve capas corriendo sobre él sería
   exactamente la clase de adorno que este producto existe para no hacer.

   El repositorio es INVENTADO, y tiene que serlo: un sitio público no nombra
   los repositorios de nadie, ni siquiera de casa. Los archivos son los
   mínimos que justifican cada capa que se enciende.

   Archivos tocados:
     .github/workflows/ci.yml
     package.json
     src/api.ts
     db/migrations/0007_sesiones.sql

   No lleva duración: el ejemplo del README trae un tiempo etiquetado para SU
   corrida, y reutilizarlo aquí —y encima para dos cargas de trabajo distintas
   dentro del mismo sitio— sería decoración con forma de medida.            */
export const DEMO = {
  repo: "ejemplo-web",
  rama: "main",
  archivos: 4,
  // Las capas que SÍ aplican, y por qué cada una:
  //   semgrep    → hay TypeScript
  //   tsc        → el cambio toca un proyecto con tsconfig
  //   eslint     → el repo ya tiene eslint configurado
  //   trivy      → package.json es un manifiesto
  //   squawk     → hay una migración bajo paths.migrations
  //   actionlint → el cambio toca .github/workflows/ci.yml
  aplican: ["semgrep", "tsc", "eslint", "trivy", "squawk", "actionlint"],
  // Las trece restantes de las diecinueve: no hay Go, Python, C#, Java,
  // PowerShell ni shell aquí.
  noAplican: 13,
  motivoNoAplican: "no hay Go, Python, C#, Java, PowerShell ni shell en este cambio",
};
