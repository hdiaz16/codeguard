package daemon

import (
	"codeguard/internal/config"
	"codeguard/internal/engines"
	gvengine "codeguard/internal/engines/govulncheck"
	"codeguard/internal/engines/linters"
	sgengine "codeguard/internal/engines/semgrep"
	sqengine "codeguard/internal/engines/squawk"
	stengine "codeguard/internal/engines/staticcheck"
	tvengine "codeguard/internal/engines/trivy"
)

func Engines(cfg *config.Config, inCI bool, cache sgengine.Cache) []engines.Engine {
	var migGlobs []string
	var migDialecto string
	if cfg != nil {
		migGlobs = cfg.Paths.Migrations
		migDialecto = cfg.Paths.DialectoMigraciones()
	}
	return []engines.Engine{
		&sgengine.Engine{Cache: cache},
		&sqengine.Engine{MigrationGlobs: migGlobs, Dialect: migDialecto},
		// Política §7: CVE crítico advierte en local, bloquea en CI.
		&tvengine.Engine{BlockCritical: inCI, SkipDBUpdate: !inCI, Cache: cache},
		// Alcanzabilidad: trivy dice "el CVE está en tu go.sum"; govulncheck
		// demuestra si el código lo llama. Misma política local/CI que trivy,
		// y en el hook sólo corre cuando cambian las dependencias — recorre el
		// módulo entero y el presupuesto del hook no está para eso.
		&gvengine.Engine{BlockReachable: inCI, SoloManifiestos: !inCI, Cache: cache},
		// Semántica SSA sobre los paquetes tocados: bugs demostrables en el
		// flujo real de valores, no patrones de texto. Lint de severidad
		// error bloquea (§7), la misma política que govet.
		&stengine.Engine{Cache: cache},
		linters.GoFmt{Cache: cache},
		linters.GoVet{Cache: cache},
		linters.Gosec{Cache: cache},
		linters.Ruff{Cache: cache},
		linters.Bandit{Cache: cache},
		// Tipos en Python, la última casilla que le faltaba al lenguaje: ruff ve
		// formato y lint, nadie veía los tipos. Sólo aplica si el repo YA
		// configuró mypy (mypy.ini, [mypy] en setup.cfg o [tool.mypy] en
		// pyproject.toml), por la misma razón que eslint: imponer comprobación
		// de tipos a un equipo que no la eligió sería puro ruido. El caché es
		// por proyecto —mypy sigue los imports, no analiza archivos sueltos— y
		// lleva dentro qué archivos se le pasaron.
		linters.Mypy{Cache: cache},
		// tsc compila el proyecto entero por cambio de un archivo: sin caché,
		// cada informe de un monorepo con frontend pagaría la compilación.
		linters.Tsc{Cache: cache},
		// Formato y estilo de TS/JS, que hasta aquí no tenían NADA (tsc sólo ve
		// tipos). Corre el eslint o el biome que el repo ya configuró, con sus
		// reglas; si no configura ninguno no aplica, y el caché es por archivo
		// con la huella de esa config dentro de la clave.
		linters.ESLint{Cache: cache},
		linters.DotnetFormat{Cache: cache},
		// Compilación de C#: hasta aquí un `; expected` en un .cs llegaba entero
		// al CI, porque dotnet format sólo mira el formato. Compila el .csproj
		// tocado (nunca la solución) con --no-restore y -t:Rebuild, así que el
		// caché por huella de proyecto no es un lujo: es lo que evita pagar la
		// compilación en cada informe.
		linters.DotnetBuild{Cache: cache},
		// CVEs de NuGet, el hueco que trivy no cubre: sin packages.lock.json no
		// encuentra NADA en un .csproj (verificado). Misma política local/CI que
		// trivy y govulncheck, y en el hook sólo cuando cambian los manifiestos
		// — este comando sí restaura y sí va a la red.
		linters.DotnetVuln{BlockCritical: inCI, SoloManifiestos: !inCI, Cache: cache},
		// Formato de Java, que hasta aquí no tenía NADA: el lenguaje sólo contaba
		// con las reglas de la casa (semgrep) y las dependencias (trivy), así que
		// la discusión sobre dónde va la llave se pagaba entera en la revisión.
		// google-java-format sólo mira el fuente —no compila ni necesita
		// classpath—, que es lo que lo hace apto para el camino del commit.
		// Caché por archivo: el formateador no tiene configuración, así que el
		// mismo contenido da siempre el mismo veredicto.
		linters.JavaFmt{Cache: cache},
		// Calidad de Java sobre el AST, el govet/staticcheck del otro lado. PMD y
		// no SpotBugs porque SpotBugs analiza bytecode y exigiría compilar el
		// proyecto, que no cabe en el presupuesto del hook. Caché por archivo, no
		// por proyecto como tsc o dotnet-build: PMD evalúa cada archivo por su
		// cuenta, así que tocar 1 de 200 cuesta 1.
		linters.JavaLint{Cache: cache},
		// La cadena de CI como superficie de análisis (W7): actionlint valida los
		// workflows de GitHub Actions tocados —inyección de shell por expresiones,
		// permisos amplios, sintaxis—. Solo aplica si el cambio toca
		// .github/workflows/*.yml. Caché por archivo: cada workflow se valida por
		// su cuenta.
		linters.ActionLint{Cache: cache},
		// PowerShell como superficie (W7): PSScriptAnalyzer sobre los .ps1 tocados
		// —instaladores, automatización con privilegios—. Los errores (sintaxis,
		// bugs) bloquean; los avisos de estilo se dicen sin bloquear. Solo aplica
		// si el cambio toca .ps1; degrada a Ausente sin pwsh o sin el módulo.
		linters.PSAnalyzer{Cache: cache},
		// Shell como superficie (W7): shellcheck sobre los .sh/.bash tocados —bugs
		// de comillas y word-splitting que solo se notan con un path con espacios—.
		// Errores bloquean, avisos se dicen. Degrada a Ausente sin la herramienta.
		linters.ShellCheck{Cache: cache},
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
