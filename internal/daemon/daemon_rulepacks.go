package daemon

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// RulepackDir resuelve el rulepack pinneado, en orden: vendoreado en el repo,
// junto al binario, un nivel arriba del binario, y la instalación estándar del
// usuario.
//
// Los dos últimos no son "por si acaso". El binario instalado vive en
// CodeGuard\bin y los rulepacks se copian ahí y también un nivel arriba; pero
// cualquier binario que NO sea el instalado —una compilación de desarrollo, una
// copia portable— no tiene rulepacks al lado, y entonces todo repo que no los
// vendoree pierde las 119 reglas de la casa EN SILENCIO. Se reprodujo en un
// repo de prueba: semgrep "corrió" en 0 ms con 0 hallazgos y la baseline se
// escribió sin cobertura de reglas. La instalación estándar es el último
// recurso porque siempre está donde está, sin importar quién arrancó el proceso.
// El del repo va el ÚLTIMO, y esto es una decisión de seguridad, no de orden.
//
// Iba primero, y con eso el repo ANALIZADO decidía qué reglas se le aplicaban:
// bastaba traer un `rulepacks/<la version que pinnea>/` con reglas de relleno
// para que las de la casa no llegaran a mirar el código. Medido: el mismo
// archivo con una inyección SQL de manual sale BLOQUEADO con el rulepack
// instalado y "formato/lint/tipos/reglas/migraciones ✓  listo — commit
// permitido" con el del repo. Sin carrera y sin atacante sofisticado: basta
// clonar el repositorio.
//
// El vendoreado sigue existiendo porque resuelve un fallo real —un binario que
// no es el instalado no tiene rulepacks al lado, y sin esto cada repo perdería
// las 119 reglas EN SILENCIO—, pero como RESPALDO: se usa cuando la versión no
// está instalada, que es el caso que lo justificó. Si están las dos, el mismo
// número nombrando dos artefactos distintos es una colisión, y en una colisión
// gana el de la organización: la versión es una promesa de paridad con el CI.
//
// Un equipo que de verdad necesite reglas propias las publica con SU número de
// versión; lo que no puede es reutilizar el de la casa para otra cosa.
func RulepackDir(repoRoot, version string) string {
	local := filepath.Join(repoRoot, "rulepacks", version)
	var candidatos []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidatos = append(candidatos,
			filepath.Join(dir, "rulepacks", version),
			filepath.Join(filepath.Dir(dir), "rulepacks", version))
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		candidatos = append(candidatos, filepath.Join(base, "CodeGuard", "rulepacks", version))
	}
	candidatos = append(candidatos, local)
	for _, c := range candidatos {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Ninguno existe: se devuelve la ruta del repo para que el mensaje de error
	// hable del sitio donde el dev PODRÍA vendorearlo.
	return local
}

// RulepackEsDelRepo dice si las reglas que se van a aplicar salen del repo
// analizado en vez de las instaladas.
//
// Existe para poder DECIRLO. El hook ya avisaba a gritos cuando el rulepack
// falta ("las reglas de la casa NO se aplicaron"), y callaba cuando lo
// sustituyen — que es peor, porque no deja rastro: el veredicto sale con su ✓ y
// nadie sabe qué reglas corrieron.
func RulepackEsDelRepo(repoRoot, version string) bool {
	return RulepackDir(repoRoot, version) == filepath.Join(repoRoot, "rulepacks", version)
}

// RulepacksInstalados lista las versiones disponibles junto al binario y
// vendoreadas en el repo, ordenadas de más nueva a más vieja. Los nombres son
// fechas (2026.08.2), así que el orden lexicográfico inverso basta salvo por
// el número final: se compara por partes para que .10 no quede antes que .9.
func RulepacksInstalados(repoRoot string) []string {
	vistos := map[string]bool{}
	var out []string
	// Los mismos sitios que mira RulepackDir, para que "instaladas: ..." no
	// contradiga a la resolución.
	dirs := []string{filepath.Join(repoRoot, "rulepacks")}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		dirs = append(dirs, filepath.Join(dir, "rulepacks"), filepath.Join(filepath.Dir(dir), "rulepacks"))
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		dirs = append(dirs, filepath.Join(base, "CodeGuard", "rulepacks"))
	}
	for _, d := range dirs {
		entradas, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entradas {
			if e.IsDir() && !vistos[e.Name()] {
				vistos[e.Name()] = true
				out = append(out, e.Name())
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return masNuevo(out[i], out[j]) })
	return out
}

func masNuevo(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			if na != nb {
				return na > nb
			}
			continue
		}
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return len(pa) > len(pb)
}

