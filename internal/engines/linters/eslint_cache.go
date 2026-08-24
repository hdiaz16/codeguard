package linters

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

func claveDeArchivo(tool herramienta, huellaConfig, shaArchivo string) string {
	return string(tool) + ":" + huellaConfig + ":" + shaArchivo
}

// huellaConfigJS resume la configuración de lint que gobierna un proyecto.
//
// Incluye los manifiestos de linter y TAMBIÉN package.json y los lockfiles, y
// eso es deliberado: en eslint las reglas no viven en el archivo de config sino
// en los plugins que éste extiende (eslint-config-airbnb,
// @typescript-eslint/...). Subir la versión de un plugin cambia los hallazgos
// con el .eslintrc intacto, y el lockfile es la única señal de ese cambio que
// se puede leer sin resolver node_modules entero.
//
// Punto ciego asumido, el mismo que tsc.go: el estado real de node_modules más
// allá del lockfile no se comprueba, y una config compartida que se importe
// desde FUERA del directorio del proyecto queda fuera de la huella. Devuelve
// vacío —no cacheable— si el repo no se puede enumerar, que es lo que pasa en
// los tests con t.TempDir y está bien: sin caché se analiza de nuevo.
func huellaConfigJS(repoRoot, dir string) string {
	return engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
			"npm-shrinkwrap.json", "bun.lock", "bun.lockb", ".eslintignore":
			return true
		}
		for _, n := range configsBiome {
			if base == n {
				return true
			}
		}
		return strings.HasPrefix(base, "eslint.config.") || strings.HasPrefix(base, ".eslintrc")
	})
}

// enProyecto pasa una ruta relativa al repo a relativa al directorio del
// proyecto, que es el cwd con el que se invoca la herramienta.
func enProyecto(dir, rel string) string {
	if dir == "." || dir == "" {
		return rel
	}
	return strings.TrimPrefix(rel, strings.TrimSuffix(dir, "/")+"/")
}

// cacheDeArchivosJS atribuye los hallazgos nuevos a su archivo y devuelve
// clave → hallazgos. Los archivos analizados sin hallazgos entran con lista
// vacía: "analizado y limpio" es el resultado que más veces se reutiliza.
func cacheDeArchivosJS(fs []finding.Finding, analizados []objetivoJS, repoRoot string) []engines.Cacheable {
	clavePorRel := make(map[string]string, len(analizados))
	porClave := make(map[string][]finding.Finding, len(analizados))
	relsPorClave := make(map[string][]string, len(analizados))
	shaPorClave := make(map[string]string, len(analizados))
	var orden []string
	for _, o := range analizados {
		if o.clave == "" {
			continue
		}
		clavePorRel[o.rel] = o.clave
		// La clave no lleva ruta: contenido idéntico la comparte, así que la
		// vigencia (bug #8) cubre TODAS las rutas que la produjeron.
		relsPorClave[o.clave] = append(relsPorClave[o.clave], o.rel)
		if _, ya := porClave[o.clave]; !ya {
			orden = append(orden, o.clave)
			porClave[o.clave] = []finding.Finding{}
			shaPorClave[o.clave] = o.sha
		}
	}
	for _, f := range fs {
		if clave, ok := clavePorRel[f.File]; ok {
			porClave[clave] = append(porClave[clave], f)
		}
	}
	out := make([]engines.Cacheable, 0, len(orden))
	for _, clave := range orden {
		out = append(out, engines.Cacheable{
			Clave:    clave,
			Vigente:  engines.VigenciaDeArchivos(repoRoot, relsPorClave[clave], shaPorClave[clave]),
			Findings: porClave[clave],
		})
	}
	return out
}

// lotesDeRutas reparte las rutas en grupos que caben en el límite. Una ruta que
// por sí sola lo excediera va en su propio lote: recortarla dejaría un archivo
// sin analizar en silencio, que es justo lo que el troceado evita.
func lotesDeRutas(rutas []string, limite int) [][]string {
	var out [][]string
	actual := []string{}
	largo := 0
	for _, r := range rutas {
		coste := len(r) + 3 // +3: el espacio separador y las comillas del shell
		if len(actual) > 0 && largo+coste > limite {
			out = append(out, actual)
			actual, largo = []string{}, 0
		}
		actual = append(actual, r)
		largo += coste
	}
	if len(actual) > 0 {
		out = append(out, actual)
	}
	return out
}

// binarioJS resuelve el ejecutable de la herramienta: primero el del propio
// proyecto, que es el que usa el CI y el que fija la versión; si no está, npx
// con --no-install para que NUNCA descargue nada a mitad de un pre-commit.
//
// En Windows los binarios de npm son .cmd, no .exe. Con workspaces el
// node_modules suele estar hoisted a la raíz del monorepo y no junto al
// manifiesto: ahí falla el lookup local y entra npx, que sí resuelve subiendo.
func binarioJS(absProyecto string, tool herramienta) (string, []string) {
	sufijo := ""
	npx := "npx"
	if runtime.GOOS == "windows" {
		sufijo = ".cmd"
		npx = "npx.cmd"
	}
	if st, err := os.Stat(filepath.Join(absProyecto, "node_modules", ".bin", string(tool)+sufijo)); err == nil && !st.IsDir() {
		return filepath.Join(absProyecto, "node_modules", ".bin", string(tool)+sufijo), nil
	}
	paquete := "eslint"
	if tool == hBiome {
		paquete = "@biomejs/biome" // el paquete no se llama como su binario
	}
	return npx, []string{"--no-install", paquete}
}

// ── comunes ─────────────────────────────────────────────────────────────────

// rutaRepoJS normaliza la ruta que reportó la herramienta a "relativa al repo
// con separador /".
//
// Hay que aceptar las dos formas porque las dos herramientas no coinciden:
// eslint devuelve rutas ABSOLUTAS con barra invertida de Windows, y biome las
// devuelve relativas a su cwd —también con barra invertida, aunque se le pasen
// con barra normal—. Y biome mezcla: en sus internalError sí manda la absoluta.
//
// Las barras invertidas se normalizan a mano y no con filepath porque los
// payloads son de Windows: así el parseo da el mismo resultado en cualquier
// plataforma donde se compile el repo, y las pruebas que usan capturas reales
// no dependen de dónde corran.
func rutaRepoJS(repoRoot, dir, p string) string {
	if p == "" {
		return ""
	}
	limpia := strings.ReplaceAll(p, `\`, "/")
	if esAbsolutaJS(limpia) {
		// relTo comprueba que el resultado caiga DENTRO de la raíz y reintenta
		// con la raíz canónica si no. Antes se usaba filepath.Rel a secas, y
		// Rel "tiene éxito" devolviendo `../../..` cuando las dos rutas son del
		// mismo disco pero apuntan a sitios distintos — el hallazgo salía con
		// una ruta que ningún editor abre, que no casa con la baseline y que no
		// coincide con ningún archivo del diff: desaparecía en silencio.
		return relTo(repoRoot, filepath.FromSlash(limpia))
	}
	if dir != "." && dir != "" {
		return path.Join(dir, limpia)
	}
	return limpia
}

// esAbsolutaJS reconoce la forma de Windows (C:/…) y la de POSIX sin preguntarle
// al sistema operativo, por el motivo de arriba.
func esAbsolutaJS(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/'
}

// comandoJS arma la orden que el dev debe teclear. Cuando el proyecto no está
// en la raíz hay que decir desde dónde: `npx eslint` ejecutado en la raíz de un
// monorepo usa otro eslint (u ninguno) y otra config.
func comandoJS(dir, orden, enPry string) string {
	if dir == "." || dir == "" {
		return "`" + orden + " " + enPry + "`"
	}
	return "`" + orden + " " + enPry + "` desde " + dir + "/"
}

// maxLinea garantiza una línea válida. biome manda 0 en los diagnósticos que
// son del archivo entero (el de formato) y un 0 en el informe se lee como
// "sin ubicación", que rompe la navegación del editor.
func maxLinea(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
