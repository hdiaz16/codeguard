// Package engines define la interfaz común de los adaptadores de escáneres
// (sección 18: un adaptador por herramienta).
package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

type Input struct {
	RepoRoot     string
	Files        []gitdiff.ChangedFile
	RulepackDir  string // raíz del rulepack pinneado (rulepacks/<ver>)
	MigrationsGl []string
}

// Engine es un escáner determinista. Run devuelve hallazgos; un error de
// ejecución NO bloquea (sección 14) — el orquestador lo registra como capa
// degradada. La única excepción es la compuerta de secretos (fail-closed),
// que el orquestador trata aparte.
type Engine interface {
	Name() string
	// Applies decide si el engine corre para este conjunto de archivos.
	Applies(in Input) bool
	Run(ctx context.Context, in Input) ([]finding.Finding, error)
}

// Cache es el caché de resultados deterministas (§9, tabla file_cache): una
// clave de contenido → los hallazgos de ESE contenido con este rulepack y
// esta config. La clave es opaca para el caché: el motor de archivos usa el
// sha del archivo; los motores de módulo (staticcheck, govulncheck) usan la
// huella agregada del módulo con su prefijo. Nil = sin caché, todo se
// analiza. Ambas operaciones son best-effort: un caché caído degrada a
// "analizar de nuevo", nunca a error.
type Cache interface {
	// Leer devuelve, de las claves dadas, las que tienen resultado guardado.
	Leer(claves []string) map[string][]finding.Finding
	// Guardar persiste hallazgos por clave; la lista vacía también cuenta —
	// "analizado y limpio" es el resultado que más veces se reutiliza.
	Guardar(porClave map[string][]finding.Finding)
}

// HuellaModulo resume el contenido de un módulo en una sola huella: los
// archivos RASTREADOS del directorio dado que pasen el filtro, con su sha de
// contenido del árbol de trabajo. Es la clave de caché de los motores que
// analizan el módulo entero: módulo sin cambios = mismos hallazgos.
//
// Punto ciego asumido: los archivos sin rastrear no entran en la huella
// aunque el compilador los vea — el mismo punto ciego que ya tiene el
// informe, que solo alimenta archivos rastreados. Devuelve vacío (no
// cacheable) si el módulo no se puede enumerar.
func HuellaModulo(repoRoot, dir string, filtro func(rel string) bool) string {
	return LeerHuellasRepo(repoRoot).Modulo(dir, filtro)
}

// HuellasRepo es el recorrido del repo hecho UNA vez, para quien necesita varias
// huellas en la misma corrida.
//
// Existe por dotnetbuild: pedía una huella por cada .csproj tocado y cada
// llamada pagaba un `git ls-files` del repo entero, más el re-hash de los
// archivos compartidos por varios proyectos (el caso típico de un Core.csproj
// referenciado por todos). En un monorepo eso se come una parte real del
// presupuesto del gancho, que es un pre-commit con el dev esperando.
//
// La alternativa era que el llamador replicara el formato de la huella para
// derivarla él; se descartó porque dos copias del mismo formato divergen, y aquí
// divergir significa que una clave de caché deja de corresponder a su contenido.
// Así el formato vive en un solo sitio —Modulo— y lo que se comparte es el
// trabajo.
//
// Los shas se calculan PEREZOSAMENTE y se memorizan: una sola huella cuesta
// exactamente lo que costaba (sólo se hashea lo que pasa el filtro), y varias
// comparten tanto el listado como los archivos que tengan en común.
//
// No es seguro usarlo desde varias goroutines: el memo no lleva candado porque
// el único consumidor recorre sus proyectos en serie.
type HuellasRepo struct {
	repoRoot   string
	rutas      []string
	shas       map[string]string
	enumerable bool
}

// LeerHuellasRepo enumera los archivos rastreados. Si el repo no se puede
// enumerar, las huellas que salgan de aquí serán vacías — o sea "no cacheable",
// el mismo criterio que tenía HuellaModulo.
func LeerHuellasRepo(repoRoot string) *HuellasRepo {
	rutas, err := gitdiff.Rastreados(repoRoot)
	return &HuellasRepo{
		repoRoot:   repoRoot,
		rutas:      rutas,
		shas:       make(map[string]string, len(rutas)),
		enumerable: err == nil && len(rutas) > 0,
	}
}

func (h *HuellasRepo) sha(rel string) string {
	if s, ok := h.shas[rel]; ok {
		return s
	}
	s := gitdiff.SHA256De(h.repoRoot, rel)
	h.shas[rel] = s
	return s
}

// Modulo es HuellaModulo sobre un recorrido ya hecho. Mismo formato, byte a byte:
// las claves de caché ya guardadas siguen siendo válidas.
func (h *HuellasRepo) Modulo(dir string, filtro func(rel string) bool) string {
	if h == nil || !h.enumerable {
		return ""
	}
	rutas := h.rutas
	prefijo := ""
	if dir != "." && dir != "" {
		prefijo = strings.TrimSuffix(dir, "/") + "/"
	}
	var partes []string
	for _, r := range rutas {
		if prefijo != "" && !strings.HasPrefix(r, prefijo) {
			continue
		}
		if filtro != nil && !filtro(r) {
			continue
		}
		sha := h.sha(r)
		if sha == "" {
			// Un archivo ilegible haría la huella inestable: mejor no cachear.
			return ""
		}
		partes = append(partes, r+":"+sha)
	}
	if len(partes) == 0 {
		return ""
	}
	sort.Strings(partes)
	sum := sha256.Sum256([]byte(strings.Join(partes, "\n")))
	return hex.EncodeToString(sum[:])
}
