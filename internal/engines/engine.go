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
	rutas, err := gitdiff.Rastreados(repoRoot)
	if err != nil || len(rutas) == 0 {
		return ""
	}
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
		sha := gitdiff.SHA256De(repoRoot, r)
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
