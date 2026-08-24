package codegraph

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Node es una entidad del grafo: función, método o consulta.
type Node struct {
	ID    string `json:"id"`    // pkg.Func o pkg.Recv.Method
	Label string `json:"label"` // nombre corto para el render
	Pkg   string `json:"pkg"`   // agrupación de primer nivel
	File  string `json:"file"`  // ubicación
	Line  int    `json:"line"`
	Kind  string `json:"kind"`  // func | method | query
	Calls int    `json:"calls"` // fan-out (grado de salida) — para el tamaño del nodo
}

// Edge es una relación dirigida.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // call | query
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Lang  string `json:"lang"`
	Root  string `json:"root"`
	// Overlay del último análisis: el grafo deja de ser un mapa bonito y se
	// convierte en el radar del agente (dónde duele, qué tocaste).
	Overlay *Overlay `json:"overlay,omitempty"`
	// Proyectos con contexto vivo, para cambiar de repo desde el explorador.
	// El grafo es SIEMPRE de un proyecto: no se mezclan sistemas distintos.
	Proyectos []Proyecto `json:"proyectos,omitempty"`
	// Error explica, en palabras para el desarrollador, por qué no hay grafo.
	// La ventana se abre igual y lo muestra: un botón que no hace nada es
	// peor que un botón que explica qué pasó.
	Error string `json:"error,omitempty"`
}

type Proyecto struct {
	Nombre string `json:"nombre"`
	Root   string `json:"root"`
	Activo bool   `json:"activo"`
	Estado string `json:"estado"` // pass | block | —
}

// Overlay proyecta los hallazgos y el diff sobre el grafo.
type Overlay struct {
	Repo    string `json:"repo"`
	Branch  string `json:"branch"`
	At      string `json:"at"`
	Verdict string `json:"verdict"`
	// Outcome es el veredicto tipado (clean|findings|blocked|degraded|failed|
	// skipped), derivado una sola vez en el daemon. El radar del explorador lo
	// lee para no firmar «✓ commit limpio» sobre todo lo que no sea "block" —
	// que era pintar limpio un análisis degradado, fallido u omitido.
	Outcome  string           `json:"outcome"`
	Findings []OverlayFinding `json:"findings"`
	Touched  []string         `json:"touched"` // IDs de funciones tocadas por el diff
}

type OverlayFinding struct {
	NodeID   string `json:"node_id"`
	Pillar   string `json:"pillar"`
	Severity string `json:"severity"`
	Blocking bool   `json:"blocking"`
	Rule     string `json:"rule"`
	Message  string `json:"message"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// NodeAt devuelve el ID de la función que contiene ese archivo:línea — así se
// mapea un hallazgo (que vive en una línea) a un nodo del grafo.
func (g *Graph) NodeAt(file string, line int) string {
	file = strings.TrimPrefix(filepath.ToSlash(file), "./")
	best, bestLine := "", -1
	for _, n := range g.Nodes {
		if n.Kind == "query" || n.File != file {
			continue
		}
		// la función que empieza más cerca por encima de la línea del hallazgo
		if n.Line <= line && n.Line > bestLine {
			best, bestLine = n.ID, n.Line
		}
	}
	return best
}

// Sensible a mayúsculas A PROPÓSITO: el SQL embebido en Go se escribe en
// mayúsculas (en este repo, 17 consultas así y ninguna en minúsculas). Con
// (?i) cualquier prosa dentro de un literal se colaba como nodo «query» falso
// — hasta la ruta "docs/ejemplos/01-select.sql" dibujaba un sql.SELECT que no
// existe. El precio es no ver una consulta escrita en minúsculas; para eso la
// solución no es relajar el regex, sino mirar solo los argumentos de
// Query/Exec/QueryContext.
var sqlVerb = regexp.MustCompile(`\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b`)
