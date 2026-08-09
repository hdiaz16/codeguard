// Package codegraph extrae el grafo de código a nivel de FUNCIÓN — quién
// llama a quién, qué consulta hace cada quién — no solo dependencias de
// paquete. Para Go usa el AST nativo (más preciso que tree-sitter).
//
// Este es el eslabón 1 del explorador de código: la extracción. El render
// interactivo (Sigma.js/WebGL en el panel) es el eslabón 2.
package codegraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
}

type Proyecto struct {
	Nombre string `json:"nombre"`
	Root   string `json:"root"`
	Activo bool   `json:"activo"`
	Estado string `json:"estado"` // pass | block | —
}

// Overlay proyecta los hallazgos y el diff sobre el grafo.
type Overlay struct {
	Repo     string           `json:"repo"`
	Branch   string           `json:"branch"`
	At       string           `json:"at"`
	Verdict  string           `json:"verdict"`
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

var sqlVerb = regexp.MustCompile(`(?is)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b`)

// BuildGo recorre el repo Go y arma el grafo función→función + función→consulta.
func BuildGo(root string) (*Graph, error) {
	fset := token.NewFileSet()
	g := &Graph{Lang: "go", Root: filepath.ToSlash(root)}
	nodeSet := map[string]*Node{}
	// mapa nombre-de-función → id completo, para resolver llamadas dentro del repo
	byName := map[string][]string{}
	type pending struct {
		fromID string
		callee string
		isSQL  bool
		sqlLbl string
		line   int
		file   string
	}
	var pends []pending

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".") || name == "spikes" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			return nil // archivo que no parsea: se salta, no se rompe
		}
		pkg := f.Name.Name
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			id, label, kind := funcID(pkg, fn)
			pos := fset.Position(fn.Pos())
			nodeSet[id] = &Node{ID: id, Label: label, Pkg: pkg, File: rel, Line: pos.Line, Kind: kind}
			byName[fn.Name.Name] = append(byName[fn.Name.Name], id)

			// recorrer el cuerpo: llamadas y literales SQL
			ast.Inspect(fn, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if callee := calleeName(x.Fun); callee != "" {
						pends = append(pends, pending{fromID: id, callee: callee, line: fset.Position(x.Pos()).Line, file: rel})
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING && sqlVerb.MatchString(x.Value) {
						verb := strings.ToUpper(sqlVerb.FindString(x.Value))
						pends = append(pends, pending{fromID: id, isSQL: true, sqlLbl: verb, line: fset.Position(x.Pos()).Line, file: rel})
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// resolver aristas: llamadas a funciones del propio repo + consultas
	edgeSet := map[string]bool{}
	sqlNodes := map[string]bool{}
	for _, pd := range pends {
		if pd.isSQL {
			qid := "sql." + pd.sqlLbl
			if !sqlNodes[qid] {
				nodeSet[qid] = &Node{ID: qid, Label: pd.sqlLbl, Pkg: "· consultas", File: pd.file, Line: pd.line, Kind: "query"}
				sqlNodes[qid] = true
			}
			addEdge(edgeSet, &g.Edges, nodeSet, pd.fromID, qid, "query")
			continue
		}
		// resolver el nombre llamado contra las funciones conocidas del repo
		for _, targetID := range byName[pd.callee] {
			if targetID != pd.fromID {
				addEdge(edgeSet, &g.Edges, nodeSet, pd.fromID, targetID, "call")
			}
		}
	}

	for _, n := range nodeSet {
		g.Nodes = append(g.Nodes, *n)
	}
	return g, nil
}

func addEdge(seen map[string]bool, edges *[]Edge, nodes map[string]*Node, from, to, kind string) {
	k := from + "->" + to
	if seen[k] {
		return
	}
	seen[k] = true
	*edges = append(*edges, Edge{From: from, To: to, Kind: kind})
	if n := nodes[from]; n != nil {
		n.Calls++
	}
}

func funcID(pkg string, fn *ast.FuncDecl) (id, label, kind string) {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		recv := recvType(fn.Recv.List[0].Type)
		return pkg + "." + recv + "." + fn.Name.Name, recv + "." + fn.Name.Name, "method"
	}
	return pkg + "." + fn.Name.Name, fn.Name.Name, "func"
}

func recvType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvType(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// calleeName saca el nombre simple de la función llamada (Foo, o x.Bar → Bar).
func calleeName(fun ast.Expr) string {
	switch t := fun.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}
