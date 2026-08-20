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
	"strconv"
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

// Sensible a mayúsculas A PROPÓSITO: el SQL embebido en Go se escribe en
// mayúsculas (en este repo, 17 consultas así y ninguna en minúsculas). Con
// (?i) cualquier prosa dentro de un literal se colaba como nodo «query» falso
// — hasta la ruta "docs/ejemplos/01-select.sql" dibujaba un sql.SELECT que no
// existe. El precio es no ver una consulta escrita en minúsculas; para eso la
// solución no es relajar el regex, sino mirar solo los argumentos de
// Query/Exec/QueryContext.
var sqlVerb = regexp.MustCompile(`\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b`)

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
		pkg    string // paquete del llamante: acota la resolución de idents desnudos
		viaSel bool   // la llamada fue x.Bar (selector) y no Bar a pelo
		// Restricciones para las llamadas con selector, deducidas del AST sin
		// go/types. Si ninguna aplica, la llamada es AMBIGUA y no genera arista:
		// una arista que falta es un límite declarado del heurístico; una arista
		// falsa es una dependencia que no existe dibujada en el explorador, y
		// sobre ese dibujo se toman decisiones.
		soloPkg  string // x es el paquete importado con este nombre: sólo funcs de ese paquete
		soloRecv string // x es una variable de este tipo: sólo métodos con ese receptor
		isSQL    bool
		sqlLbl   string
		line     int
		file     string
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

		// Imports del archivo: nombre visible → base de la ruta. Es lo que
		// permite distinguir «x es un paquete» de «x es una variable» en x.Bar()
		// sin cargar go/types. Se usa la base de la ruta como nombre de paquete:
		// cuando difieren (yaml.v3 → package yaml) la arista se pierde, pero
		// nunca se inventa una falsa.
		imports := map[string]string{}
		for _, imp := range f.Imports {
			ruta, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			base := ruta[strings.LastIndex(ruta, "/")+1:]
			nombre := base
			if imp.Name != nil {
				if imp.Name.Name == "_" || imp.Name.Name == "." {
					continue
				}
				nombre = imp.Name.Name
			}
			imports[nombre] = base
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			id, label, kind := funcID(pkg, fn)
			pos := fset.Position(fn.Pos())
			nodeSet[id] = &Node{ID: id, Label: label, Pkg: pkg, File: rel, Line: pos.Line, Kind: kind}
			byName[fn.Name.Name] = append(byName[fn.Name.Name], id)

			// Tipos locales deducibles sin go/types: el receptor, los parámetros
			// y las variables con tipo explícito o literal compuesto (var x T,
			// x := T{...}). Es lo único que permite saber a QUÉ tipo pertenece el
			// método en x.Close(). Lo demás —campos de struct, retornos de
			// función, tipos calificados de otro paquete— queda ambiguo.
			varTypes := map[string]string{}
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				if t := recvType(fn.Recv.List[0].Type); t != "?" {
					for _, n := range fn.Recv.List[0].Names {
						varTypes[n.Name] = t
					}
				}
			}
			if fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					t := recvType(field.Type)
					if t == "?" {
						continue
					}
					for _, n := range field.Names {
						varTypes[n.Name] = t
					}
				}
			}
			if fn.Body != nil {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch d := n.(type) {
					case *ast.DeclStmt:
						gd, ok := d.Decl.(*ast.GenDecl)
						if !ok || gd.Tok != token.VAR {
							return true
						}
						for _, spec := range gd.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok || vs.Type == nil {
								continue
							}
							if t := recvType(vs.Type); t != "?" {
								for _, n := range vs.Names {
									varTypes[n.Name] = t
								}
							}
						}
					case *ast.AssignStmt:
						if d.Tok != token.DEFINE {
							return true
						}
						for i, rhs := range d.Rhs {
							lit, ok := rhs.(*ast.CompositeLit)
							if !ok || i >= len(d.Lhs) {
								continue
							}
							ident, ok := d.Lhs[i].(*ast.Ident)
							if !ok {
								continue
							}
							if t := recvType(lit.Type); t != "?" {
								varTypes[ident.Name] = t
							}
						}
					}
					return true
				})
			}

			// recorrer el cuerpo: llamadas y literales SQL
			ast.Inspect(fn, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if callee, sel := calleeName(x.Fun); callee != "" {
						pd := pending{fromID: id, callee: callee, pkg: pkg, viaSel: sel,
							line: fset.Position(x.Pos()).Line, file: rel}
						if sel {
							// Se decide AQUÍ qué hay a la izquierda del punto,
							// porque imports y varTypes mueren al cerrar el
							// archivo y la resolución ocurre después.
							switch sx := selectorIdent(x.Fun); {
							case sx == "":
							default:
								if impPkg, ok := imports[sx]; ok {
									pd.soloPkg = impPkg
								} else if t, ok := varTypes[sx]; ok {
									pd.soloRecv = t
								}
							}
						}
						pends = append(pends, pd)
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
			if targetID == pd.fromID {
				continue
			}
			tgt := nodeSet[targetID]
			if tgt == nil {
				continue
			}
			if !pd.viaSel {
				// Un identificador desnudo (Validate() a pelo) sólo puede
				// resolver a una función del MISMO paquete. Sin este filtro,
				// Validate() en un paquete dibujaba aristas hacia el Validate()
				// de todos los demás: dependencias que no existen.
				if tgt.Pkg != pd.pkg || tgt.Kind != "func" {
					continue
				}
			} else {
				// Con selector (x.Bar) sólo se emite arista si se dedujo qué es
				// x: un paquete importado —entonces la FUNCIÓN de ese paquete— o
				// una variable de tipo conocido —entonces el MÉTODO de ese tipo,
				// que siendo un ident sin calificar sólo puede ser local—. Si no
				// se dedujo nada, no hay arista: repartir la arista de cualquier
				// x.Close() entre todos los Close() del repo dibujaba
				// dependencias inexistentes, y el explorador es el mapa sobre el
				// que un agente decide dónde tocar.
				switch {
				case pd.soloPkg != "":
					if tgt.Pkg != pd.soloPkg || tgt.Kind != "func" {
						continue
					}
				case pd.soloRecv != "":
					if tgt.Pkg != pd.pkg || tgt.Kind != "method" ||
						!strings.HasSuffix(tgt.ID, "."+pd.soloRecv+"."+pd.callee) {
						continue
					}
				default:
					continue
				}
			}
			addEdge(edgeSet, &g.Edges, nodeSet, pd.fromID, targetID, "call")
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
	case *ast.IndexExpr:
		// receptor genérico con un parámetro: Stack[T] → Stack. Sin este caso
		// caía en "?" y todos los tipos genéricos del paquete colisionaban en
		// el mismo id (pkg.?.Push), mezclando sus aristas.
		return recvType(t.X)
	case *ast.IndexListExpr:
		// receptor genérico con varios: Pair[K, V] → Pair
		return recvType(t.X)
	}
	return "?"
}

// selectorIdent devuelve el identificador a la izquierda del punto en una
// llamada con selector (x.Bar → x). Si la izquierda no es un identificador
// simple —h.campo.Bar, foo().Bar—, devuelve "": sin saber qué es, la llamada
// queda ambigua y no genera arista.
func selectorIdent(fun ast.Expr) string {
	if sel, ok := fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

// calleeName saca el nombre simple de la función llamada (Foo, o x.Bar → Bar) y
// dice si venía de un selector: es la distinción que evita resolver un
// identificador desnudo contra funciones de otros paquetes.
func calleeName(fun ast.Expr) (nombre string, viaSelector bool) {
	switch t := fun.(type) {
	case *ast.Ident:
		return t.Name, false
	case *ast.SelectorExpr:
		return t.Sel.Name, true
	}
	return "", false
}
