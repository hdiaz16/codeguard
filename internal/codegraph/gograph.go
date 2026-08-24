package codegraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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
