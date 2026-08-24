package pipeline

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Complejidad ciclomática: cuántos caminos distintos puede tomar la ejecución
// de una función. Cada bifurcación añade uno. Importa porque el número de
// pruebas necesarias para cubrirla crece igual, y porque una función con
// treinta caminos ya no cabe entera en la cabeza de quien la lee.
//
// Es un aviso, nunca un bloqueo: hay funciones legítimamente ramificadas —un
// despachador, una máquina de estados— y partirlas por obedecer un número las
// empeora. La decisión es del autor (P4).

// UmbralComplejidadPorDefecto sale de la práctica común (McCabe proponía 10;
// las herramientas modernas usan 10–15). 15 evita ahogar en avisos a código
// existente y sigue marcando lo que de verdad cuesta leer.
const UmbralComplejidadPorDefecto = 15

func umbralComplejidad(cfg *config.Config) int {
	if cfg != nil && cfg.MaxComplexity > 0 {
		return cfg.MaxComplexity
	}
	return UmbralComplejidadPorDefecto
}

func revisarComplejidad(cfg *config.Config, files []gitdiff.ChangedFile) []finding.Finding {
	umbral := umbralComplejidad(cfg)
	var out []finding.Finding
	for _, f := range files {
		if f.Status == "D" {
			continue
		}
		abs := filepath.Join(cfg.RepoRoot, filepath.FromSlash(f.Path))
		src, err := os.ReadFile(abs)
		if err != nil {
			continue // el archivo puede haberse movido; no es asunto de esta regla
		}
		var funcs []funcion
		switch strings.ToLower(filepath.Ext(f.Path)) {
		case ".go":
			funcs = complejidadGo(f.Path, src)
		case ".ts", ".tsx", ".js", ".jsx", ".cs", ".java":
			funcs = complejidadLlaves(src)
		default:
			continue
		}
		for _, fn := range funcs {
			if fn.Complejidad <= umbral {
				continue
			}
			fnd := finding.Finding{
				Engine:   "playbook",
				RuleKey:  "complejidad-excesiva",
				Pillar:   finding.Quality,
				Severity: finding.Warning,
				Blocking: false,
				File:     f.Path,
				Line:     fn.Linea,
				Message: fmt.Sprintf("%s tiene complejidad %d (el umbral es %d)",
					fn.Nombre, fn.Complejidad, umbral),
				Why: "Cada bifurcación multiplica los caminos posibles y las pruebas necesarias " +
					"para cubrirlos. Pasado cierto punto la función deja de caber en la cabeza " +
					"de quien la lee y los errores se esconden en las ramas que nadie recorre.",
				FixHint: "Extrae las ramas independientes a funciones con nombre, o sustituye la " +
					"cadena de condiciones por una tabla de despacho. Si la ramificación es " +
					"esencial, deja el porqué en un comentario.",
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: fn.Nombre,
				Identidad:   finding.IdentidadSemantica,
			}
			out = append(out, fnd)
		}
	}
	return out
}

type funcion struct {
	Nombre      string
	Linea       int
	Complejidad int
}

// complejidadGo usa el AST de verdad: cuenta exactamente los nodos que
// bifurcan, sin depender de cómo esté formateado el código.
func complejidadGo(ruta string, src []byte) []funcion {
	fset := token.NewFileSet()
	archivo, err := parser.ParseFile(fset, ruta, src, 0)
	if err != nil {
		return nil // código a medio escribir: no es asunto de esta regla
	}
	var out []funcion
	for _, decl := range archivo.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		c := 1 // el camino base
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch t := n.(type) {
			case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
				c++
			case *ast.BinaryExpr:
				// && y || crean un camino cada uno (evaluación en corto).
				if t.Op == token.LAND || t.Op == token.LOR {
					c++
				}
			}
			return true
		})
		nombre := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			nombre = tipoReceptor(fd.Recv.List[0].Type) + "." + nombre
		}
		out = append(out, funcion{Nombre: nombre, Linea: fset.Position(fd.Pos()).Line, Complejidad: c})
	}
	return out
}

func tipoReceptor(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return tipoReceptor(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}
