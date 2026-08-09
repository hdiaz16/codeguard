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
			}
			fnd.ComputeFingerprint()
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

// palabrasQueBifurcan son las que abren un camino nuevo en los lenguajes de
// llaves. "else" no cuenta: no añade un camino, completa el de su if.
var palabrasQueBifurcan = []string{"if", "for", "while", "case", "catch"}

// complejidadLlaves aproxima la complejidad en TS/JS/C#/Java sin un parser por
// lenguaje. Sigue la profundidad de llaves para saber dónde acaba cada
// función y cuenta palabras clave dentro.
//
// Es una aproximación consciente: no entiende cadenas de texto ni comentarios
// que contengan estas palabras, así que puede contar de más. Por eso sólo
// avisa, y por eso el umbral es holgado. Un parser por lenguaje daría números
// exactos a cambio de mantener cuatro gramáticas.
func complejidadLlaves(src []byte) []funcion {
	lineas := strings.Split(string(src), "\n")
	var out []funcion
	var actual *funcion
	profundidad, profundidadInicio := 0, 0

	for i, linea := range lineas {
		limpia := sinTextoNiComentarios(linea)

		if actual == nil && pareceDeclaracionDeFuncion(limpia) {
			nombre := nombreDeFuncion(limpia)
			actual = &funcion{Nombre: nombre, Linea: i + 1, Complejidad: 1}
			profundidadInicio = profundidad
		}
		if actual != nil {
			for _, p := range palabrasQueBifurcan {
				actual.Complejidad += contarPalabra(limpia, p)
			}
			actual.Complejidad += strings.Count(limpia, "&&") + strings.Count(limpia, "||")
		}

		profundidad += strings.Count(limpia, "{") - strings.Count(limpia, "}")
		if actual != nil && profundidad <= profundidadInicio && strings.Contains(limpia, "}") {
			out = append(out, *actual)
			actual = nil
		}
	}
	if actual != nil {
		out = append(out, *actual) // archivo sin cerrar: contamos lo que vimos
	}
	return out
}

// sinTextoNiComentarios quita literales de cadena y comentarios de línea para
// no contar palabras clave que sólo aparecen en un mensaje o una nota.
func sinTextoNiComentarios(l string) string {
	var b strings.Builder
	var comilla rune
	anterior := rune(0)
	for i, r := range l {
		if comilla == 0 && (r == '/' && i+1 < len(l) && l[i+1] == '/') {
			break
		}
		switch {
		case comilla != 0:
			if r == comilla && anterior != '\\' {
				comilla = 0
			}
		case r == '"' || r == '\'' || r == '`':
			comilla = r
		default:
			b.WriteRune(r)
		}
		anterior = r
	}
	return b.String()
}

func pareceDeclaracionDeFuncion(l string) bool {
	t := strings.TrimSpace(l)
	if !strings.Contains(t, "(") || !strings.Contains(t, "{") {
		return false
	}
	switch {
	case strings.HasPrefix(t, "function ") || strings.Contains(t, " function "):
		return true
	case strings.Contains(t, "=>") && strings.Contains(t, "("):
		return true
	case strings.HasPrefix(t, "if") || strings.HasPrefix(t, "for") ||
		strings.HasPrefix(t, "while") || strings.HasPrefix(t, "switch") ||
		strings.HasPrefix(t, "catch") || strings.HasPrefix(t, "}"):
		return false
	case contarPalabra(t, "public")+contarPalabra(t, "private")+
		contarPalabra(t, "protected")+contarPalabra(t, "static")+
		contarPalabra(t, "async") > 0:
		return true
	}
	// Método suelto de clase: nombre(args) {
	i := strings.Index(t, "(")
	return i > 0 && esIdentificador(strings.TrimSpace(t[:i]))
}

func esIdentificador(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		esLetra := r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !esLetra && !(i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func nombreDeFuncion(l string) string {
	t := strings.TrimSpace(l)
	i := strings.Index(t, "(")
	if i <= 0 {
		return "(anónima)"
	}
	campos := strings.FieldsFunc(t[:i], func(r rune) bool {
		return r == ' ' || r == '\t' || r == '=' || r == ':'
	})
	if len(campos) == 0 {
		return "(anónima)"
	}
	return campos[len(campos)-1]
}

// contarPalabra cuenta apariciones como palabra completa, para que "iffy" o
// "forEach" no cuenten como bifurcaciones.
func contarPalabra(l, palabra string) int {
	n, desde := 0, 0
	for {
		i := strings.Index(l[desde:], palabra)
		if i < 0 {
			return n
		}
		i += desde
		antes := i == 0 || !esCaracterDePalabra(rune(l[i-1]))
		fin := i + len(palabra)
		despues := fin >= len(l) || !esCaracterDePalabra(rune(l[fin]))
		if antes && despues {
			n++
		}
		desde = fin
	}
}

func esCaracterDePalabra(r rune) bool {
	return r == '_' || r == '$' || (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
