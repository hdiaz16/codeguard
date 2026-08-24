package codegraph

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"codeguard/internal/gitdiff"
)

// Extractor de TypeScript/JavaScript a nivel de función. Sin tree-sitter:
// análisis léxico dirigido, suficiente para el mapa de llamadas de un repo
// típico (Next/React/Node) y sin dependencias nativas.

var (
	// function foo(...) / export function foo / async function foo
	reFuncDecl = regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*[<(]`)
	// const foo = (...) => / const foo = async (...) =>  / const foo = function
	reArrow = regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>`)
	// métodos de clase / objeto:  nombre(args) {   (con indentación)
	reMethod = regexp.MustCompile(`(?m)^\s{2,}(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*(\w+)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|\s.]+)?\s*\{`)
	// clases y componentes
	reClass = regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:default\s+)?class\s+(\w+)`)
	// llamadas: nombre( ... — se filtra contra las funciones conocidas
	reCall = regexp.MustCompile(`\b(\w+)\s*\(`)
	// consultas: literales SQL y llamadas a ORM
	reSQLLit = regexp.MustCompile("(?is)`[^`]*\\b(SELECT|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\b[^`]*`")
	reORM    = regexp.MustCompile(`\b(?:from|insert|update|delete|select|findMany|findUnique|findFirst|createMany|upsert)\s*\(`)
)

// palabras que parecen llamadas pero no lo son
var noSonLlamadas = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true,
	"return": true, "function": true, "typeof": true, "await": true, "new": true,
	"require": true, "import": true, "console": true, "String": true, "Number": true,
	"Boolean": true, "Array": true, "Object": true, "JSON": true, "Promise": true,
	"Math": true, "Date": true, "Error": true, "Set": true, "Map": true, "super": true,
}

// BuildTS arma el grafo función→función y función→consulta de un repo TS/JS.
func BuildTS(root string) (*Graph, error) {
	// Rastreados ya se encarga de SinVentana (el daemon no tiene consola) y de
	// las rutas con caracteres no ASCII, que git entrecomilla por defecto.
	rutas, err := gitdiff.Rastreados(root, "*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs")
	if err != nil {
		return nil, err
	}
	g := &Graph{Lang: "typescript", Root: filepath.ToSlash(root)}
	nodes := map[string]*Node{}
	byName := map[string][]string{} // nombre simple → ids (para resolver llamadas)

	type cuerpo struct {
		id, texto, file string
	}
	var cuerpos []cuerpo

	for _, rel := range rutas {
		if strings.Contains(rel, "node_modules/") ||
			strings.HasSuffix(rel, ".d.ts") || strings.Contains(rel, ".next/") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || len(raw) > 400*1024 {
			continue
		}
		src := string(raw)
		lineas := strings.Split(src, "\n")
		mod := moduloDe(rel)

		// Offsets de inicio de línea: se calculan UNA vez por archivo y la línea
		// de cada coincidencia sale por búsqueda binaria. Antes se recontaban los
		// "\n" desde el principio del archivo por CADA coincidencia, que con
		// archivos de cientos de KB y muchas declaraciones es cuadrático.
		inicios := make([]int, len(lineas))
		off := 0
		for i, l := range lineas {
			inicios[i] = off
			off += len(l) + 1
		}
		lineaDe := func(offset int) int {
			i := sort.Search(len(inicios), func(i int) bool { return inicios[i] > offset }) - 1
			if i < 0 {
				i = 0
			}
			return i + 1
		}

		// declaraciones: nombre + línea
		type decl struct {
			nombre string
			linea  int
			kind   string
		}
		var decls []decl
		for _, re := range []struct {
			re   *regexp.Regexp
			kind string
		}{{reFuncDecl, "func"}, {reArrow, "func"}, {reMethod, "method"}, {reClass, "class"}} {
			for _, m := range re.re.FindAllStringSubmatchIndex(src, -1) {
				nombre := src[m[2]:m[3]]
				if noSonLlamadas[nombre] || len(nombre) < 2 {
					continue
				}
				decls = append(decls, decl{nombre, lineaDe(m[0]), re.kind})
			}
		}
		for _, d := range decls {
			id := mod + "." + d.nombre
			if nodes[id] != nil {
				// Colisión: el mismo nombre en otro archivo del mismo módulo
				// (helpers homónimos por archivo, habitual en Next.js). Antes
				// se descartaba en silencio y con ella se iban sus llamadas y
				// sus consultas. Se desambigua con archivo:línea; byName sigue
				// indexando por nombre simple, así que las llamadas resuelven
				// a las dos, y el id sin sufijo se conserva para la primera.
				id = fmt.Sprintf("%s@%s:%d", id, rel, d.linea)
				if nodes[id] != nil {
					continue
				}
			}
			nodes[id] = &Node{ID: id, Label: d.nombre, Pkg: mod, File: rel, Line: d.linea, Kind: d.kind}
			byName[d.nombre] = append(byName[d.nombre], id)
			// el "cuerpo" es desde la declaración hasta la siguiente (aproximación
			// léxica: suficiente para atribuir llamadas a su función)
			fin := len(lineas)
			for _, o := range decls {
				if o.linea > d.linea && o.linea < fin {
					fin = o.linea
				}
			}
			ini := d.linea - 1
			if ini < 0 {
				ini = 0
			}
			if fin > len(lineas) {
				fin = len(lineas)
			}
			cuerpos = append(cuerpos, cuerpo{id, strings.Join(lineas[ini:fin], "\n"), rel})
		}
	}

	// aristas
	edges := map[string]bool{}
	sqlNodes := map[string]bool{}
	for _, c := range cuerpos {
		if m := reSQLLit.FindStringSubmatch(c.texto); m != nil {
			verbo := strings.ToUpper(strings.Fields(m[1])[0])
			qid := "sql." + verbo
			if !sqlNodes[qid] {
				nodes[qid] = &Node{ID: qid, Label: verbo, Pkg: "· consultas", File: c.file, Kind: "query"}
				sqlNodes[qid] = true
			}
			addEdge(edges, &g.Edges, nodes, c.id, qid, "query")
		} else if reORM.MatchString(c.texto) && strings.Contains(strings.ToLower(c.texto), "await") {
			qid := "sql.ORM"
			if !sqlNodes[qid] {
				nodes[qid] = &Node{ID: qid, Label: "ORM", Pkg: "· consultas", File: c.file, Kind: "query"}
				sqlNodes[qid] = true
			}
			addEdge(edges, &g.Edges, nodes, c.id, qid, "query")
		}
		for _, m := range reCall.FindAllStringSubmatch(c.texto, -1) {
			nombre := m[1]
			if noSonLlamadas[nombre] {
				continue
			}
			for _, destino := range byName[nombre] {
				if destino != c.id {
					addEdge(edges, &g.Edges, nodes, c.id, destino, "call")
				}
			}
		}
	}

	for _, n := range nodes {
		g.Nodes = append(g.Nodes, *n)
	}
	return g, nil
}

// moduloDe agrupa por carpeta (máx 3 niveles) — el "paquete" en TS.
func moduloDe(rel string) string {
	d := path.Dir(rel)
	if d == "." {
		return "raíz"
	}
	parts := strings.Split(d, "/")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "/")
}

// Build elige el extractor según el stack del repo.
//
// La detección es por ARCHIVOS RASTREADOS, no por manifiestos en la raíz. El
// layout corporativo más común es el monorepo —backend/go.mod +
// frontend/package.json— y ahí la raíz no tiene ninguno de los dos: el
// explorador decía "no encontré funciones que mapear" con cuatrocientos
// archivos de código enfrente (pasó con portal-cliente). Los extractores siempre
// recorrieron el árbol completo; sólo la puerta de entrada miraba la raíz.
//
// Y un monorepo con ambos stacks obtiene AMBOS grafos, fusionados: los IDs
// van namespaceados por paquete (Go) o carpeta (TS), así que no chocan, y un
// hallazgo del frontend tiene dónde anclarse igual que uno del backend.
func Build(root string) (*Graph, error) {
	hayGo := tieneRastreados(root, "*.go")
	hayTS := tieneRastreados(root, "*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs")
	switch {
	case hayGo && hayTS:
		g, err := BuildGo(root)
		if err != nil {
			return BuildTS(root) // medio grafo es mejor que ninguno
		}
		t, err := BuildTS(root)
		if err != nil {
			return g, nil
		}
		g.Nodes = append(g.Nodes, t.Nodes...)
		g.Edges = append(g.Edges, t.Edges...)
		g.Lang = "go + typescript"
		return g, nil
	case hayGo:
		return BuildGo(root)
	case hayTS:
		return BuildTS(root)
	}
	return &Graph{Lang: "?", Root: filepath.ToSlash(root)}, nil
}

func tieneRastreados(root string, patrones ...string) bool {
	rutas, err := gitdiff.Rastreados(root, patrones...)
	return err == nil && len(rutas) > 0
}
