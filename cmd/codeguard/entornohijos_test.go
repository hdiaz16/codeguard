//go:build windows

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// La CLI lanza hijos —git y el `go list` del grafo— y hasta ahora les entregaba
// os.Environ() entero. El daemon ya no: sus motores corren con proc.Entorno() y
// su git con proc.EntornoGit(). La CLI se quedó fuera de esa mudanza, y es la
// que más veces lanza git: cada commit pasa por su hook.
//
// Que la clave llegue ahí no es teórico. `codeguard` llama a
// proc.RefrescarVariables() al arrancar (main.go:42), que TRAE del registro las
// variables de usuario que el proceso no tiene. Mientras la bóveda no gestione
// la clave —una instalación con `install.ps1 -ApiKey` que el daemon aún no ha
// migrado— esa llamada mete la clave en el proceso, y de ahí baja a cada hijo
// lanzado sin cmd.Env.

// binarioFalso deja un ejecutable con ese nombre PRIMERO en el PATH, que vuelca
// el entorno que recibe y sale bien.
//
// Se mira lo que llega al otro lado y no la lista que preparamos: comprobar el
// []string que le pasamos a cmd.Env probaría que escribimos lo que quisimos
// escribir, no que el hijo recibe lo que creemos.
func binarioFalso(t *testing.T, nombre string) (volcado string) {
	t.Helper()
	dir := t.TempDir()
	volcado = filepath.Join(dir, "entorno-visto.txt")
	guion := "@echo off\r\necho ==== %* >> \"" + volcado + "\"\r\nset >> \"" + volcado + "\"\r\n"
	if err := os.WriteFile(filepath.Join(dir, nombre+".cmd"), []byte(guion), 0o755); err != nil {
		t.Fatal(err)
	}
	// Delante del PATH heredado: exec.LookPath recorre los directorios en orden
	// y dentro de cada uno prueba las extensiones de PATHEXT, así que un .cmd en
	// un directorio anterior gana al .exe de uno posterior.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return volcado
}

func loVisto(t *testing.T, volcado string) string {
	t.Helper()
	raw, err := os.ReadFile(volcado)
	if err != nil {
		t.Fatalf("el binario falso no llegó a correr: %v", err)
	}
	return string(raw)
}

const claveDePrueba = "clave-que-ningun-hijo-de-la-cli-necesita"

// El git que corre en CADA commit.
//
// arbolPreparado es la primera cosa que hace el hook de pre-commit, y era la
// invocación de git más caliente del producto corriendo con el entorno entero.
func TestElGitDelHookNoRecibeLaClaveDelModelo(t *testing.T) {
	volcado := binarioFalso(t, "git")
	t.Setenv("FOUNDRY_API_KEY", claveDePrueba)
	// La cara opuesta, y es la que hace daño si se filtra de más: git le dice al
	// hook QUÉ índice está commiteando. Sin esto, `write-tree` firma el árbol
	// del índice real y no el del `git commit -a` en curso.
	t.Setenv("GIT_INDEX_FILE", "indice-temporal-de-prueba")

	arbolPreparado(t.TempDir()) // sólo interesa el efecto secundario

	visto := loVisto(t, volcado)
	if strings.Contains(visto, claveDePrueba) {
		t.Error("git recibió la API key del modelo: cualquier hook, alias o " +
			"credential helper configurado por el usuario la tiene a un paso")
	}
	if !strings.Contains(visto, "indice-temporal-de-prueba") {
		t.Error("git no recibió GIT_INDEX_FILE: `write-tree` firmaría el árbol " +
			"equivocado y el trailer diría que analizamos algo que no analizamos")
	}
	if !strings.Contains(strings.ToUpper(visto), "PATH=") {
		t.Error("git se quedó sin PATH: no encontraría ni sus propios subcomandos")
	}
}

// Y el resto de invocaciones de git de la CLI que se pueden llamar sueltas.
//
// Las dos que viven dentro de un RunE de cobra —el `git log` del post-commit y
// el `git config` de escritura de install— no se ejercitan aquí: llamarlas
// obligaría a montar un enrolamiento entero y la prueba diría más sobre el
// andamiaje que sobre el entorno. A esas las cubre TestTodoGitDeLaCLIPasaPorGitCmd,
// que las mira en el código fuente y no distingue entre alcanzables o no.
func TestLosDemasGitDeLaCLINoRecibenLaClave(t *testing.T) {
	for _, c := range []struct {
		nombre string
		correr func(repo string)
	}{
		{"gitRemote (main.go)", func(r string) { gitRemote(r) }},
		{"gitBranch (main.go)", func(r string) { gitBranch(r) }},
		{"revisarRepo (statuscmd.go)", func(r string) { revisarRepo(r) }},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			volcado := binarioFalso(t, "git")
			t.Setenv("FOUNDRY_API_KEY", claveDePrueba)
			c.correr(t.TempDir())
			if strings.Contains(loVisto(t, volcado), claveDePrueba) {
				t.Errorf("%s le entregó la API key del modelo a git", c.nombre)
			}
		})
	}
}

// El `go list` del grafo de dependencias.
//
// Es el mismo agujero con otro binario, y con el agravante de que la cadena de
// herramientas de Go ejecuta código del módulo que analiza en cuanto hay un
// `//go:generate` o cgo por medio.
func TestElGoListDelGrafoNoRecibeLaClaveDelModelo(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"),
		[]byte("module ejemplo\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	volcado := binarioFalso(t, "go")
	t.Setenv("FOUNDRY_API_KEY", claveDePrueba)

	if _, err := goEdges(repo, "."); err != nil {
		t.Logf("goEdges devolvió error (esperable con un go falso): %v", err)
	}

	if strings.Contains(loVisto(t, volcado), claveDePrueba) {
		t.Error("`go list` recibió la API key del modelo")
	}
}

// La otra mitad del contrato: acotar el entorno no puede romper lo que se
// acota. Con `go` de verdad, sobre el módulo de este repo.
func TestElGrafoSigueResolviendoLosPaquetesConElEntornoAcotado(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin cadena de herramientas de Go")
	}
	raiz, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	raiz = filepath.Dir(raiz) // cmd/codeguard -> cmd -> raíz del repo
	if _, err := os.Stat(filepath.Join(raiz, "go.mod")); err != nil {
		t.Skipf("no se encontró el go.mod del repo: %v", err)
	}

	edges, err := goEdges(raiz, ".")
	if err != nil {
		t.Fatalf("go list dejó de funcionar con el entorno acotado: %v", err)
	}
	if len(edges) == 0 {
		t.Error("go list no devolvió ninguna arista: el grafo saldría vacío y " +
			"nadie lo notaría, que es la forma silenciosa de romperlo")
	}
}

// arbolPreparado tiene que firmar el árbol del índice que se está commiteando.
//
// Esta prueba está en verde ANTES y DESPUÉS del arreglo, y es a propósito: es
// la que se pone roja si alguien "termina el trabajo" cambiando gitCmd a
// proc.Entorno(). Sin GIT_INDEX_FILE, git escribe el árbol del índice REAL, y
// durante un `git commit -a` ese no es el que se commitea: el run id quedaría
// atado a un árbol que nadie va a commitear y el trailer afirmaría que pasó por
// CodeGuard un contenido que no pasó.
func TestArbolPreparadoMiraElIndiceQueSeEstaCommiteando(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("sin git")
	}
	repo := t.TempDir()
	git := func(extra []string, args ...string) string {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = repo
		c.Env = append(os.Environ(), extra...)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(nil, "init", "-q", ".")
	git(nil, "config", "user.email", "t@t.t")
	git(nil, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("uno\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(nil, "add", "a.txt")
	git(nil, "commit", "-q", "-m", "base")

	// El worktree cambia, pero el índice REAL se queda como estaba: es
	// exactamente el estado en el que git lanza el hook de un `git commit -a`.
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("dos\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	indiceTemporal := filepath.Join(t.TempDir(), "index.temporal")
	env := []string{"GIT_INDEX_FILE=" + indiceTemporal}
	git(env, "read-tree", "HEAD")
	git(env, "add", "a.txt")

	arbolDelTemporal := git(env, "write-tree")
	arbolDelReal := git(nil, "write-tree")
	if arbolDelTemporal == arbolDelReal {
		t.Fatal("los dos índices dan el mismo árbol: la prueba no distinguiría nada")
	}

	t.Setenv("GIT_INDEX_FILE", indiceTemporal)
	got := arbolPreparado(repo)

	if got == arbolDelReal {
		t.Fatalf("arbolPreparado firmó el árbol del índice REAL (%s) en vez del "+
			"que se está commiteando (%s): perdió GIT_INDEX_FILE por el camino",
			arbolDelReal, arbolDelTemporal)
	}
	if got != arbolDelTemporal {
		t.Fatalf("arbolPreparado devolvió %q, esperaba %q", got, arbolDelTemporal)
	}
}

// Ningún git de este paquete puede construirse a mano.
//
// Las siete invocaciones que había filtraban por la misma razón: cada una se
// armaba su propio exec.Command y nada obligaba a acotarle el entorno. Arreglar
// las siete de una en una deja el mismo agujero abierto para la octava, que se
// escribirá dentro de seis meses. Con un único constructor, el camino seguro es
// el ÚNICO camino, y esta prueba es lo que lo mantiene así.
//
// Se comprueba sólo git a propósito: los dos `python -c` de enginescmd.go están
// en manos de otra remediación, y una prueba que falle por trabajo ajeno se
// desactiva en vez de arreglarse.
//
// LO QUE ESTE GUARDA NO RECONOCE, medido intentando rodearlo, para
// que nadie lo confunda con una garantía: escapan el alias del import
// (`import ex "os/exec"`), la variable local (`bin := "git"`), la constante de
// paquete, la concatenación (`"gi"+"t"`) y cualquier llamada fuera de un
// FuncDecl (un `var x = exec.Command("git", …)` a nivel de paquete, porque el
// ast.Inspect exterior sólo desciende a declaraciones de función).
//
// SÍ reconoce, porque se intentó rodearlo con ellas y no se pudo:
// exec.CommandContext, "git.exe", cualquier combinación de mayúsculas, una ruta
// absoluta terminada en git/git.exe, las cadenas con comillas invertidas, y las
// llamadas dentro de un closure de cobra, de un método con receptor o de un
// func literal — que es donde viven todas las invocaciones reales.
//
// Es deliberado: su trabajo es cortar la reincidencia ACCIDENTAL —la octava
// invocación se escribirá en la forma natural, y ésa sí la caza— no resistir a
// quien quiera rodearlo. Perseguir el resto pediría análisis de flujo y daría
// una falsa sensación de hermetismo, que es peor que un alcance declarado.
func TestTodoGitDeLaCLIPasaPorGitCmd(t *testing.T) {
	fset := token.NewFileSet()
	// parser.ParseDir quedó deprecado en Go 1.25 —no mira las etiquetas de
	// compilación al agrupar archivos por paquete— y con el toolchain 1.26 lo
	// delata staticcheck (SA1019) en cada commit que toque este paquete.
	//
	// Aquí no hacía falta agrupar por paquete para nada: lo que este guarda
	// vigila es CADA .go que no sea de test, uno a uno. Así que se enumera el
	// directorio y se parsea archivo por archivo, que además hace explícito
	// —y no un efecto colateral del filtro— qué entra y qué no.
	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	archivos := map[string]*ast.File{}
	for _, e := range entradas {
		nombre := e.Name()
		if e.IsDir() || !strings.HasSuffix(nombre, ".go") || strings.HasSuffix(nombre, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, nombre, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		archivos[nombre] = f
	}
	// Sin esto, el día que el filtro se escriba mal este test pasaría sin haber
	// mirado un solo archivo — verde perpetuo por no tener nada que revisar,
	// que es justo el modo de fallo que el resto del repo persigue.
	if len(archivos) == 0 {
		t.Fatal("no se parseó ningún archivo: el guarda no estaría vigilando nada")
	}
	{
		// La ruta no se usa: los mensajes de error salen de fset.Position, que
		// ya la lleva dentro. Antes se guardaba en una variable y se tiraba a
		// "_" al final del bucle, y la regla de la casa tiene razón en
		// quejarse — era código muerto disfrazado de uso.
		for _, archivo := range archivos {
			ast.Inspect(archivo, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				if fn.Name.Name == "gitCmd" {
					return false // el constructor es el único sitio legítimo
				}
				if fn.Body == nil {
					return true
				}
				ast.Inspect(fn.Body, func(m ast.Node) bool {
					llamada, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := llamada.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok || id.Name != "exec" {
						return true
					}
					if sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext" {
						return true
					}
					for _, arg := range llamada.Args {
						lit, ok := arg.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						// Se compara sobre filepath.Base y sin distinguir
						// mayúsculas. Las dos cosas salieron de intentar
						// rodearlo: `exec.Command("GIT.EXE", …)` escapaba a una
						// comparación exacta en una plataforma cuyos nombres de
						// archivo no distinguen mayúsculas —LookPath lo
						// encuentra igual—, y una ruta absoluta clavada
						// (`C:\Program Files\Git\bin\git.exe`) es más plausible
						// aquí que varias de las formas que sí se documentan
						// abajo: nadie escribe `"gi"+"t"` por accidente, pero
						// alguien sí clava la ruta de Git for Windows.
						v, _ := strconv.Unquote(lit.Value)
						base := strings.ToLower(filepath.Base(v))
						if base == "git" || base == "git.exe" {
							t.Errorf("%s: %s arma git a mano en vez de usar gitCmd: "+
								"hereda el entorno completo del proceso, con la clave "+
								"del modelo dentro",
								fset.Position(lit.Pos()), fn.Name.Name)
						}
					}
					return true
				})
				return false
			})
		}
	}
}
