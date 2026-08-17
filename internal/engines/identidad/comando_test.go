package identidad

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Ningún hijo de este paquete puede construirse a mano.
//
// identidad lanza `java -jar`, el `pmd.bat` de PMD y un trivy. Mientras sólo lo
// llamaba la CLI —una aplicación de consola— nadie lo notaba. En cuanto lo llame
// el daemon, que no tiene consola, cada uno de esos hijos estrena una ventana
// negra visible; y con el .bat la abre cmd.exe, que es peor porque ni siquiera
// depende de que el programa imprima algo.
//
// Arreglar los dos sitios de arranque.go y dejar el de auditoria.go con su
// propio criterio era repetir el pecado que este paquete ya tenía: dos formas de
// armar un hijo, y la tercera se escribirá distinta. Con un constructor único el
// camino seguro es el único camino, y esta prueba es lo que lo mantiene así.
//
// Mismo guardián que cmd/daemon (TestNingunHijoDelDaemonSeArmaAMano) y que la
// CLI sobre gitCmd. LO QUE NO RECONOCE, dicho para que nadie lo lea como
// hermético: el alias del import, un &exec.Cmd{} por literal, os.StartProcess y
// las llamadas fuera de un FuncDecl. Corta la reincidencia accidental, que es la
// que ocurre de verdad.
func TestNingunHijoDeIdentidadSeArmaAMano(t *testing.T) {
	fset := token.NewFileSet()
	// ReadDir + ParseFile y no parser.ParseDir, que quedó deprecado en Go 1.25
	// y lo delata staticcheck en cada commit que toque este paquete. Mismo
	// cambio y misma red que en los guardas hermanos (hijosdeldaemon_test.go,
	// entornohijos_test.go): fallar si no se parseó ni un archivo, para que un
	// filtro mal escrito no deje el guarda en verde perpetuo.
	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var archivos []*ast.File
	for _, en := range entradas {
		nombre := en.Name()
		if en.IsDir() || !strings.HasSuffix(nombre, ".go") || strings.HasSuffix(nombre, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, nombre, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		archivos = append(archivos, f)
	}
	if len(archivos) == 0 {
		t.Fatal("no se parseó ningún archivo: el guarda no estaría vigilando nada")
	}
	visto := false
	for _, archivo := range archivos {
		ast.Inspect(archivo, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if fn.Name.Name == "comandoIdentidad" {
				visto = true
				return false
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
				// LookPath no lanza nada: sólo mira el PATH. Prohibirlo aquí
				// obligaría a rodear el guardián por una razón falsa.
				if sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext" {
					return true
				}
				t.Errorf("%s: %s arma un hijo a mano en vez de usar comandoIdentidad: "+
					"cuando el daemon importe este paquete, Windows le abrirá al hijo "+
					"una ventana negra y le pasará el entorno entero, con la clave del "+
					"modelo dentro", fset.Position(llamada.Pos()), fn.Name.Name)
				return true
			})
			return false
		})
	}
	if !visto {
		t.Fatal("no se encontró comandoIdentidad: o se renombró el constructor o esta prueba " +
			"dejó de vigilar el paquete")
	}
}

// El contrato del constructor, sin lanzar nada.
//
// Medido: HideWindow y CREATE_NO_WINDOW bastan por separado para que no se vea
// la ventana, así que la prueba de comportamiento deja vivo al mutante que quita
// uno solo. Ésta fija los dos.
func TestElConstructorDeIdentidadPideVentanaOcultaYEntornoAcotado(t *testing.T) {
	const creationNoWindow = 0x08000000
	c := comandoIdentidad(t.Context(), "java", "-version")

	if c.SysProcAttr == nil {
		t.Fatal("SysProcAttr nil: el hijo abrirá una ventana de consola")
	}
	if !c.SysProcAttr.HideWindow {
		t.Error("falta HideWindow")
	}
	if c.SysProcAttr.CreationFlags&creationNoWindow == 0 {
		t.Error("falta CREATE_NO_WINDOW")
	}

	// El entorno acotado no es un extra: el daemon lleva la API key del modelo
	// en el suyo y aquí se lanza un jar de terceros.
	if c.Env == nil {
		t.Fatal("cmd.Env nil: el hijo hereda os.Environ() entero, con la clave del modelo dentro")
	}
	for _, e := range c.Env {
		if strings.HasPrefix(strings.ToUpper(e), "CODEGUARD_LLM") {
			t.Errorf("se coló un secreto en el entorno del hijo: %s", strings.SplitN(e, "=", 2)[0])
		}
	}
	// Control: lo que java y el .bat SÍ necesitan tiene que seguir ahí, o el
	// arreglo de la ventana habría roto la detección del JDK en silencio.
	for _, necesaria := range []string{"PATH=", "PATHEXT=", "COMSPEC=", "SYSTEMROOT="} {
		hay := false
		for _, e := range c.Env {
			if strings.HasPrefix(strings.ToUpper(e), necesaria) {
				hay = true
				break
			}
		}
		if !hay {
			t.Errorf("falta %s en el entorno: java o pmd.bat no se resolverían", necesaria)
		}
	}
}
