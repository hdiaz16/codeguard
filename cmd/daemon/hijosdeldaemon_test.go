package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Ningún hijo del daemon puede construirse a mano.
//
// El daemon no tiene consola (se compila con -H windowsgui), así que todo
// ejecutable de consola que lance sin CREATE_NO_WINDOW abre una ventana negra
// visible. Pasó con el git del historial. Los motores no lo sufrían porque van
// por proc.Correr, que ya la oculta; el fallo fue armar un exec.Command al
// margen de ese camino, y arreglar ese sitio solo dejaría el agujero abierto
// para el siguiente —un `explorer` para abrir una carpeta, un `git` más— que se
// escribirá dentro de seis meses en la forma más natural del mundo.
//
// Con un único constructor el camino seguro es el ÚNICO camino, y esta prueba
// es lo que lo mantiene así. Es el mismo guardián que la CLI tiene sobre gitCmd
// (TestTodoGitDeLaCLIPasaPorGitCmd), por la razón hermana: allí lo que se
// escapaba era el entorno con la clave del modelo dentro.
//
// LO QUE NO RECONOCE, para que nadie lo confunda con una garantía: el alias del
// import (`import ex "os/exec"`), un exec.Cmd construido por literal
// (`&exec.Cmd{Path: …}`), os.StartProcess, y cualquier llamada fuera de un
// FuncDecl. Su trabajo es cortar la reincidencia ACCIDENTAL, no resistir a
// quien quiera rodearlo.
//
// Sólo mira los archivos que NO son de prueba: la propia prueba de la ventana
// arma un exec.Command a mano a propósito, como control.
func TestNingunHijoDelDaemonSeArmaAMano(t *testing.T) {
	fset := token.NewFileSet()
	// ReadDir + ParseFile y no parser.ParseDir, que quedó deprecado en Go 1.25
	// y lo delata staticcheck en cada commit que toque este paquete. Aquí no
	// hacía falta agrupar por paquete: se vigila cada .go que no sea de test,
	// uno a uno. Es el mismo cambio que ya se hizo en el guarda hermano de la
	// CLI (entornohijos_test.go), y la misma red: fallar si no se parseó ni un
	// archivo, para que un filtro mal escrito no deje el guarda en verde
	// perpetuo por no tener nada que mirar.
	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	archivos := map[string]*ast.File{}
	for _, en := range entradas {
		nombre := en.Name()
		if en.IsDir() || !strings.HasSuffix(nombre, ".go") || strings.HasSuffix(nombre, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, nombre, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		archivos[nombre] = f
	}
	if len(archivos) == 0 {
		t.Fatal("no se parseó ningún archivo: el guarda no estaría vigilando nada")
	}
	visto := false
	{
		for _, archivo := range archivos {
			ast.Inspect(archivo, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				if fn.Name.Name == "comandoDaemon" {
					visto = true
					return false // el constructor es el único sitio legítimo
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
					t.Errorf("%s: %s arma un hijo a mano en vez de usar comandoDaemon: "+
						"el daemon no tiene consola y Windows le abrirá al hijo una "+
						"ventana negra visible en la cara del desarrollador",
						fset.Position(llamada.Pos()), fn.Name.Name)
					return true
				})
				return false
			})
		}
	}
	// Si alguien renombra o borra el constructor, la prueba dejaría de mirar
	// nada y seguiría en verde. Esto lo impide.
	if !visto {
		t.Fatal("no se encontró comandoDaemon: o se renombró el constructor o esta prueba " +
			"dejó de vigilar el paquete")
	}
}
