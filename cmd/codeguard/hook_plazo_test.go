package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// NINGÚN MOTOR CORRE SIN PLAZO EN EL GANCHO.
//
// El fallo que retira: la etapa 2 siempre tuvo tope (hookDeadline) y la etapa 1
// —la compuerta de secretos, la ÚNICA que bloquea— se llamaba con un
// context.Background() pelado. Un gitleaks colgado dejaba el `git commit` del
// usuario esperando para siempre, sin mensaje. Lo pisa cada commit.
//
// POR QUÉ ESTE TEST MIRA EL FUENTE Y NO EL COMPORTAMIENTO, que es una decisión y
// no una pereza: el test de comportamiento vive en internal/engines/gitleaks
// (TestUnGitleaksColgadoSeRindeYNoCuelgaElCommit) y comprueba que el motor se
// rinde cuando le dan un plazo. Pero ese test PASABA YA ANTES del arreglo — el
// motor siempre respetó el contexto que le dieran; lo que estaba roto era el
// contexto que el gancho le daba. Un test que pasa antes y después no prueba
// nada, y aquí lo que hay que clavar es precisamente la línea de llamada.
//
// El método no es nuevo en este repo: TestElContratoNoDejaMotoresFuera recorre
// el módulo por AST para que nadie añada un motor y se olvide de meterlo bajo
// contrato. Esto es lo mismo para el plazo.
func TestElGanchoNoLanzaNingunMotorSinPlazo(t *testing.T) {
	fset := token.NewFileSet()
	archivo, err := parser.ParseFile(fset, "hook.go", nil, 0)
	if err != nil {
		t.Fatalf("no pude leer hook.go: %v", err)
	}

	// Se mira hook.go y NO todo el paquete, y es deliberado: la invariante es del
	// GANCHO. Los comandos que el usuario invoca a mano (baseline, report, ci)
	// llaman a pipeline.Run con context.Background() a propósito —ahí no hay un
	// `git commit` esperando y el usuario puede cortar con Ctrl-C—, así que
	// ampliar el recorrido al paquete pondría este test en rojo por tres usos
	// legítimos. Si la etapa 1 se mudara a otro archivo, hay que traer su nombre
	// aquí.
	sinPlazo := identificadoresSinPlazo(archivo)

	var culpables []string
	ast.Inspect(archivo, func(n ast.Node) bool {
		llamada, ok := n.(*ast.CallExpr)
		if !ok || len(llamada.Args) == 0 {
			return true
		}
		sel, ok := llamada.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Run" {
			return true
		}
		if !esContextBackground(llamada.Args[0]) && !sinPlazo[nombreIdent(llamada.Args[0])] {
			return true
		}
		culpables = append(culpables, fset.Position(llamada.Pos()).String())
		return true
	})

	if len(culpables) > 0 {
		t.Errorf("hay %d motor(es) lanzados con un contexto sin plazo en el gancho "+
			"(Background/TODO, directo o guardado en una variable), o sea sin tope: "+
			"si el binario se cuelga, el commit del usuario no vuelve nunca.\n  %s",
			len(culpables), strings.Join(culpables, "\n  "))
	}
}

// identificadoresSinPlazo devuelve los nombres de variable que guardan un
// context.Background()/TODO(). Sin esto la guarda era puramente sintáctica y el
// refactor más inocente la eludía: `ctx := context.Background()` seguido de
// `motor.Run(ctx, …)` pasaba en verde reintroduciendo el cuelgue exacto que este
// test existe para evitar.
//
// Se miran DOS formas de declarar la variable, porque las dos existen en Go y las
// dos eludían la guarda: el `:=` (AssignStmt) y el `var ctx = …` (ValueSpec, que
// en el AST no es una asignación sino una declaración). Lo que NO se mira, y es
// decisión y no descuido: un contexto que llega de un helper (`ctx := nuevoCtx()`)
// o por parámetro. Cubrir eso exige type-checking y convertiría esta guarda en un
// analizador de flujo de datos — desproporcionado para un test; esas vías las
// cubre la revisión, no el AST.
func identificadoresSinPlazo(archivo *ast.File) map[string]bool {
	variables := map[string]bool{}
	ast.Inspect(archivo, func(n ast.Node) bool {
		switch nodo := n.(type) {
		case *ast.AssignStmt:
			for i, derecha := range nodo.Rhs {
				// En `a, b := f()` los dos lados no miden lo mismo: sólo se
				// empareja lo que existe.
				if !esContextBackground(derecha) || i >= len(nodo.Lhs) {
					continue
				}
				if ident, ok := nodo.Lhs[i].(*ast.Ident); ok {
					variables[ident.Name] = true
				}
			}
		case *ast.ValueSpec:
			// `var ctx = context.Background()` llega aquí y no por AssignStmt:
			// sin esta rama, la forma `var` era la vía barata de esquivarla.
			for i, valor := range nodo.Values {
				if !esContextBackground(valor) || i >= len(nodo.Names) {
					continue
				}
				variables[nodo.Names[i].Name] = true
			}
		}
		return true
	})
	return variables
}

// nombreIdent da el nombre cuando la expresión es una variable pelada, y "" en
// cualquier otro caso.
func nombreIdent(e ast.Expr) string {
	if ident, ok := e.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// Nota: verificado contra el daemon 1.12.0 por el camino del producto.
// esContextBackground reconoce tanto context.Background() como el
// context.TODO() que a veces se cuela en su lugar. Los dos son "sin plazo".
func esContextBackground(e ast.Expr) bool {
	llamada, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := llamada.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	paquete, ok := sel.X.(*ast.Ident)
	if !ok || paquete.Name != "context" {
		return false
	}
	return sel.Sel.Name == "Background" || sel.Sel.Name == "TODO"
}

// LA GUARDA TIENE QUE VER LAS DOS FORMAS DE DECLARAR EL CONTEXTO.
//
// Vigilaba sólo el `:=`, así que `var ctx = context.Background()` era la vía
// barata de esquivarla: el gancho podía volver a lanzar un motor sin plazo y el
// test seguía en verde. Aquí se le da a la función un archivo sintético con las
// dos formas —y con una tercera que NO tiene que marcar— para fijar su frontera.
func TestLaGuardaReconoceElVarYNoSoloElDosPuntosIgual(t *testing.T) {
	fuente := `package p

import "context"

func f() {
	conDosPuntos := context.Background()
	var conVar = context.TODO()
	var conVarios, otro = context.Background(), 1
	conPlazo, cancel := context.WithTimeout(context.Background(), 0)
	_ = conDosPuntos
	_ = conVar
	_ = conVarios
	_ = otro
	_ = conPlazo
	_ = cancel
}
`
	archivo, err := parser.ParseFile(token.NewFileSet(), "sintetico.go", fuente, 0)
	if err != nil {
		t.Fatal(err)
	}
	sinPlazo := identificadoresSinPlazo(archivo)

	for _, quiero := range []string{"conDosPuntos", "conVar", "conVarios"} {
		if !sinPlazo[quiero] {
			t.Errorf("%q guarda un contexto sin plazo y la guarda no lo ve: un motor "+
				"lanzado con él se cuelga sin que nadie lo cace", quiero)
		}
	}
	if sinPlazo["conPlazo"] {
		t.Error("un context.WithTimeout se marcó como sin plazo: la guarda acusaría en falso")
	}
	if sinPlazo["cancel"] {
		t.Error("la función de cancelación no es un contexto")
	}
}
