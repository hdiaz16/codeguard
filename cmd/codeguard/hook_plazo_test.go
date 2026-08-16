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
		if !esContextBackground(llamada.Args[0]) {
			return true
		}
		culpables = append(culpables, fset.Position(llamada.Pos()).String())
		return true
	})

	if len(culpables) > 0 {
		t.Errorf("hay %d motor(es) lanzados con context.Background() en el gancho, "+
			"o sea sin tope: si el binario se cuelga, el commit del usuario no vuelve nunca.\n  %s",
			len(culpables), strings.Join(culpables, "\n  "))
	}
}

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
