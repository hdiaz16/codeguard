package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"codeguard/internal/pipeline"
)

// N004 — la última puerta por la que el orbe podía volver a mentir.
//
// El resto de la remediación dejó orbStateFor como el único sitio donde se
// decide el color del orbe. La demo del menú lo saltaba entero: era la única
// forma de ponerlo en cualquier estado en cualquier momento, y venía en el build
// que se instala en la máquina de un desarrollador.
func TestLaDemoDeEstadosNoViajaEnElProducto(t *testing.T) {
	// Se mira el CÓDIGO FUENTE y no la constante de este build, y es a propósito:
	// bajo -tags codeguard_demo la constante vale true legítimamente, así que
	// afirmar sobre ella haría fallar un build válido; y en el build por defecto
	// vale false por construcción, así que afirmarlo no descubriría nada. Lo que
	// de verdad hay que impedir es que la entrada del menú vuelva a vivir en un
	// archivo SIN la etiqueta, que es exactamente como llegó la primera vez.
	//
	// Es el mismo enfoque que TestTodoGitDeLaCLIPasaPorGitCmd: cortar la
	// reincidencia accidental leyendo el árbol, sin pretender resistir a quien
	// quiera rodearlo.
	const marca = "Demo de estados"
	fset := token.NewFileSet()
	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entradas {
		nombre := ent.Name()
		if !strings.HasSuffix(nombre, ".go") || strings.HasSuffix(nombre, "_test.go") {
			continue
		}
		crudo, err := os.ReadFile(nombre)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(crudo), marca) {
			continue
		}
		// Este archivo monta la entrada del menú: exige la etiqueta.
		archivo, err := parser.ParseFile(fset, nombre, crudo, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", nombre, err)
		}
		if !tieneEtiqueta(archivo, "codeguard_demo") {
			t.Errorf("%s monta la entrada «%s» y NO lleva `//go:build codeguard_demo`.\n"+
				"Esa entrada conduce el orbe a estados inventados durante 12 s y tapa un "+
				"bloqueo real; el orbe es un indicador de seguridad y esta sería la única "+
				"ruta que no pasa por orbStateFor.\n"+
				"Si hace falta para desarrollar, que viva detrás de la etiqueta.", nombre, marca)
		}
	}
}

// tieneEtiqueta busca `//go:build <etiqueta>` entre los comentarios de cabecera.
func tieneEtiqueta(archivo *ast.File, etiqueta string) bool {
	for _, grupo := range archivo.Comments {
		for _, c := range grupo.List {
			if strings.HasPrefix(c.Text, "//go:build") && strings.Contains(c.Text, etiqueta) {
				return true
			}
		}
	}
	return false
}

// Y la contraparte de la etiqueta: que el menú de producción no la ofrezca.
//
// Se comprueba sobre el método y no sobre el menú de Wails porque construir el
// menú exige una aplicación viva; lo que importa es que en este build la función
// que añade la entrada no añada ninguna, y eso sí se puede afirmar sin ventanas.
func TestElMenuDeProduccionNoAnadeLaEntradaDeDemo(t *testing.T) {
	if demoDeEstadosCompilada {
		t.Skip("build de depuración: aquí la entrada SÍ debe existir")
	}
	// El menú de verdad se construye con e.app vivo. Basta con que la llamada no
	// haga nada: en producción anadirDemoDeEstados tiene cuerpo vacío, así que
	// pasarle un menú nil no puede explotar. Si alguien le pusiera cuerpo sin
	// quitar la etiqueta, esto lo delataría con un panic.
	e := &escritorio{}
	e.anadirDemoDeEstados(nil)
}

// Reponer el orbe tiene que decir la VERDAD, no volver a un idle de cortesía.
//
// El final de la demo era `set("idle", "demo terminada")`, y eso dejaba la
// bandeja mintiendo hasta el siguiente análisis —sin límite de tiempo—. Aunque
// la demo ya no viaje, la reposición se usa desde el build de depuración y es la
// pieza que impide que el problema vuelva en otra forma.
func TestReponerElOrbeRecalculaLaVerdadYNoUnIdleDeCortesia(t *testing.T) {
	casos := []struct {
		nombre string
		p      *panelPayload
		quiero string
	}{
		// Los payloads llevan el Outcome derivado, como los deja
		// construirPayload: el orbe LEE, no re-deriva (turnos 61-68).
		{"un bloqueo real sigue viéndose", &panelPayload{
			Repo: "portal", Branch: "master", Verdict: "block", Outcome: "blocked", Blocking: 1}, "blocked"},
		{"un análisis omitido sigue sin afirmar nada", &panelPayload{
			Repo: "portal", Branch: "master", Verdict: "skipped", Outcome: "skipped",
			Reason: pipeline.MotivoTodoExcluido}, "idle"},
		{"una avería sigue pidiendo que se mire", &panelPayload{
			Repo: "portal", Branch: "master", Verdict: "skipped", Outcome: "skipped",
			Reason: pipeline.MotivoNoEnrolado}, "degraded"},
		{"un pass limpio sigue en verde", &panelPayload{
			Repo: "portal", Branch: "master", Verdict: "pass", Outcome: "clean"}, "pass"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			e, _ := escritorioDePrueba(nil)
			tray, g := bandejaDePrueba(20 * time.Millisecond)
			e.tray = tray
			e.activo = c.p

			e.reponerOrbe()

			u := g.ultima(t)
			if u.estado != c.quiero {
				t.Errorf("reponer dejó el orbe en %q y el estado real es %q", u.estado, c.quiero)
			}
			if strings.Contains(u.tooltip, "demo") {
				t.Errorf("el tooltip quedó hablando de la demo: %q", u.tooltip)
			}
			// El tooltip tiene que ser el mismo que se vería sin demo de por
			// medio: reponer no puede inventarse una frase propia.
			if quiero := tooltipDelOrbe(c.p); u.tooltip != quiero {
				t.Errorf("reponer escribió un tooltip propio:\n  llegó:  %q\n  quería: %q", u.tooltip, quiero)
			}
		})
	}
}

// Sin ningún análisis todavía, reponer no puede afirmar nada.
func TestReponerElOrbeSinAnalisisNoAfirmaNada(t *testing.T) {
	e, _ := escritorioDePrueba(nil)
	tray, g := bandejaDePrueba(20 * time.Millisecond)
	e.tray = tray

	e.reponerOrbe()

	u := g.ultima(t)
	if u.estado == "pass" {
		t.Errorf("sin ningún análisis el orbe quedó en verde (tooltip %q): "+
			"afirma una revisión limpia que no ha ocurrido", u.tooltip)
	}
	if u.estado != "idle" {
		t.Errorf("sin análisis se esperaba «idle» y llegó %q", u.estado)
	}
}
