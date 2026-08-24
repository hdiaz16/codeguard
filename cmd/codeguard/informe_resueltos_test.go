package main

import (
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/pipeline"
)

// «RESUELTO» POR AUSENCIA, CON UNA CAPA QUE NO MIRÓ.
//
// Un hallazgo se daba por resuelto porque estaba en el informe anterior y ya no
// aparece. Una capa degradada produce esa misma ausencia sin que nadie toque el
// código, así que el informe marcaba con casilla `[x]` bugs intactos —en el
// mismo documento donde, un párrafo más arriba, admite que esa capa no corrió—.
//
// Medido en un repo de juguete: con staticcheck instalado, U1000 y SA4006
// salían pendientes; renombrando su binario, los DOS aparecían como resueltos.
//
// Y lo lee sobre todo un AGENTE decidiendo si queda trabajo.
func TestUnaCapaCaidaNoPuedeResolverNada(t *testing.T) {
	cfg := &config.Config{Rulepack: "2026.08.2"}
	res := &pipeline.Result{
		Verdict:  pipeline.Pass,
		Degraded: []string{"falta:staticcheck"},
	}
	// Lo que el llamador calcularía HOY: la sección de resueltos se calla y el
	// hueco se nombra.
	md := construirInforme(cfg, res, pipeline.Finalizar(res, "", nil).GarantiaRota, nil, nil,
		nil,                           // resueltos: ninguno, porque no se puede decir
		[]string{"falta:staticcheck"}, // el porqué
		nil, false, false, "")

	if strings.Contains(md, "Resueltos desde el informe anterior") {
		t.Error("con una capa caída no se puede afirmar que nada se resolvió, " +
			"y el informe lo estaba afirmando con casillas [x]")
	}
	if !strings.Contains(md, "No puedo decir qué se resolvió") {
		t.Error("el hueco tiene que NOMBRARSE: una sección que simplemente " +
			"desaparece se lee como «no había nada que resolver», que es la " +
			"misma ausencia que acabamos de dejar de tomar por buena")
	}
	if !strings.Contains(md, "falta:staticcheck") {
		t.Error("hay que decir QUÉ capa se cayó; «algo se degradó» no le sirve a nadie")
	}
}

// LA CONTRAPARTE, sin la cual lo de arriba no vale: con todas las capas sanas,
// los resueltos tienen que seguir saliendo. Un informe que nunca los muestre
// pasaría el test de arriba y le quitaría al agente su única señal de progreso.
func TestConLasCapasSanasLosResueltosSiguenSaliendo(t *testing.T) {
	cfg := &config.Config{Rulepack: "2026.08.2"}
	res := &pipeline.Result{Verdict: pipeline.Pass, Degraded: []string{}}
	md := construirInforme(cfg, res, pipeline.Finalizar(res, "", nil).GarantiaRota, nil, nil,
		[]string{"`U1000` — otro.go:7"}, nil, nil, false, false, "")

	if !strings.Contains(md, "Resueltos desde el informe anterior") {
		t.Fatal("con las capas sanas el informe tiene que poder decir qué se resolvió")
	}
	if !strings.Contains(md, "U1000") {
		t.Error("el resuelto concreto no aparece")
	}
	if strings.Contains(md, "No puedo decir qué se resolvió") {
		t.Error("no hay ninguna capa caída: sobra el aviso")
	}
}

// LA DECISIÓN, que es lo que de verdad hay que clavar. Los tests de arriba
// ejercitan el RENDERIZADO; éste ejercita el `if`. Sin él, quitar la condición
// entera de reportcmd.go dejaba los tres en verde.
func TestLaDecisionDeQuePuedeDeclararseResuelto(t *testing.T) {
	previos := map[string]string{
		"aaa": "`U1000` — otro.go:7",
		"bbb": "`SA4006` — otro.go:8",
	}
	// Ninguno de los dos aparece en esta corrida. La pregunta es POR QUÉ.
	actuales := map[string]bool{}

	casos := []struct {
		nombre    string
		degraded  []string
		resueltos int
		noSePuede int
	}{
		{"todas las capas sanas: ausencia = resuelto de verdad",
			nil, 2, 0},
		{"lista vacía, igual que la anterior",
			[]string{}, 2, 0},
		{"una capa CAÍDA: la ausencia ya no significa nada",
			[]string{"falta:staticcheck"}, 0, 1},
		{"un motor que falló",
			[]string{"staticcheck:error"}, 0, 1},
		{"sin el rulepack no corrieron las reglas de la casa",
			[]string{"rulepack-ausente:2026.08.2"}, 0, 1},
		{"degradación DELIBERADA: no tapa nada, o cualquier diff grande perdería su señal de progreso",
			[]string{"deterministic:diff_too_large"}, 2, 0},
		{"daemon apagado tampoco tapa",
			[]string{"daemon:offline"}, 2, 0},
		{"una deliberada y una rota juntas: manda la rota",
			[]string{"deterministic:diff_too_large", "falta:semgrep"}, 0, 1},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			// La derivación vive en el llamador (reportcmd deriva el outcome y
			// pasa GarantiaRota); aquí se emula esa frontera con el criterio
			// canónico — lo que este test fija es que las DELIBERADAS no tapan
			// resueltos y las ROTAS sí, a través de la pareja real.
			resueltos, noSePuede := calcularResueltos(previos, actuales, pipeline.SinGarantia(c.degraded))
			if len(resueltos) != c.resueltos {
				t.Errorf("resueltos = %d (%v), se esperaban %d", len(resueltos), resueltos, c.resueltos)
			}
			if len(noSePuede) != c.noSePuede {
				t.Errorf("capas que impiden decirlo = %d (%v), se esperaban %d",
					len(noSePuede), noSePuede, c.noSePuede)
			}
			// Nunca las dos cosas a la vez: o se puede afirmar, o no.
			if len(resueltos) > 0 && len(noSePuede) > 0 {
				t.Error("no puede afirmar y a la vez decir que no puede afirmar")
			}
		})
	}
}
