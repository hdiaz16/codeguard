package main

import (
	"encoding/json"
	"strings"
	"testing"

	"codeguard/internal/daemon"
)

// El panel tiene que distinguir «esta capa le toca a tu repo» de «esta capa
// puede correr en esta máquina».
//
// Durante meses solo contestaba la primera: decía «tu repo: 3 capas lo
// vigilan» aunque tsc no estuviera instalado. daemon.Disponibilidad existía
// desde entonces —escrita, probada y documentada sobre una medición de 10
// repos reales, donde 5 sobre-declaraban— y no la llamaba NADIE. El 3 de un
// repo de TypeScript sin tsc es peor que un 2, porque no se puede desmentir
// mirando. Se cableó el 2026-08-25.
//
// Se comprueba el fuente del panel y no un render, igual que el resto de las
// pruebas de esta pestaña: la vista es JavaScript embebido y lo que se vigila
// es que siga MIRANDO el dato.
func TestElPanelMiraLasCapasQueNoPuedenCorrer(t *testing.T) {
	html := leerPanel(t)

	i := strings.Index(html, "function fichaHTML")
	if i < 0 {
		t.Fatal("no encuentro fichaHTML: esta prueba dejó de vigilar la pestaña Proyecto")
	}
	fin := strings.Index(html[i:], "\n  function dato(")
	if fin < 0 {
		t.Fatal("no encuentro el final de fichaHTML")
	}
	ficha := html[i : i+fin]
	if !strings.Contains(ficha, "no_disponibles") {
		t.Error("fichaHTML no mira p.no_disponibles: el panel vuelve a prometer capas que " +
			"esta máquina no puede ejecutar")
	}
	if !strings.Contains(ficha, "no puede correr aquí") {
		t.Error("la ficha no dice en palabras que una capa no puede correr aquí")
	}

	// Y la cabecera: el número de capas no debe incluir las que no pueden.
	if !strings.Contains(html, "delRepo.length - sinPoder.length") {
		t.Error("la cabecera cuenta TODAS las capas del repo, incluidas las que no pueden " +
			"correr: ese número promete una vigilancia que no existe")
	}
}

// El contrato de datos: NoDisponible tiene que viajar al panel con el motivo,
// no solo con el nombre. Sin el motivo, el dev sabe que algo falla y no qué
// hacer, que es la mitad inútil del aviso.
func TestNoDisponibleViajaConSuMotivo(t *testing.T) {
	ficha := &panelPayload{
		Repo: "portal-cliente", RepoRoot: "c:/repos/portal-cliente",
		CapasRepo: []string{"semgrep", "tsc", "gofmt"},
		NoDisponibles: []daemon.NoDisponible{
			{Motor: "tsc", Falta: "npx", Motivo: "no encuentro npx — instala Node.js"},
		},
	}
	b, err := json.Marshal(ficha)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, quiero := range []string{`"no_disponibles"`, `"tsc"`, `"npx"`, "instala Node.js"} {
		if !strings.Contains(js, quiero) {
			t.Errorf("el payload del panel no lleva %s:\n%s", quiero, js)
		}
	}

	// Sin faltantes, el campo NO viaja: el caso normal no gasta ni un byte de
	// cable ni un píxel de aviso.
	sano := &panelPayload{Repo: "api-go", CapasRepo: []string{"gofmt", "govet"}}
	b2, err := json.Marshal(sano)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b2), "no_disponibles") {
		t.Errorf("sin capas faltantes el campo no debe viajar: %s", b2)
	}
}
