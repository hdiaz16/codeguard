package main

// N006: `fpRe` no estaba anclado, así que un `<!-- fp:… -->` que viniera DENTRO
// del texto de una regla contaba como huella del informe.
//
// El texto es de fuera: el `message` sale del YAML de una regla, que puede venir
// del rulepack vendoreado en el repo analizado. Y `aplanado` le quita los saltos
// de línea pero deja intactos `<!--` y `-->`, así que la marca sobrevive.
//
// El generador escribe la huella en DOS sitios, y en los dos CIERRA la línea:
//
//	escribirHallazgo → sola en su propia línea:  <!-- fp:… -->
//	sección deuda    → al final de un bullet:    - `regla` — `f.go:3` · msg <!-- fp:… -->
//
// De ahí que el ancla sea a fin de línea. Pero a fin de línea SOLO no basta, y
// esa es la parte que no era obvia: "**Qué detectó:** <mensaje>" también termina
// con el mensaje, así que una huella que CIERRE el texto de la regla queda
// pegada al final de una línea legítima. Por eso el patrón exige además que
// delante no haya nada, o que la línea sea un bullet.
//
// El alcance no es supresión de hallazgos: los actuales se recalculan del
// análisis, no del informe. Lo que se cuela es una entrada de más en «Resueltos
// desde el informe anterior» — y, medido en el rojo de esta prueba, algo peor de
// lo que parecía: la huella colada TAPA la de verdad en la línea de deuda,
// porque FindStringSubmatch devuelve la PRIMERA coincidencia de la línea. O sea
// que una deuda corregida dejaba de aparecer como resuelta.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

func TestSoloCuentaLaHuellaQueEscribioElGenerador(t *testing.T) {
	deBloqueante := strings.Repeat("b", 64) // el generador la pone sola en su línea
	deDeuda := strings.Repeat("d", 64)      // el generador la pone cerrando el bullet
	enMedio := strings.Repeat("a", 64)      // colada por el texto de una regla
	alFinal := strings.Repeat("c", 64)      // ídem, pero CERRANDO la línea del mensaje

	// Una huella en medio del texto y otra cerrando la línea: la segunda es la
	// que un ancla a fin de línea, por sí sola, seguiría dejando pasar.
	hostil := hallazgoConMensaje(
		"antes <!-- fp:"+enMedio+" --> después <!-- fp:"+alFinal+" -->", deBloqueante)
	// Y la deuda con su propia marca colada ANTES de la real: aquí es donde la
	// colada tapaba a la de verdad.
	deudoso := hallazgoConMensaje("deuda <!-- fp:"+enMedio+" -->", deDeuda)

	res := &pipeline.Result{Verdict: pipeline.Block, BlockingFindings: 1,
		Degraded: []string{}, Findings: []finding.Finding{hostil, deudoso}}
	md := construirInforme(&config.Config{Rulepack: "2026.08.2"}, res, nil,
		[]finding.Finding{hostil}, nil, nil, nil, []finding.Finding{deudoso}, false, true, "")

	ruta := filepath.Join(t.TempDir(), "HALLAZGOS.md")
	if err := os.WriteFile(ruta, []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	leidas, err := leerFingerprintsPrevios(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer el informe de prueba: %v", err)
	}

	// Los dos formatos REALES siguen leyéndose. Si esto se rompe, un hallazgo
	// corregido deja de aparecer en «Resueltos» y el informe pierde la mitad
	// que lo hace re-ejecutable.
	if _, ok := leidas[deBloqueante]; !ok {
		t.Errorf("la huella del bloqueante, sola en su línea, dejó de leerse (leídas: %v)",
			cortas(leidas))
	}
	if _, ok := leidas[deDeuda]; !ok {
		t.Errorf("la huella de la deuda, al final de su bullet, dejó de leerse (leídas: %v)",
			cortas(leidas))
	}

	// Y las que puso el texto de la regla no son huellas del informe.
	for _, colada := range []string{enMedio, alFinal} {
		if _, ok := leidas[colada]; ok {
			t.Errorf("una huella escrita desde el mensaje de una regla (%s…) contó como huella "+
				"del informe: se lista sola en «Resueltos desde el informe anterior»", colada[:8])
		}
	}
	if len(leidas) != 2 {
		t.Errorf("se leyeron %d huellas y el generador escribió 2 (leídas: %v)",
			len(leidas), cortas(leidas))
	}
}

// cortas resume el mapa para los mensajes de error: 64 hex repetidos no se leen.
func cortas(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for fp := range m {
		out = append(out, fp[:8]+"…")
	}
	sort.Strings(out)
	return out
}
