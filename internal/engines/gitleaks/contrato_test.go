package gitleaks

import (
	"context"
	"errors"
	"testing"

	"codeguard/internal/engines"
)

// EL CONTRATO EN LA COMPUERTA QUE MÁS DAÑO HACE CUANDO CALLA.
//
// gitleaks es la etapa 1: bloqueante, offline, fail-closed, y lo único que
// decide si una credencial sale del portátil. Hasta el arreglo, su camino de
// éxito era `case runErr == nil: return nil, nil` — devolvía "limpio" por el
// solo hecho de que el proceso terminara con 0, sin abrir el reporte.
//
// Eso hace indistinguibles «gitleaks escaneó el índice y no hay secretos» de
// «lo que corrió no era gitleaks y terminó contento». La diferencia entre las
// dos es un secreto commiteado, y la segunda se anuncia en verde.
//
// La señal para separarlas ya estaba: gitleaks escribe --report-path SIEMPRE.
// Medido con 8.30.1 sobre un índice limpio: sale 0 y deja `[]`, tres bytes.
func TestCodigoCeroSinReporteEsAveriaYNoLimpio(t *testing.T) {
	repo := t.TempDir()
	e := &Engine{Binary: stubGitleaksModo(t, "mudo"), Mode: "staged"}

	hallazgos, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})

	if err == nil {
		t.Fatalf("una herramienta que sale con 0 sin escribir reporte NO puede pasar por "+
			"«limpio»: el motor devolvió %d hallazgo(s) y ningún error, que es exactamente "+
			"lo que el panel pinta de verde", len(hallazgos))
	}
	// Fail-closed (§14): el gancho bloquea SÓLO si el error viene envuelto en
	// ErrUnavailable. Sin el envoltorio, esto se degradaría a "capa naranja" y el
	// commit saldría igual — que es la mitad del fallo, no su arreglo.
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("sin ErrUnavailable la compuerta no bloquea y el secreto sale: %v", err)
	}
	if len(hallazgos) != 0 {
		t.Errorf("no puede inventar hallazgos cuando no pudo escanear: %d", len(hallazgos))
	}
}

// EL CONTROL, y no es opcional: sin él, un motor que devolviera error SIEMPRE
// pasaría la prueba de arriba con nota. Y el coste de equivocarse por este lado
// es peor que el de arriba en el día a día — la compuerta es fail-closed, así
// que un falso «no pude escanear» bloquea TODOS los commits del repo.
func TestCodigoCeroConReporteVacioSiEsLimpio(t *testing.T) {
	repo := t.TempDir()
	e := &Engine{Binary: stubGitleaksModo(t, "limpio"), Mode: "staged"}

	hallazgos, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})

	if err != nil {
		t.Fatalf("gitleaks escaneó y no encontró nada: eso es limpio, no avería. "+
			"Si esto falla, la compuerta bloquea cada commit del repo: %v", err)
	}
	if len(hallazgos) != 0 {
		t.Errorf("un reporte vacío no puede producir hallazgos: %d", len(hallazgos))
	}
}

// La otra mitad del control: el camino con hallazgos tiene que seguir llegando
// entero al veredicto. El arreglo movió la lectura del reporte al camino común
// de los códigos 0 y 9, y una lectura mal movida se ve igual que un repo limpio.
func TestReporteConSecretoDaHallazgoBloqueante(t *testing.T) {
	repo := t.TempDir()
	e := &Engine{Binary: stubGitleaksModo(t, "hallazgo"), Mode: "staged"}

	hallazgos, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})

	if err != nil {
		t.Fatalf("el código 9 es «encontré secretos», no una avería: %v", err)
	}
	if len(hallazgos) != 1 {
		t.Fatalf("se esperaba 1 hallazgo del reporte, hubo %d", len(hallazgos))
	}
	h := hallazgos[0]
	if !h.Blocking {
		t.Error("un secreto en el diff bloquea; si no, la etapa 1 no es una compuerta")
	}
	if h.File != "config/prod.yaml" || h.Line != 12 {
		t.Errorf("el sitio del secreto es lo único que viaja a la UI, y llegó mal: %s:%d",
			h.File, h.Line)
	}
	if h.Fingerprint == "" {
		t.Error("sin huella no se puede reconocer el mismo secreto entre corridas")
	}
}
