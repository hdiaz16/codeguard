package main

import (
	"testing"
	"time"

	"codeguard/internal/store"
)

// El umbral DOBLE de la síntesis (Q3): recurrente = 2 corridas seguidas;
// persistente = 5 seguidas O ≥2 durante más de 24 h. Una racha vieja pero corta
// escala igual que una nueva pero larga — las dos son «esto ya no es un
// tropiezo».
func TestClaseDeRachaAplicaElUmbralDoble(t *testing.T) {
	ahora := time.Now()
	casos := []struct {
		nombre string
		sc     store.SaludCapa
		quiere string
	}{
		{"dos seguidas y recientes", store.SaludCapa{RachaFallos: 2, PrimerFallo: ahora.Add(-time.Hour)}, "recurrente"},
		{"cinco seguidas aunque nuevas", store.SaludCapa{RachaFallos: 5, PrimerFallo: ahora}, "persistente"},
		{"dos seguidas pero de hace más de 24h", store.SaludCapa{RachaFallos: 2, PrimerFallo: ahora.Add(-25 * time.Hour)}, "persistente"},
		{"tres seguidas, jóvenes y por debajo de cinco", store.SaludCapa{RachaFallos: 3, PrimerFallo: ahora.Add(-2 * time.Hour)}, "recurrente"},
		{"justo en el borde de 24h sigue recurrente", store.SaludCapa{RachaFallos: 2, PrimerFallo: ahora.Add(-23 * time.Hour)}, "recurrente"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := claseDeRacha(c.sc); got != c.quiere {
				t.Errorf("claseDeRacha(racha=%d, edad=%s) = %q, esperaba %q",
					c.sc.RachaFallos, time.Since(c.sc.PrimerFallo).Round(time.Hour), got, c.quiere)
			}
		})
	}
}

// La antigüedad se dice en palabras y solo cuando hay fecha de inicio: una
// racha sin inicio no inventa una edad.
func TestAntiguedadDeRachaSoloConFecha(t *testing.T) {
	if got := antiguedadDeRacha(store.SaludCapa{RachaFallos: 3}); got != "" {
		t.Errorf("sin PrimerFallo no debe decir antigüedad: %q", got)
	}
	if got := antiguedadDeRacha(store.SaludCapa{RachaFallos: 3, PrimerFallo: time.Now().Add(-48 * time.Hour)}); got == "" {
		t.Error("con PrimerFallo debe decir hace cuánto")
	}
}
