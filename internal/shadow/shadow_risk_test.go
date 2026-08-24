package shadow

import (
	"testing"

	"codeguard/internal/config"
)

// RiskConfigHash versiona los PESOS: no depende del orden de las claves (un mapa
// no tiene orden) y cambia en cuanto cambia un peso. Es la mitad derivada de la
// identidad de la fórmula; la otra, el algoritmo, la lleva RiskFormulaVersion.
func TestRiskConfigHashDependeSoloDeLosPesos(t *testing.T) {
	con := func(w map[string]int) *config.Config {
		c := &config.Config{}
		c.Risk.Weights = w
		return c
	}
	base := RiskConfigHash(con(map[string]int{"touches_migration": 3, "ai_generated": 2}))

	// El mismo contenido en otro orden de inserción da la MISMA huella.
	otroOrden := RiskConfigHash(con(map[string]int{"ai_generated": 2, "touches_migration": 3}))
	if otroOrden != base {
		t.Error("el orden de las claves no puede cambiar la huella: un mapa no tiene orden")
	}

	// Cambiar un peso cambia la huella.
	if RiskConfigHash(con(map[string]int{"touches_migration": 9, "ai_generated": 2})) == base {
		t.Error("cambiar un peso debe cambiar la huella")
	}

	// Añadir un factor cambia la huella (pesos distintos).
	if RiskConfigHash(con(map[string]int{"touches_migration": 3, "ai_generated": 2, "nuevo": 1})) == base {
		t.Error("añadir un peso debe cambiar la huella")
	}
}

// La versión de la fórmula es explícita y positiva: existe para subirse a mano
// cuando el ALGORITMO cambie con los mismos pesos.
func TestRiskFormulaVersionEsExplicita(t *testing.T) {
	if RiskFormulaVersion < 1 {
		t.Errorf("RiskFormulaVersion debe ser un entero positivo, es %d", RiskFormulaVersion)
	}
}
