package daemon

import (
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines"
)

// Toda capa del pipeline tiene su política de red DECLARADA en el registro
// (W4, Q4): un motor nuevo que no declare corre frenado (RedDe cae a
// denegado), pero este test exige la declaración EXPLÍCITA — el fail-closed
// silencioso del registro es la red de seguridad, no la licencia para no
// declarar. Itera los motores REALES del pipeline, no una copia de la lista.
func TestTodaCapaDeclaraSuRed(t *testing.T) {
	cfg := &config.Config{}
	explicitos := 0
	for _, eng := range Engines(cfg, false, nil) {
		nombre := eng.Name()
		switch engines.RedDe(nombre) {
		case engines.RedDenegada, engines.RedSoloActualizar, engines.RedRequerida:
			explicitos++
		default:
			t.Errorf("el motor %s tiene una política de red desconocida", nombre)
		}
	}
	// gitleaks corre en la etapa 1 (no está en Engines) pero también declara.
	if engines.RedDe("gitleaks") != engines.RedDenegada {
		t.Error("gitleaks debía declarar red denegada")
	}
	if explicitos < 15 {
		t.Fatalf("solo %d motores pasaron por el registro: la lista del pipeline cambió y este test ya no la cubre", explicitos)
	}
}
