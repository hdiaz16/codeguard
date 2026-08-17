package pipeline

import (
	"strings"
	"testing"
)

// EL CONTROL Y SU CONTRARIO, en la misma tabla y a propósito: un criterio que
// dijera "todo rompe la garantía" pasaría los casos de arriba y arruinaría el
// CI de todo el mundo; uno que dijera "nada la rompe" es el agujero que
// estamos cerrando. Sólo la tabla entera prueba algo.
func TestQueDegradacionesRompenLaGarantia(t *testing.T) {
	casos := []struct {
		nombre   string
		degraded []string
		rompe    bool
	}{
		// ── las que SÍ: había algo que mirar y no se miró ──
		{"rulepack ausente (el medido: deja pasar una inyección SQL)",
			[]string{"rulepack-ausente:9999.99.99"}, true},
		{"un motor no está instalado en el runner",
			[]string{"falta:semgrep"}, true},
		{"un motor falló al ejecutarse",
			[]string{"staticcheck:error"}, true},
		{"un motor no terminó en el plazo",
			[]string{"semgrep:plazo"}, true},
		{"mezcla: una deliberada y una rota, gana la rota",
			[]string{"deterministic:diff_too_large", "rulepack-ausente:2026.08.2"}, true},

		// ── las que NO: política deliberada del producto ──
		{"diff demasiado grande es una decisión anunciada, no una avería",
			[]string{"deterministic:diff_too_large"}, false},
		{"daemon apagado sólo existe en el gancho, y allí se analiza igual",
			[]string{"daemon:offline"}, false},
		{"migración sin vigilar es aviso de configuración (decisión de N011)",
			[]string{"squawk:migracion-sin-vigilar"}, false},
		{"sin degradaciones",
			nil, false},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			rotas := SinGarantia(c.degraded)
			if got := len(rotas) > 0; got != c.rompe {
				t.Errorf("SinGarantia(%v) rompe=%v, se esperaba %v (devolvió %v)",
					c.degraded, got, c.rompe, rotas)
			}
		})
	}
}

// Una etiqueta deliberada que un día acabe en ":error" no puede romper el job
// por accidente: la lista de deliberadas manda sobre los sufijos genéricos.
// Sin este orden, renombrar una etiqueta interna pondría en rojo a todo el
// mundo sin que nadie hubiera decidido nada.
func TestLasDeliberadasGananALosSufijosGenericos(t *testing.T) {
	for _, d := range []string{"deterministic:diff_too_large", "daemon:offline", "squawk:migracion-sin-vigilar"} {
		if !esPoliticaDeliberada(d) {
			t.Errorf("%q dejó de estar en la lista de deliberadas: si alguien la renombró, "+
				"revisa que el cambio sea intencionado — rompe jobs ajenos", d)
		}
	}
}

// El mensaje tiene que nombrar la capa concreta. "Algo se degradó" no le sirve
// a nadie a las 3 de la mañana mirando un log de CI.
func TestLaCapaRotaViajaEnElResultado(t *testing.T) {
	rotas := SinGarantia([]string{"rulepack-ausente:2026.08.2", "daemon:offline", "trivy:error"})
	junto := strings.Join(rotas, " ")
	for _, quiero := range []string{"rulepack-ausente:2026.08.2", "trivy:error"} {
		if !strings.Contains(junto, quiero) {
			t.Errorf("falta %q en %v", quiero, rotas)
		}
	}
	if strings.Contains(junto, "daemon:offline") {
		t.Errorf("daemon:offline no debería viajar como capa rota: %v", rotas)
	}
}
