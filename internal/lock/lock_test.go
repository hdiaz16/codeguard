package lock

import (
	"bytes"
	"strings"
	"testing"
)

func ejemplo() Lock {
	return Lock{
		Schema:             Schema,
		CodeguardVersion:   "1.2.3",
		RulepackVersion:    "2026.08.3",
		RulepackDigest:     "aaaa",
		ConfigDigest:       "bbbb",
		BaselineDigest:     "cccc",
		RiskFormulaVersion: 1,
		RiskConfigHash:     "dddd",
	}
}

// La propiedad de la que depende que `lock --update` sin cambios no ensucie el
// diff: el mismo contenido serializa a los MISMOS bytes, siempre.
func TestBytesEsDeterminista(t *testing.T) {
	a, err := ejemplo().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ejemplo().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("dos serializaciones del mismo lock difieren:\n%s\n---\n%s", a, b)
	}
	if !bytes.HasSuffix(a, []byte("\n")) {
		t.Error("el lock debe terminar en salto de línea (archivo de texto POSIX)")
	}
}

// Escribir y Cargar es un viaje de ida y vuelta exacto; un repo sin lock es
// «todavía no hay», no un error.
func TestEscribirCargarRoundTrip(t *testing.T) {
	repo := t.TempDir()

	if _, hay, err := Cargar(repo); err != nil || hay {
		t.Fatalf("un repo sin lock debe dar (_, false, nil): hay=%v err=%v", hay, err)
	}

	quiero := ejemplo()
	if err := Escribir(repo, quiero); err != nil {
		t.Fatal(err)
	}
	tengo, hay, err := Cargar(repo)
	if err != nil || !hay {
		t.Fatalf("tras Escribir, Cargar debe encontrarlo: hay=%v err=%v", hay, err)
	}
	if tengo != quiero {
		t.Errorf("round-trip no exacto:\n  quiero %+v\n  tengo  %+v", quiero, tengo)
	}
}

// Cada entrada determinista que cambie —binario, rulepack (nombre o digest),
// config, baseline, fórmula o pesos— es un skew que Diferencias DEBE nombrar.
// Es el corazón de «bit-flip de baseline/motor/rulepack se detecta».
func TestDiferenciasDetectaCadaCampo(t *testing.T) {
	base := ejemplo()
	if d := Diferencias(base, base); len(d) != 0 {
		t.Fatalf("dos locks idénticos no tienen diferencias, salieron %v", d)
	}

	casos := []struct {
		nombre  string
		mutar   func(*Lock)
		enTexto string
	}{
		{"binario", func(l *Lock) { l.CodeguardVersion = "9.9.9" }, "codeguard"},
		{"rulepack versión", func(l *Lock) { l.RulepackVersion = "2027.01.1" }, "rulepack (versión)"},
		{"rulepack digest", func(l *Lock) { l.RulepackDigest = "ffff" }, "rulepack (digest)"},
		{"config", func(l *Lock) { l.ConfigDigest = "ffff" }, "config"},
		{"baseline", func(l *Lock) { l.BaselineDigest = "ffff" }, "baseline"},
		{"fórmula", func(l *Lock) { l.RiskFormulaVersion = 2 }, "fórmula de riesgo"},
		{"pesos", func(l *Lock) { l.RiskConfigHash = "ffff" }, "pesos de riesgo"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			otro := base
			c.mutar(&otro)
			d := Diferencias(base, otro)
			if len(d) != 1 {
				t.Fatalf("un solo campo cambió pero Diferencias reportó %d: %v", len(d), d)
			}
			if !strings.Contains(d[0], c.enTexto) {
				t.Errorf("la diferencia no nombra el campo %q: %q", c.enTexto, d[0])
			}
		})
	}
}

// Un lock de un schema que este binario no entiende se nombra como diferencia,
// no se ignora: la lección de siempre, lo desconocido no pasa por bueno.
func TestDiferenciasNombraElSchema(t *testing.T) {
	repo := ejemplo()
	repo.Schema = 999
	d := Diferencias(repo, ejemplo())
	if len(d) == 0 || !strings.Contains(d[0], "schema") {
		t.Errorf("un schema desconocido debe salir como diferencia: %v", d)
	}
}
