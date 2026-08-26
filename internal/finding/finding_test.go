package finding

import (
	"strings"
	"testing"
)

// El fingerprint es la clave de supresión y caché: si cambia entre versiones
// o entre máquinas, las baselines del equipo dejan de coincidir.
func TestFingerprintEstable(t *testing.T) {
	f := Finding{RuleKey: "ts-explicit-any", File: "src/lib/a.ts", Line: 10, LineContent: "  function f(x: any) {  "}
	got := f.ComputeFingerprint()
	// Prefijo del fingerprint real, medido contra este mismo caso. El valor que
	// habia antes ("b3a4d1") nunca coincidio: se declaraba como "verificado" y
	// se tiraba con `_ = want`, asi que la comprobacion jamas corrio.
	const want = "47e550c4fe4ce7cc"
	if len(got) != 64 {
		t.Fatalf("fingerprint debe ser sha256 hex (64), fue %d", len(got))
	}
	// mismo hallazgo con separadores Windows y espacios distintos = mismo fingerprint
	g := Finding{RuleKey: "ts-explicit-any", File: `src\lib\a.ts`, Line: 99, LineContent: "function f(x: any) {"}
	if g.ComputeFingerprint() != got {
		t.Errorf("el fingerprint debe ignorar separadores, espacios y número de línea:\n%s\n%s", got, g.Fingerprint)
	}
	// Este prefijo llevaba declarado desde el primer día y se tiraba con
	// `_ = want`, así que el valor grabado nunca se comprobó. Es la mitad que
	// importa del test: sin él, el fingerprint puede cambiar entre versiones
	// —invalidando las baselines de todo el equipo— sin que nada falle.
	if !strings.HasPrefix(got, want) {
		t.Errorf("el fingerprint grabado cambió: %s no empieza por %s.\n"+
			"Si el cambio es deliberado, las baselines existentes dejan de coincidir.", got, want)
	}
}

func TestFingerprintDistingueReglas(t *testing.T) {
	a := Finding{RuleKey: "r1", File: "x.go", LineContent: "code"}
	b := Finding{RuleKey: "r2", File: "x.go", LineContent: "code"}
	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Error("reglas distintas sobre la misma línea deben tener fingerprints distintos")
	}
}

func TestNormalizar(t *testing.T) {
	casos := []struct {
		nombre      string
		in          Finding
		wantLine    int
		wantEndLine int
	}{
		{"rango válido intacto", Finding{Line: 3, EndLine: 7}, 3, 7},
		{"endline cero se iguala", Finding{Line: 5, EndLine: 0}, 5, 5},
		{"rango invertido corregido", Finding{Line: 10, EndLine: 2}, 10, 10},
		{"puntual intacto", Finding{Line: 4, EndLine: 4}, 4, 4},
		{"negativos elevados", Finding{Line: -1, EndLine: -5}, 0, 0},
		{"cero válido", Finding{Line: 0, EndLine: 0}, 0, 0},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			f := c.in
			f.Normalizar()
			if f.Line != c.wantLine || f.EndLine != c.wantEndLine {
				t.Fatalf("Normalizar() = (%d, %d), want (%d, %d)",
					f.Line, f.EndLine, c.wantLine, c.wantEndLine)
			}
			if f.EndLine < f.Line {
				t.Fatalf("invariante violado: EndLine %d < Line %d", f.EndLine, f.Line)
			}
		})
	}
}

func TestHuellaCorta(t *testing.T) {
	const sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	casos := []struct {
		nombre string
		h      string
		n      int
		want   string
	}{
		{"corta estándar", sha, 8, "9f86d081"},
		{"huella vacía", "", 8, ""},
		{"n cero", sha, 0, ""},
		{"n negativo", sha, -1, ""},
		{"n mayor que longitud", "abc", 10, "abc"},
		{"n igual a longitud", "abc", 3, "abc"},
		{"huella corta real", "deadbeef", 12, "deadbeef"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := huellaCorta(c.h, c.n); got != c.want {
				t.Fatalf("huellaCorta(%q, %d) = %q, want %q", c.h, c.n, got, c.want)
			}
		})
	}
}
