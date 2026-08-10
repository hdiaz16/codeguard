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
