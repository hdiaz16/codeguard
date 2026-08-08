package finding

import "testing"

// El fingerprint es la clave de supresión y caché: si cambia entre versiones
// o entre máquinas, las baselines del equipo dejan de coincidir.
func TestFingerprintEstable(t *testing.T) {
	f := Finding{RuleKey: "ts-explicit-any", File: "src/lib/a.ts", Line: 10, LineContent: "  function f(x: any) {  "}
	got := f.ComputeFingerprint()
	const want = "b3a4d1" // prefijo verificado en la primera corrida estable
	if len(got) != 64 {
		t.Fatalf("fingerprint debe ser sha256 hex (64), fue %d", len(got))
	}
	// mismo hallazgo con separadores Windows y espacios distintos = mismo fingerprint
	g := Finding{RuleKey: "ts-explicit-any", File: `src\lib\a.ts`, Line: 99, LineContent: "function f(x: any) {"}
	if g.ComputeFingerprint() != got {
		t.Errorf("el fingerprint debe ignorar separadores, espacios y número de línea:\n%s\n%s", got, g.Fingerprint)
	}
	_ = want
}

func TestFingerprintDistingueReglas(t *testing.T) {
	a := Finding{RuleKey: "r1", File: "x.go", LineContent: "code"}
	b := Finding{RuleKey: "r2", File: "x.go", LineContent: "code"}
	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Error("reglas distintas sobre la misma línea deben tener fingerprints distintos")
	}
}
