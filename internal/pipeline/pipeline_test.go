package pipeline

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

type fakeEngine struct{ out []finding.Finding }

func (fakeEngine) Name() string               { return "fake" }
func (fakeEngine) Applies(engines.Input) bool { return true }
func (f fakeEngine) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	return f.out, nil
}

func mk(rule, file string, line int, blocking bool) finding.Finding {
	f := finding.Finding{Engine: "fake", RuleKey: rule, Pillar: finding.Quality,
		Severity: finding.Error, Blocking: blocking, File: file, Line: line,
		Message: rule, LineContent: rule, Source: finding.Deterministic}
	f.ComputeFingerprint()
	return f
}

func run(t *testing.T, opt Options) *Result {
	t.Helper()
	if opt.Config == nil {
		opt.Config = &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000}
	}
	if opt.Diff == nil {
		opt.Diff = &gitdiff.Diff{Files: []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}}}
	}
	res, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestConsolidaDeduplicaYOrdena(t *testing.T) {
	res := run(t, Options{Engines: []engines.Engine{fakeEngine{out: []finding.Finding{
		mk("dup", "a.go", 5, true),
		mk("dup", "a.go", 5, true), // duplicado exacto
		mk("aviso", "a.go", 1, false),
	}}}})
	if len(res.Findings) != 2 {
		t.Fatalf("esperaba 2 tras dedupe, hubo %d", len(res.Findings))
	}
	if !res.Findings[0].Blocking {
		t.Error("los bloqueantes van primero")
	}
	if res.Verdict != Block || res.BlockingFindings != 1 {
		t.Errorf("veredicto/conteo mal: %s %d", res.Verdict, res.BlockingFindings)
	}
}

func TestBaselineSuprimePeroNuncaSecretos(t *testing.T) {
	viejo := mk("viejo", "a.go", 5, true)
	secreto := mk("aws-key", "a.go", 7, true)
	secreto.Engine = "gitleaks"
	secreto.ComputeFingerprint()

	res := run(t, Options{
		Engines:      []engines.Engine{fakeEngine{out: []finding.Finding{viejo, secreto}}},
		Suppressions: map[string]bool{viejo.Fingerprint: true, secreto.Fingerprint: true},
	})
	if res.Suppressed != 1 {
		t.Errorf("debía suprimir solo el hallazgo viejo, suprimió %d", res.Suppressed)
	}
	if len(res.Findings) != 1 || res.Findings[0].Engine != "gitleaks" {
		t.Fatal("el secreto JAMÁS se suprime, aunque esté en la baseline")
	}
}

func TestAutoCalibracionDegradaPeroNuncaSecretos(t *testing.T) {
	ruidosa := mk("regla-ruidosa", "a.go", 5, true)
	secreto := mk("aws-key", "a.go", 7, true)
	secreto.Engine = "gitleaks"

	res := run(t, Options{
		Engines:      []engines.Engine{fakeEngine{out: []finding.Finding{ruidosa, secreto}}},
		DemotedRules: map[string]bool{"fake/regla-ruidosa": true, "gitleaks/aws-key": true},
	})
	var gotRuidosa, gotSecreto *finding.Finding
	for i := range res.Findings {
		switch res.Findings[i].RuleKey {
		case "regla-ruidosa":
			gotRuidosa = &res.Findings[i]
		case "aws-key":
			gotSecreto = &res.Findings[i]
		}
	}
	if gotRuidosa == nil || gotRuidosa.Blocking {
		t.Error("la regla ruidosa debía degradarse a aviso")
	}
	if gotSecreto == nil || !gotSecreto.Blocking {
		t.Error("gitleaks nunca se degrada, ni con feedback")
	}
}

func TestRepoNoEnrolado(t *testing.T) {
	res, err := Run(context.Background(), Options{Config: nil, Diff: &gitdiff.Diff{}})
	if err != nil || res.Verdict != Skipped {
		t.Fatalf("sin config = skipped, fue %v %v", res.Verdict, err)
	}
}

// Un motor ausente se reconoce por el SISTEMA DE ERRORES, no por el texto del
// mensaje. Antes se comparaba contra literales traducibles ("cannot find the
// file", "el sistema no puede encontrar"): en un Windows en francés o alemán
// esa comparación no casaba y un motor que simplemente no estaba instalado se
// reportaba como fallo del análisis, pintando de naranja commits sanos.
//
// Los dos caminos salen de medir con exec real, no de suponer:
//   - binario que no está en el PATH  → exec.ErrNotFound
//   - ruta absoluta inexistente       → *fs.PathError con fs.ErrNotExist
func TestMotorAusenteSeDetectaSinDependerDelIdioma(t *testing.T) {
	// Caminos reales: se ejecutan de verdad para no fiarse de un error fabricado.
	errPATH := exec.Command("binario-que-no-existe-jamas-cg.exe").Run()
	errRuta := exec.Command(filepath.Join(t.TempDir(), "no", "existe", "motor.exe")).Run()

	for nombre, err := range map[string]error{
		"no está en el PATH":    errPATH,
		"ruta absoluta ausente": errRuta,
	} {
		if err == nil {
			t.Fatalf("%s: se esperaba un error de ejecución", nombre)
		}
		if !isMissingBinary(err) {
			t.Errorf("%s: debía reconocerse como motor ausente y no lo hizo (%v)", nombre, err)
		}
	}

	// Y lo contrario: un motor que SÍ corrió y falló no es un motor ausente —
	// confundirlos escondería un fallo real detrás de "falta: X".
	corrioYFallo := errors.New("semgrep no llegó a analizar: raíz de escaneo inválida")
	if isMissingBinary(corrioYFallo) {
		t.Error("un motor que corrió y falló no puede reportarse como ausente")
	}
}
