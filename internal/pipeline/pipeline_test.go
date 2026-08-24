package pipeline

import (
	"context"
	"errors"
	"fmt"
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

// La regla de ambigüedad de las huellas v2, en la superficie que decide: dos
// hallazgos indistinguibles (mismo texto, mismo contexto — aquí sin fuente de
// líneas, así que sin ancla) comparten huella, y NINGUNO se suprime aunque la
// baseline traiga esa huella: baselinear uno enterraría al otro en silencio.
func TestLosAmbiguosNoSeSuprimenNiConLaBaselineEnMano(t *testing.T) {
	uno := mk("regla-x", "a.go", 5, true)
	otro := mk("regla-x", "a.go", 9, true) // mismo contenido, otra línea
	res := run(t, Options{
		Engines: []engines.Engine{fakeEngine{out: []finding.Finding{uno, otro}}},
		// La baseline trae la v1 de ambos (idéntica: en v1 ya colapsaban) — y
		// también colapsan en v2 sin ancla, que es lo que los hace ambiguos.
		Suppressions: map[string]bool{uno.Fingerprint: true},
	})
	if res.Suppressed != 0 {
		t.Errorf("se suprimieron %d hallazgos AMBIGUOS: aceptar uno enterró al otro", res.Suppressed)
	}
	if len(res.Findings) != 2 {
		t.Errorf("los dos ambiguos deben seguir a la vista, quedaron %d", len(res.Findings))
	}
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

// Un motor que no cupo en el plazo NO es un motor que falló. La diferencia
// importa porque cambia lo que el desarrollador hace al leerlo: "error" lo
// manda a buscar una avería, "plazo" le dice que la primera corrida en frío
// fue cara y la siguiente irá con caché.
//
// Pasó de verdad tras una instalación limpia: staticcheck y eslint salieron
// etiquetados como error, y en la corrida siguiente tardaron 502 ms y 610 ms.
// Y el motivo viajaba perdido: proc.Correr formateaba el context.DeadlineExceeded
// con %v en vez de %w, así que aquí no había forma de distinguirlo sin comparar
// textos traducibles.
func TestElPlazoAgotadoNoSeReportaComoError(t *testing.T) {
	in := engines.Input{RepoRoot: t.TempDir(), Files: []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}}}
	cfg := &config.Config{RepoRoot: in.RepoRoot, MaxDiffLines: 10000}

	lento := &motorFalso{nombre: "lento", err: fmt.Errorf(
		"lento no terminó: plazo agotado: el motor no terminó a tiempo: %w", context.DeadlineExceeded)}
	roto := &motorFalso{nombre: "roto", err: errors.New("salida ilegible")}

	res, err := Run(context.Background(), Options{
		Config: cfg, Diff: &gitdiff.Diff{Files: in.Files}, Engines: []engines.Engine{lento, roto},
	})
	if err != nil {
		t.Fatalf("un motor degradado nunca tumba el pipeline: %v", err)
	}
	tiene := func(etiqueta string) bool {
		for _, d := range res.Degraded {
			if d == etiqueta {
				return true
			}
		}
		return false
	}
	if !tiene("lento:plazo") {
		t.Errorf("el que se pasó de tiempo debe etiquetarse como plazo, llegó %v", res.Degraded)
	}
	if !tiene("roto:error") {
		t.Errorf("el que falló de verdad sigue siendo error, llegó %v", res.Degraded)
	}
}

// motorFalso es un Engine que siempre falla con el error dado.
type motorFalso struct {
	nombre string
	err    error
}

func (m *motorFalso) Name() string               { return m.nombre }
func (m *motorFalso) Applies(engines.Input) bool { return true }
func (m *motorFalso) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	return nil, m.err
}
