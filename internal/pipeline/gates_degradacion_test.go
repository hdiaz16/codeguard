package pipeline

import (
	"errors"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines"
)

func TestRunBloqueaCuandoSemgrepObligatorioFalla(t *testing.T) {
	cfg := &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000,
		Gates: config.Gates{SemgrepError: "block"}}
	res := run(t, Options{Config: cfg, Engines: []engines.Engine{
		&motorFalso{nombre: "semgrep", err: errors.New("core roto")},
	}})
	if res.Verdict != Block || res.BlockingFindings != 0 {
		t.Fatalf("verdict=%q bloqueantes=%d degradadas=%v", res.Verdict, res.BlockingFindings, res.Degraded)
	}
	if o := Finalizar(res, "", nil); !o.Bloquea() || o.Estado != Bloqueado {
		t.Fatalf("outcome=%+v; la política no llegó al veredicto canónico", o)
	}
}

func TestSemgrepDegradadoRespetaSuGate(t *testing.T) {
	for _, degradacion := range []string{
		"semgrep:error", "semgrep:plazo", "semgrep:cobertura-parcial",
		"falta:semgrep", "rulepack-ausente:2026.08.3",
	} {
		cfg := &config.Config{Gates: config.Gates{SemgrepError: "block"}}
		if !bloqueaDegradacionSemgrep(cfg, []string{degradacion}) {
			t.Errorf("%q no bloqueó aunque semgrep_error=block", degradacion)
		}
	}
}

func TestSemgrepDegradadoNoInventaUnBloqueoSiLaPoliticaNoLoPide(t *testing.T) {
	for _, gate := range []string{"", "warn"} {
		cfg := &config.Config{Gates: config.Gates{SemgrepError: gate}}
		if bloqueaDegradacionSemgrep(cfg, []string{"semgrep:error"}) {
			t.Errorf("semgrep:error bloqueó con gate %q", gate)
		}
	}
	if bloqueaDegradacionSemgrep(&config.Config{Gates: config.Gates{SemgrepError: "block"}}, []string{"gosec:error"}) {
		t.Fatal("la política de Semgrep bloqueó por la caída de otro motor")
	}
}
