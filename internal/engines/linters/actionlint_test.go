package linters

import (
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

func TestEsWorkflowReconoceSoloLosDeActions(t *testing.T) {
	casos := []struct {
		ruta string
		si   bool
	}{
		{".github/workflows/ci.yml", true},
		{".github/workflows/nightly.yaml", true},
		{"sub/.github/workflows/deploy.yml", true},
		{".github/actions/build/action.yml", false}, // composite action, no workflow
		{"src/config.yml", false},
		{".github/workflows/README.md", false},
		{".github/dependabot.yml", false},
	}
	for _, c := range casos {
		if got := esWorkflow(c.ruta); got != c.si {
			t.Errorf("esWorkflow(%q) = %v, esperaba %v", c.ruta, got, c.si)
		}
	}
}

func TestActionLintAplicaSoloSiCambianWorkflows(t *testing.T) {
	con := func(fs ...gitdiff.ChangedFile) engines.Input {
		return engines.Input{Files: fs}
	}
	if (ActionLint{}).Applies(con(gitdiff.ChangedFile{Path: "main.go", Status: "M"})) {
		t.Error("sin workflows no debe aplicar")
	}
	if !(ActionLint{}).Applies(con(gitdiff.ChangedFile{Path: ".github/workflows/ci.yml", Status: "M"})) {
		t.Error("un workflow tocado debe hacer aplicar")
	}
	// Un workflow BORRADO no se analiza: ya no existe archivo que leer.
	if (ActionLint{}).Applies(con(gitdiff.ChangedFile{Path: ".github/workflows/ci.yml", Status: "D"})) {
		t.Error("un workflow borrado no debe hacer aplicar")
	}
}

// El parser mapea el JSON de actionlint a hallazgos: kind → RuleKey, la ruta
// relativa con '/', y bloqueante (actionlint no hace nits). NO pone LineContent:
// la línea real la lee AsignarHuellas (motor nuevo, nace en v2).
func TestHallazgosActionLintMapeaElJSON(t *testing.T) {
	raw := `[
	  {"message":"property \"foo\" is not defined","filepath":".github/workflows/ci.yml","line":10,"column":9,"kind":"expression","snippet":"x"},
	  {"message":"shellcheck reported issue in this script","filepath":".github/workflows/ci.yml","line":21,"column":9,"kind":"shellcheck","snippet":"run: echo ${{ github.event.issue.title }}"}
	]`
	fs, err := hallazgosActionLint("repo", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos, obtuve %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Engine != "actionlint" || !f.Blocking || f.Severity != finding.Error {
			t.Errorf("un hallazgo de actionlint bloquea y es error: %+v", f)
		}
		if f.File != ".github/workflows/ci.yml" {
			t.Errorf("File = %q, esperaba el workflow relativo", f.File)
		}
		if f.Message == "" {
			t.Error("sin Message el parser no dejó insumo para la huella")
		}
		if f.LineContent != "" {
			t.Errorf("el parser NO debe poner LineContent (lo hace AsignarHuellas): %q", f.LineContent)
		}
	}
	if fs[0].RuleKey != "expression" || fs[1].RuleKey != "shellcheck" {
		t.Errorf("el kind debe ser la RuleKey: %q, %q", fs[0].RuleKey, fs[1].RuleKey)
	}
}

func TestHallazgosActionLintSalidaVaciaNoInventaNada(t *testing.T) {
	for _, s := range []string{"", "  ", "null", "[]", "\n[]\n"} {
		fs, err := hallazgosActionLint("repo", s)
		if err != nil {
			t.Errorf("salida %q no debe dar error: %v", s, err)
		}
		if len(fs) != 0 {
			t.Errorf("salida %q no debe producir hallazgos: %+v", s, fs)
		}
	}
}
