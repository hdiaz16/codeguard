package linters

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

func TestShellCheckAplicaSoloConScripts(t *testing.T) {
	con := func(p, st string) engines.Input {
		return engines.Input{Files: []gitdiff.ChangedFile{{Path: p, Status: st}}}
	}
	if (ShellCheck{}).Applies(con("main.go", "M")) {
		t.Error("sin .sh no debe aplicar")
	}
	if !(ShellCheck{}).Applies(con("deploy.sh", "M")) {
		t.Error("un .sh tocado debe hacer aplicar")
	}
	if !(ShellCheck{}).Applies(con("lib/util.bash", "M")) {
		t.Error(".bash también aplica")
	}
	if (ShellCheck{}).Applies(con("deploy.sh", "D")) {
		t.Error("un .sh borrado no aplica")
	}
}

// El parser mapea el JSON de shellcheck: code → SC####, level → severidad
// (error bloquea; warning/info/style avisan). NO pone LineContent.
func TestHallazgosShellCheckMapeaNivelYCodigo(t *testing.T) {
	raw := `[
	  {"file":"deploy.sh","line":2,"column":6,"level":"info","code":2086,"message":"Double quote to prevent globbing"},
	  {"file":"deploy.sh","line":3,"column":1,"level":"error","code":1073,"message":"Couldn't parse this"}
	]`
	fs, err := hallazgosShellCheck("repo", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos, obtuve %d", len(fs))
	}
	if fs[0].RuleKey != "SC2086" || fs[0].Blocking {
		t.Errorf("el info SC2086 no debe bloquear: %+v", fs[0])
	}
	if fs[1].RuleKey != "SC1073" || !fs[1].Blocking || fs[1].Severity != finding.Error {
		t.Errorf("el error SC1073 debe bloquear: %+v", fs[1])
	}
	for _, f := range fs {
		if f.Engine != "shellcheck" || f.File != "deploy.sh" || f.LineContent != "" {
			t.Errorf("engine/ruta/LineContent mal: %+v", f)
		}
	}
}

func TestHallazgosShellCheckVacioNoInventaNada(t *testing.T) {
	for _, s := range []string{"", "  ", "null", "[]"} {
		fs, err := hallazgosShellCheck("repo", s)
		if err != nil || len(fs) != 0 {
			t.Errorf("salida %q no debe dar hallazgos: err=%v fs=%+v", s, err, fs)
		}
	}
}

// Integración real: con shellcheck presente, caza el SC2086 de una variable sin
// comillas. Salta limpio sin la herramienta.
func TestIntegracionShellCheckCazaSC2086(t *testing.T) {
	if testing.Short() {
		t.Skip("lanza shellcheck: fuera del modo corto")
	}
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("sin shellcheck en esta máquina")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	raiz := t.TempDir()
	escribir(t, raiz, "scripts/run.sh", "#!/bin/sh\necho $HOME\n")
	fs, err := ShellCheck{}.Run(ctx, engines.Input{RepoRoot: raiz, Files: []gitdiff.ChangedFile{
		{Path: "scripts/run.sh", Status: "M"},
	}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var vio2086 bool
	for _, f := range fs {
		if f.RuleKey == "SC2086" && f.File == "scripts/run.sh" {
			vio2086 = true
		}
	}
	if !vio2086 {
		t.Errorf("debía cazar SC2086 (variable sin comillas); hallazgos: %+v", fs)
	}
}
