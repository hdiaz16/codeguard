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

func TestPSAnalyzerAplicaSoloConPS1(t *testing.T) {
	if (PSAnalyzer{}).Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "main.go", Status: "M"}}}) {
		t.Error("sin .ps1 no debe aplicar")
	}
	if !(PSAnalyzer{}).Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "tools/deploy.ps1", Status: "M"}}}) {
		t.Error("un .ps1 tocado debe hacer aplicar")
	}
}

// El parser mapea el JSON de PSScriptAnalyzer: RuleName → RuleKey, la ruta
// relativa, y la severidad numérica (Error/ParseError ≥ 2 bloquean; Warning
// avisa). NO pone LineContent (motor nuevo: lo hace AsignarHuellas).
func TestHallazgosPSSAMapeaSeveridadYRuta(t *testing.T) {
	raw := []byte(`[
	  {"RuleName":"PSAvoidUsingWriteHost","Severity":1,"Line":3,"Column":1,"Message":"usa Write-Host","ScriptPath":"scripts/deploy.ps1"},
	  {"RuleName":"PSAvoidUsingPlainTextForPassword","Severity":2,"Line":9,"Column":5,"Message":"password en claro","ScriptPath":"scripts/deploy.ps1"}
	]`)
	fs, err := hallazgosPSSA("repo", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos, obtuve %d", len(fs))
	}
	if fs[0].RuleKey != "PSAvoidUsingWriteHost" || fs[0].Blocking || fs[0].Severity != finding.Warning {
		t.Errorf("el Warning (sev 1) no debe bloquear: %+v", fs[0])
	}
	if fs[1].RuleKey != "PSAvoidUsingPlainTextForPassword" || !fs[1].Blocking || fs[1].Severity != finding.Error {
		t.Errorf("el Error (sev 2) debe bloquear: %+v", fs[1])
	}
	for _, f := range fs {
		if f.Engine != "psscriptanalyzer" || f.File != "scripts/deploy.ps1" {
			t.Errorf("engine/ruta mal: %+v", f)
		}
		if f.LineContent != "" {
			t.Errorf("el parser NO debe poner LineContent: %q", f.LineContent)
		}
	}
}

func TestHallazgosPSSAUnObjetoSueltoTambienCuenta(t *testing.T) {
	// ConvertTo-Json emite un objeto (no arreglo) cuando hay UN diagnóstico.
	raw := []byte(`{"RuleName":"PSUseDeclaredVarsMoreThanAssignments","Severity":1,"Line":1,"Column":1,"Message":"var sin usar","ScriptPath":"a.ps1"}`)
	fs, err := hallazgosPSSA("repo", raw)
	if err != nil || len(fs) != 1 {
		t.Fatalf("un objeto suelto debe dar 1 hallazgo: err=%v fs=%+v", err, fs)
	}
}

func TestHallazgosPSSAVacioNoInventaNada(t *testing.T) {
	for _, s := range [][]byte{[]byte(""), []byte("  "), []byte("null")} {
		fs, err := hallazgosPSSA("repo", s)
		if err != nil || len(fs) != 0 {
			t.Errorf("salida %q no debe dar hallazgos: err=%v fs=%+v", s, err, fs)
		}
	}
}

// Integración con la herramienta REAL: si están pwsh y el módulo, el motor
// caza el Write-Host de un .ps1 de juguete. Salta limpio cuando no están, para
// no teñir de rojo una máquina sin PowerShell.
func TestIntegracionPSAnalyzerCazaElWriteHost(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca PowerShell: fuera del modo corto")
	}
	bin := "pwsh"
	if _, err := exec.LookPath(bin); err != nil {
		if _, err := exec.LookPath("powershell"); err != nil {
			t.Skip("sin pwsh ni powershell en esta máquina")
		}
		bin = "powershell"
	}
	// ¿está el módulo? Sin él, el motor degrada (correcto) pero este test no
	// prueba lo que quiere; se salta con voz.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	chk := exec.CommandContext(ctx, bin, "-NoProfile", "-NonInteractive", "-Command",
		"if (Get-Module -ListAvailable PSScriptAnalyzer) { 'si' } else { 'no' }")
	out, _ := chk.Output()
	if string(out) == "" || out[0] != 's' {
		t.Skip("PSScriptAnalyzer no está instalado (Install-Module PSScriptAnalyzer)")
	}

	raiz := t.TempDir()
	escribir(t, raiz, "tools/deploy.ps1", "Write-Host 'hola'\n")
	fs, err := PSAnalyzer{}.Run(ctx, engines.Input{RepoRoot: raiz, Files: []gitdiff.ChangedFile{
		{Path: "tools/deploy.ps1", Status: "M"},
	}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var vioWriteHost bool
	for _, f := range fs {
		if f.RuleKey == "PSAvoidUsingWriteHost" && f.File == "tools/deploy.ps1" {
			vioWriteHost = true
		}
	}
	if !vioWriteHost {
		t.Errorf("con el módulo presente debía cazar PSAvoidUsingWriteHost; hallazgos: %+v", fs)
	}
}
