package linters

import (
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

func TestGosecApplies(t *testing.T) {
	g := Gosec{}
	if !g.Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "main.go"}}}) {
		t.Errorf("Gosec debe aplicar a archivos .go")
	}
	if g.Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "app.py"}}}) {
		t.Errorf("Gosec no debe aplicar a archivos .py")
	}
	if g.Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "main.go", Status: "D"}}}) {
		t.Errorf("Gosec no debe aplicar a archivos borrados")
	}
}

func TestGosecRecibePaquetesNoArchivos(t *testing.T) {
	got := paquetesGosec([]string{"main.go", "cmd/api/main.go", "cmd/api/routes.go", "-generado/x.go"})
	want := []string{".", "./cmd/api", "./-generado"}
	if len(got) != len(want) {
		t.Fatalf("paquetes=%v; esperaba %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paquetes=%v; esperaba %v", got, want)
		}
	}
}

func TestParseGosecJSON(t *testing.T) {
	raw := `{
		"Golang errors": {},
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"cwe": {
					"id": "89",
					"url": "https://cwe.mitre.org/data/definitions/89.html"
				},
				"rule_id": "G201",
				"details": "SQL string formatting",
				"file": "db/query.go",
				"code": "query := fmt.Sprintf(\"SELECT * FROM users WHERE id = '%s'\", id)",
				"line": "15",
				"column": "2"
			}
		],
		"Stats": {
			"files": 1,
			"lines": 30,
			"nosec": 0,
			"found": 1
		}
	}`

	findings, err := parseGosecJSON(raw, "C:/repo")
	if err != nil {
		t.Fatalf("parseGosecJSON error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, got: %d", len(findings))
	}

	f := findings[0]
	if f.Engine != "gosec" {
		t.Errorf("Engine = %q, want gosec", f.Engine)
	}
	if f.RuleKey != "G201" {
		t.Errorf("RuleKey = %q, want G201", f.RuleKey)
	}
	if f.Severity != finding.Error {
		t.Errorf("Severity = %q, want error", f.Severity)
	}
	if f.Line != 15 || f.EndLine != 15 {
		t.Errorf("Line/EndLine = %d/%d, want 15/15", f.Line, f.EndLine)
	}
	if f.Why == "" || f.FixHint == "" {
		t.Fatalf("Gosec debe entregar causa y corrección: %+v", f)
	}
}
