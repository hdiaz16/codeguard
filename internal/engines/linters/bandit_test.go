package linters

import (
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

func TestBanditApplies(t *testing.T) {
	b := Bandit{}
	if b.Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "main.go"}}}) {
		t.Errorf("Bandit no debe aplicar a archivos .go")
	}
	if !b.Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "app.py"}}}) {
		t.Errorf("Bandit debe aplicar a archivos .py")
	}
	if b.Applies(engines.Input{Files: []gitdiff.ChangedFile{{Path: "app.py", Status: "D"}}}) {
		t.Errorf("Bandit no debe aplicar a archivos borrados")
	}
}

func TestParseBanditJSON(t *testing.T) {
	raw := `{
		"errors": [],
		"generated_at": "2026-08-20T12:00:00Z",
		"results": [
			{
				"code": "2 eval('2 + 2')\n",
				"filename": "server/main.py",
				"issue_confidence": "HIGH",
				"issue_cwe": {
					"id": 95,
					"link": "https://cwe.mitre.org/data/definitions/95.html"
				},
				"issue_severity": "HIGH",
				"issue_text": "Use of possibly insecure function - consider using safer ast.literal_eval.",
				"line_number": 2,
				"line_range": [2],
				"more_info": "https://bandit.readthedocs.io/en/1.7.5/blacklists/blacklist_calls.html#b307-eval",
				"test_id": "B307",
				"test_name": "blacklisted_calls"
			}
		]
	}`

	findings, err := parseBanditJSON(raw, "C:/repo")
	if err != nil {
		t.Fatalf("parseBanditJSON error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, got: %d", len(findings))
	}

	f := findings[0]
	if f.Engine != "bandit" {
		t.Errorf("Engine = %q, want bandit", f.Engine)
	}
	if f.RuleKey != "B307" {
		t.Errorf("RuleKey = %q, want B307", f.RuleKey)
	}
	if f.Severity != finding.Error {
		t.Errorf("Severity = %q, want error", f.Severity)
	}
	if f.Line != 2 || f.EndLine != 2 {
		t.Errorf("Line/EndLine = %d/%d, want 2/2", f.Line, f.EndLine)
	}
}
