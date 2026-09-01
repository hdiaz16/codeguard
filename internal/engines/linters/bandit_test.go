package linters

import (
	"context"
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

	findings, errores, err := parseBanditJSON(raw, "C:/repo")
	if err != nil {
		t.Fatalf("parseBanditJSON error: %v", err)
	}
	if len(errores) != 0 {
		t.Fatalf("errores inesperados: %+v", errores)
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
	if f.Why == "" || f.FixHint == "" {
		t.Fatalf("Bandit debe entregar causa y corrección: %+v", f)
	}
}

func TestBanditHaceVisibleLaCoberturaParcial(t *testing.T) {
	raw := `{"errors":[{"filename":"b.py","reason":"syntax error"}],"results":[{"code":"eval(x)","filename":"a.py","issue_severity":"HIGH","issue_text":"eval inseguro","line_number":1,"test_id":"B307"}]}`
	findings, errores, err := parseBanditJSON(raw, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(errores) != 1 || errores[0].Filename != "b.py" {
		t.Fatalf("Bandit debe conservar hallazgos y errores por archivo: findings=%+v errors=%+v", findings, errores)
	}
	pendientes := []gitdiff.ChangedFile{{Path: "a.py", SHA256: "a"}, {Path: "b.py", SHA256: "b"}}
	completos, recibos := coberturaBandit(pendientes, findings, errores)
	if len(completos) != 1 || completos[0].Path != "a.py" {
		t.Fatalf("sólo a.py puede cachearse; completos=%+v", completos)
	}
	if len(recibos) != 2 || recibos[0].Estado != engines.CoberturaCompleta || recibos[1].Estado != engines.CoberturaParcial {
		t.Fatalf("la cobertura por archivo no refleja el error de b.py: %+v", recibos)
	}
}

type cacheBanditPrueba struct {
	datos     map[string][]finding.Finding
	guardadas []engines.Cacheable
}

func (c *cacheBanditPrueba) Leer(claves []string) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, k := range claves {
		if fs, ok := c.datos[k]; ok {
			out[k] = fs
		}
	}
	return out
}

func (c *cacheBanditPrueba) Guardar(entradas []engines.Cacheable) {
	c.guardadas = append(c.guardadas, entradas...)
}

func TestBanditSirveUnHitSinInvocarElBinario(t *testing.T) {
	const sha = "abc123"
	cache := &cacheBanditPrueba{datos: map[string][]finding.Finding{
		claveBandit("app.py", sha): {{
			Engine: "bandit", RuleKey: "B307", File: "app.py", Message: "eval",
			Pillar: finding.Security, Severity: finding.Error, Source: finding.Deterministic,
			LineContent: "eval(x)",
		}},
	}}
	b := Bandit{Binary: "bandit-que-no-existe", Cache: cache}
	res, err := b.RunConCobertura(context.Background(), engines.Input{
		RepoRoot: t.TempDir(),
		Files:    []gitdiff.ChangedFile{{Path: "app.py", SHA256: sha}},
	})
	if err != nil {
		t.Fatalf("un hit completo no debe invocar el binario ausente: %v", err)
	}
	if len(res.Findings) != 1 || len(res.Recibos) != 1 || res.Recibos[0].Estado != engines.CoberturaCompleta {
		t.Fatalf("hit de Bandit incompleto: %+v", res)
	}
}
