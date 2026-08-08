// Package semgrep adapta Semgrep CE con el rule pack de la casa (etapa 2).
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string // vacío = buscar en PATH
}

func (e *Engine) Name() string { return "semgrep" }

func (e *Engine) Applies(in engines.Input) bool {
	for _, f := range in.Files {
		if f.Status != "D" {
			return true
		}
	}
	return false
}

type sgResult struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Metadata struct {
				Pillar  string `json:"pillar"`
				Why     string `json:"why"`
				FixHint string `json:"fix_hint"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "semgrep"
	}
	rules := filepath.Join(in.RulepackDir, "semgrep")
	if _, err := os.Stat(rules); err != nil {
		return nil, fmt.Errorf("rulepack sin reglas semgrep en %s: %w", rules, err)
	}

	// Solo archivos tocados (sección 5, etapa 2): targets explícitos.
	args := []string{"scan", "--config", rules, "--json", "--metrics=off", "--quiet", "--disable-version-check"}
	targets := 0
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		args = append(args, filepath.Join(in.RepoRoot, filepath.FromSlash(f.Path)))
		targets++
	}
	if targets == 0 {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	out, runErr := cmd.Output()
	// Semgrep sale con 1 cuando hay hallazgos bloqueantes; el JSON sigue siendo válido.
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("semgrep no corrió: %v", runErr)
	}

	var res sgResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("salida de semgrep ilegible: %v", err)
	}

	findings := make([]finding.Finding, 0, len(res.Results))
	for _, r := range res.Results {
		sev := finding.Warning
		if strings.EqualFold(r.Extra.Severity, "ERROR") {
			sev = finding.Error
		}
		pillar := finding.Quality
		switch strings.ToLower(r.Extra.Metadata.Pillar) {
		case "security":
			pillar = finding.Security
		case "data":
			pillar = finding.Data
		}
		rel, err := filepath.Rel(in.RepoRoot, r.Path)
		if err != nil {
			rel = r.Path
		}
		f := finding.Finding{
			Engine:  "semgrep",
			RuleKey: shortRuleID(r.CheckID),
			Pillar:  pillar,
			// Política de compuertas §7: semgrep ERROR bloquea, WARNING avisa.
			Severity:    sev,
			Blocking:    sev == finding.Error,
			File:        filepath.ToSlash(rel),
			Line:        r.Start.Line,
			EndLine:     r.End.Line,
			Message:     r.Extra.Message,
			Why:         r.Extra.Metadata.Why,
			FixHint:     r.Extra.Metadata.FixHint,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: firstLine(r.Extra.Lines),
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

// shortRuleID recorta el prefijo de ruta que semgrep antepone al id de la regla.
func shortRuleID(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
