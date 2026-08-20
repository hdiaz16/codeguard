package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
)

// Bandit adapta el analizador de seguridad AST de Python (bandit)
// al contrato engines.Engine (Pilar 4: Cobertura de Élite en Python).
type Bandit struct {
	Binary string
	Cache  engines.Cache
}

func (Bandit) Name() string { return "bandit" }

func (Bandit) Applies(in engines.Input) bool {
	return len(filesWithExt(in, ".py")) > 0
}

type banditReport struct {
	Errors  []banditError  `json:"errors"`
	Results []banditResult `json:"results"`
}

type banditError struct {
	Filename string `json:"filename"`
	Reason   string `json:"reason"`
}

type banditResult struct {
	Code            string `json:"code"`
	Filename        string `json:"filename"`
	IssueConfidence string `json:"issue_confidence"`
	IssueCwe        struct {
		ID int `json:"id"`
	} `json:"issue_cwe"`
	IssueSeverity string `json:"issue_severity"`
	IssueText     string `json:"issue_text"`
	LineNumber    int    `json:"line_number"`
	TestID        string `json:"test_id"`
	TestName      string `json:"test_name"`
}

func (b Bandit) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := b.Binary
	if bin == "" {
		bin = "bandit"
	}

	archivos := filesWithExt(in, ".py")
	if len(archivos) == 0 {
		return nil, nil
	}

	var rutasRelativas []string
	for _, f := range archivos {
		rutasRelativas = append(rutasRelativas, f.Path)
	}

	sanitizadas := fsutil.SanitizarRutas(in.RepoRoot, rutasRelativas)
	if len(sanitizadas) == 0 {
		return nil, nil
	}

	args := []string{"-f", "json", "-q"}
	args = append(args, fsutil.ComoArgumentosCLI(sanitizadas)...)

	salida, fallo, err := runToolConSalida(ctx, in.RepoRoot, bin, args...)
	if err != nil {
		return nil, fmt.Errorf("bandit no corrió: %w", err)
	}

	findings, parseErr := parseBanditJSON(salida, in.RepoRoot)
	if parseErr != nil {
		return nil, parseErr
	}

	if len(findings) == 0 {
		if fallo {
			return nil, fmt.Errorf("bandit salió con error y no produjo diagnósticos: %s", strings.TrimSpace(salida))
		}
		if err := contrato.Identidad(ctx, contrato.Version("bandit", bin, "--version",
			regexp.MustCompile(`(?i)bandit`),
			"Instala bandit con `pip install bandit` o `pipx install bandit`.",
		)); err != nil {
			return nil, err
		}
	}

	return findings, nil
}

func parseBanditJSON(raw, repoRoot string) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" {
		return nil, nil
	}

	start := strings.Index(trimmed, "{")
	if start == -1 {
		return nil, fmt.Errorf("bandit: salida no contiene JSON: %q", raw)
	}
	trimmed = trimmed[start:]

	var report banditReport
	if err := json.Unmarshal([]byte(trimmed), &report); err != nil {
		return nil, fmt.Errorf("bandit: error al decodificar JSON: %w", err)
	}

	var findings []finding.Finding
	for _, res := range report.Results {
		relPath := res.Filename
		if filepath.IsAbs(relPath) {
			if rel, err := filepath.Rel(repoRoot, relPath); err == nil {
				relPath = rel
			}
		}
		relPath = filepath.ToSlash(relPath)

		sev := finding.Warning
		blocking := false
		if strings.EqualFold(res.IssueSeverity, "high") {
			sev = finding.Error
			blocking = true
		} else if strings.EqualFold(res.IssueSeverity, "medium") {
			sev = finding.Warning
		} else {
			sev = finding.Info
		}

		cweStr := ""
		if res.IssueCwe.ID > 0 {
			cweStr = fmt.Sprintf(" [CWE-%d]", res.IssueCwe.ID)
		}

		f := finding.Finding{
			Engine:      "bandit",
			RuleKey:     res.TestID,
			Pillar:      finding.Security,
			Severity:    sev,
			Blocking:    blocking,
			File:        relPath,
			Line:        res.LineNumber,
			EndLine:     res.LineNumber,
			Message:     res.IssueText + cweStr,
			LineContent: strings.TrimSpace(res.Code),
			Source:      finding.Deterministic,
		}
		f.Normalizar()
		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}
