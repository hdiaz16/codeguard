package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// Ruff cubre dos compuertas de §7 para Python: lint de errores (ruff check,
// reglas por defecto E4/E7/E9/F que son errores genuinos → BLOQUEA) y
// formato (ruff format --check → BLOQUEA).
type Ruff struct {
	Binary string
}

func (Ruff) Name() string { return "ruff" }

func (Ruff) Applies(in engines.Input) bool { return len(filesWithExt(in, ".py")) > 0 }

type ruffDiag struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Filename string `json:"filename"`
	Location struct {
		Row int `json:"row"`
	} `json:"location"`
	Fix *struct {
		Message string `json:"message"`
	} `json:"fix"`
}

func (e Ruff) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "ruff"
	}
	var paths []string
	for _, f := range filesWithExt(in, ".py") {
		paths = append(paths, filepath.Join(in.RepoRoot, filepath.FromSlash(f.Path)))
	}

	var findings []finding.Finding

	// ── lint de errores ──
	checkOut, err := runTool(ctx, in.RepoRoot, bin, append([]string{"check", "--output-format", "json", "--exit-zero"}, paths...)...)
	if err != nil {
		return nil, fmt.Errorf("ruff no corrió: %w", err)
	}
	var diags []ruffDiag
	if jerr := json.Unmarshal([]byte(checkOut), &diags); jerr != nil {
		return nil, fmt.Errorf("salida de ruff ilegible: %v", jerr)
	}
	for _, d := range diags {
		fix := "Revisa la regla " + d.Code + " en la documentación de Ruff."
		if d.Fix != nil && d.Fix.Message != "" {
			fix = d.Fix.Message + " (auto-corregible con `ruff check --fix`)."
		}
		f := finding.Finding{
			Engine:      "ruff",
			RuleKey:     d.Code,
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        relTo(in.RepoRoot, d.Filename),
			Line:        d.Location.Row,
			Message:     d.Message,
			Why:         "Las reglas por defecto de Ruff (pyflakes + errores de sintaxis) son errores reales, no estilo.",
			FixHint:     fix,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: d.Code + " " + d.Message,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}

	// ── formato ──
	fmtOut, err := runTool(ctx, in.RepoRoot, bin, append([]string{"format", "--check"}, paths...)...)
	if err != nil {
		return nil, fmt.Errorf("ruff format no corrió: %w", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(fmtOut, "\n") {
		line = strings.TrimSpace(line)
		var target string
		switch {
		// ruff < 0.9: "Would reformat: path"
		case strings.HasPrefix(line, "Would reformat: "):
			target = strings.TrimPrefix(line, "Would reformat: ")
		// ruff moderno: "--> path:linea:col"
		case strings.HasPrefix(line, "--> "):
			target = strings.TrimPrefix(line, "--> ")
			if i := strings.Index(target, ".py:"); i >= 0 {
				target = target[:i+3]
			}
		default:
			continue
		}
		rel := relTo(in.RepoRoot, target)
		if seen[rel] {
			continue
		}
		seen[rel] = true
		f := finding.Finding{
			Engine:      "ruff",
			RuleKey:     "ruff-format",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        rel,
			Line:        1,
			Message:     "Archivo sin formatear (ruff format)",
			Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
			FixHint:     "Ejecuta `ruff format " + rel + "` (es auto-corregible).",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: rel,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
