package linters

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// GoFmt implementa la compuerta de formato para Go (§7: formato BLOQUEA —
// auto-corregible, cero ambigüedad).
type GoFmt struct{}

func (GoFmt) Name() string { return "gofmt" }

func (GoFmt) Applies(in engines.Input) bool { return len(filesWithExt(in, ".go")) > 0 }

func (GoFmt) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	files := filesWithExt(in, ".go")
	args := []string{"-l"}
	for _, f := range files {
		args = append(args, filepath.Join(in.RepoRoot, filepath.FromSlash(f.Path)))
	}
	out, err := runTool(ctx, in.RepoRoot, "gofmt", args...)
	if err != nil {
		return nil, fmt.Errorf("gofmt no corrió: %w", err)
	}
	var findings []finding.Finding
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		rel := relTo(in.RepoRoot, strings.TrimSpace(line))
		f := finding.Finding{
			Engine:      "gofmt",
			RuleKey:     "gofmt",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        rel,
			Line:        1,
			Message:     "Archivo sin formatear (gofmt)",
			Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
			FixHint:     "Ejecuta `gofmt -w " + rel + "` (es auto-corregible).",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: rel,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
