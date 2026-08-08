package linters

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// GoVet implementa la compuerta de lint de errores para Go (§7: lint severidad
// error BLOQUEA). Corre sobre los paquetes que contienen archivos tocados.
type GoVet struct{}

func (GoVet) Name() string { return "govet" }

func (GoVet) Applies(in engines.Input) bool {
	if len(filesWithExt(in, ".go")) == 0 {
		return false
	}
	_, err := os.Stat(filepath.Join(in.RepoRoot, "go.mod"))
	return err == nil
}

// formato: path.go:12:3: mensaje
var vetLine = regexp.MustCompile(`^(.+\.go):(\d+):(?:\d+:)?\s*(.+)$`)

func (GoVet) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	pkgs := map[string]bool{}
	for _, f := range filesWithExt(in, ".go") {
		dir := filepath.Dir(filepath.FromSlash(f.Path))
		pkgs["./"+filepath.ToSlash(dir)] = true
	}
	args := []string{"vet"}
	for p := range pkgs {
		args = append(args, p)
	}
	out, err := runTool(ctx, in.RepoRoot, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("go vet no corrió: %w", err)
	}
	var findings []finding.Finding
	for _, line := range strings.Split(out, "\n") {
		m := vetLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		lineNo, _ := strconv.Atoi(m[2])
		f := finding.Finding{
			Engine:      "govet",
			RuleKey:     "govet",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        filepath.ToSlash(m[1]),
			Line:        lineNo,
			Message:     m[3],
			Why:         "go vet solo reporta construcciones que son errores con alta certeza.",
			FixHint:     "Corrige el patrón señalado; go vet no produce falsos positivos intencionales.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: m[3],
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
