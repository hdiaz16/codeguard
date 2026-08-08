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

// Tsc implementa la compuerta de compilación de tipos para TS (§7: BLOQUEA).
// Requiere tsconfig.json en la raíz; usa --incremental para que las corridas
// calientes queden en presupuesto (spike S5). En Windows el CLI de npm es
// npx.cmd, no un .exe — de ahí la resolución explícita.
type Tsc struct{}

func (Tsc) Name() string { return "tsc" }

func (Tsc) Applies(in engines.Input) bool {
	if len(filesWithExt(in, ".ts")) == 0 && len(filesWithExt(in, ".tsx")) == 0 {
		return false
	}
	_, err := os.Stat(filepath.Join(in.RepoRoot, "tsconfig.json"))
	return err == nil
}

// formato --pretty false: src/mod7.ts(19,14): error TS2322: mensaje
var tscLine = regexp.MustCompile(`^(.+?)\((\d+),\d+\): error (TS\d+): (.+)$`)

func (Tsc) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := "npx"
	if _, err := os.Stat(filepath.Join(in.RepoRoot, "node_modules", ".bin", "tsc.cmd")); err == nil {
		bin = filepath.Join(in.RepoRoot, "node_modules", ".bin", "tsc.cmd")
	}
	var out string
	var err error
	if bin == "npx" {
		out, err = runTool(ctx, in.RepoRoot, "npx.cmd", "--no-install", "tsc", "--noEmit", "--incremental", "--pretty", "false")
	} else {
		out, err = runTool(ctx, in.RepoRoot, bin, "--noEmit", "--incremental", "--pretty", "false")
	}
	if err != nil {
		return nil, fmt.Errorf("tsc no corrió: %w", err)
	}
	var findings []finding.Finding
	for _, line := range strings.Split(out, "\n") {
		m := tscLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		lineNo, _ := strconv.Atoi(m[2])
		f := finding.Finding{
			Engine:      "tsc",
			RuleKey:     m[3],
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        filepath.ToSlash(m[1]),
			Line:        lineNo,
			Message:     m[4],
			Why:         "Un error de tipos es un error de compilación: el CI lo rechazará igual.",
			FixHint:     "Corrige el tipo señalado; el mensaje de tsc indica el tipo esperado y el recibido.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: m[3] + " " + m[4],
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
