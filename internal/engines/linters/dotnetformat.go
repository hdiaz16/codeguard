package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// DotnetFormat implementa la compuerta de formato para C# (§7: BLOQUEA).
// Requiere el SDK de .NET; si falta con archivos .cs tocados, el orquestador
// registra la capa como degradada.
type DotnetFormat struct{}

func (DotnetFormat) Name() string { return "dotnet-format" }

func (DotnetFormat) Applies(in engines.Input) bool {
	return len(filesWithExt(in, ".cs")) > 0
}

type dnfReport []struct {
	FilePath    string `json:"FilePath"`
	FileChanges []struct {
		LineNumber        int    `json:"LineNumber"`
		FormatDescription string `json:"FormatDescription"`
	} `json:"FileChanges"`
}

func (DotnetFormat) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	if _, err := exec.LookPath("dotnet"); err != nil {
		return nil, fmt.Errorf("SDK de .NET no disponible: %w", err)
	}
	report := filepath.Join(os.TempDir(), "codeguard-dnf.json")
	defer os.Remove(report)

	// El reporte JSON evita parsear la salida humana del comando.
	_, err := runTool(ctx, in.RepoRoot, "dotnet", "format", "--verify-no-changes", "--report", report)
	if err != nil {
		return nil, fmt.Errorf("dotnet format no corrió: %w", err)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		return nil, nil // sin reporte = sin cambios requeridos
	}
	var rep dnfReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("reporte de dotnet format ilegible: %v", err)
	}
	var findings []finding.Finding
	for _, file := range rep {
		for _, ch := range file.FileChanges {
			f := finding.Finding{
				Engine:      "dotnet-format",
				RuleKey:     "dotnet-format",
				Pillar:      finding.Quality,
				Severity:    finding.Error,
				Blocking:    true,
				File:        relTo(in.RepoRoot, file.FilePath),
				Line:        ch.LineNumber,
				Message:     ch.FormatDescription,
				Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
				FixHint:     "Ejecuta `dotnet format` (es auto-corregible).",
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: ch.FormatDescription,
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}
