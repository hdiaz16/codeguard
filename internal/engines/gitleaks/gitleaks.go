// Package gitleaks adapta el escáner de secretos (etapa 1, BLOQUEANTE, OFFLINE).
package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	// Binary es la ruta al ejecutable; si está vacío se busca en PATH.
	Binary string
	// Mode: "staged" (hook) o "range" (ci, requiere Base/Head).
	Mode string
	Base string
	Head string
}

func (e *Engine) Name() string { return "gitleaks" }

func (e *Engine) Applies(engines.Input) bool { return true }

// ErrUnavailable distingue "gitleaks no pudo correr" (fail-closed con mensaje
// de reparación, sección 14) de "corrió y no encontró nada".
var ErrUnavailable = errors.New("gitleaks no disponible")

type leak struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Match       string `json:"Match"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "gitleaks"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("%w: %v — ejecuta `codeguard repair`", ErrUnavailable, err)
	}

	report, err := os.CreateTemp("", "codeguard-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	report.Close()
	defer os.Remove(report.Name())

	// `protect` está deprecado desde 8.19: se usa `gitleaks git` (spec §5 etapa 1).
	args := []string{"git", "--redact", "--report-format", "json", "--report-path", report.Name(), "--exit-code", "9"}
	switch e.Mode {
	case "staged":
		args = append(args, "--pre-commit", "--staged")
	case "range":
		args = append(args, "--log-opts", e.Base+".."+e.Head)
	default:
		return nil, fmt.Errorf("%w: modo desconocido %q", ErrUnavailable, e.Mode)
	}
	args = append(args, in.RepoRoot)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Combinada()

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		return nil, nil // sin hallazgos
	case errors.As(runErr, &exitErr) && exitErr.ExitCode() == 9:
		// exit 9 = hallazgos (lo fijamos con --exit-code); cualquier otro código es error real
	default:
		return nil, fmt.Errorf("%w: %v: %s", ErrUnavailable, runErr, out)
	}

	raw, err := os.ReadFile(report.Name())
	if err != nil {
		return nil, fmt.Errorf("%w: sin reporte: %v", ErrUnavailable, err)
	}
	var leaks []leak
	if err := json.Unmarshal(raw, &leaks); err != nil {
		return nil, fmt.Errorf("%w: reporte ilegible: %v", ErrUnavailable, err)
	}

	findings := make([]finding.Finding, 0, len(leaks))
	for _, l := range leaks {
		f := finding.Finding{
			Engine:   "gitleaks",
			RuleKey:  l.RuleID,
			Pillar:   finding.Security,
			Severity: finding.Error,
			Blocking: true,
			File:     filepath.ToSlash(l.File),
			Line:     l.StartLine,
			EndLine:  l.EndLine,
			Message:  "Secreto detectado: " + l.Description,
			Why: "Un secreto commiteado queda en el historial de git para siempre. " +
				"Borrarlo del historial NO invalida la credencial: hay que rotarla primero.",
			FixHint:     "1) Rota la credencial en el proveedor. 2) Saca el valor a una variable de entorno o al gestor de secretos. 3) Vuelve a commitear.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: l.Match, // ya viene redactado por --redact
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
