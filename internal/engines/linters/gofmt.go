package linters

import (
	"bytes"
	"context"
	"fmt"
	"os"
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
		abs := strings.TrimSpace(line)
		// gofmt marca cualquier archivo con CRLF, y en Windows git deja CRLF
		// en el disco por autocrlf. Sin esta comprobación, un repo recién
		// clonado bloqueaba TODOS los commits que tocaran Go, `gofmt -w` los
		// "arreglaba" y git los revertía al siguiente checkout. Ademas rompia
		// la promesa central: en el CI pasaba y en local no.
		if soloFinalesDeLinea(ctx, in.RepoRoot, abs) {
			continue
		}
		rel := relTo(in.RepoRoot, abs)
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

// soloFinalesDeLinea dice si lo único que gofmt objeta del archivo son los
// CRLF. Se le pasa el contenido ya normalizado a LF por la entrada estándar y
// se compara con lo que devuelve: si coinciden, el formato del código es
// correcto y lo que sobra son los finales de línea.
//
// Los finales de línea son asunto de git (.gitattributes), no del formato del
// código: bloquear por ellos convertiría el agente en un obstáculo para
// cualquiera que trabaje en Windows.
func soloFinalesDeLinea(ctx context.Context, repoRoot, abs string) bool {
	raw, err := os.ReadFile(abs)
	if err != nil || !bytes.Contains(raw, []byte("\r\n")) {
		return false
	}
	normalizado := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	formateado, err := runToolStdin(ctx, repoRoot, "gofmt", normalizado)
	if err != nil || len(formateado) == 0 {
		return false // ante la duda, se reporta: es una compuerta bloqueante
	}
	return bytes.Equal(bytes.TrimRight(formateado, "\n"), bytes.TrimRight(normalizado, "\n"))
}
