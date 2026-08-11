package linters

import (
	"bytes"
	"context"
	"go/format"
	"os"
	"path/filepath"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// GoFmt implementa la compuerta de formato para Go (§7: formato BLOQUEA —
// auto-corregible, cero ambigüedad).
//
// No ejecuta el binario gofmt: usa go/format, que ES gofmt como librería.
// La versión anterior lanzaba `gofmt -l` y, por cada archivo con CRLF, otro
// gofmt por stdin para distinguir "mal formateado" de "sólo finales de línea"
// — en un repo Windows recién clonado eso son cientos de procesos bajo el
// sandbox (~6 s medidos) para responder que todo estaba bien. En proceso son
// milisegundos, no hay binario que pueda faltar, y la paridad con el CI queda
// por construcción: el CI corre este mismo código.
type GoFmt struct{}

func (GoFmt) Name() string { return "gofmt" }

func (GoFmt) Applies(in engines.Input) bool { return len(filesWithExt(in, ".go")) > 0 }

func (GoFmt) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var findings []finding.Finding
	for _, cf := range filesWithExt(in, ".go") {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		raw, err := os.ReadFile(filepath.Join(in.RepoRoot, filepath.FromSlash(cf.Path)))
		if err != nil {
			continue // borrado entre el diff y aquí; no hay nada que formatear
		}
		// Los finales de línea son asunto de git (.gitattributes), no del
		// formato: en Windows autocrlf deja CRLF en disco y bloquear por eso
		// convertiría el agente en un obstáculo. Se compara normalizado a LF.
		normalizado := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
		formateado, err := format.Source(normalizado)
		if err != nil {
			// No parsea como Go: eso lo señala govet/el compilador con un
			// mensaje mejor que el nuestro. El formato no es el problema.
			continue
		}
		if bytes.Equal(bytes.TrimRight(formateado, "\n"), bytes.TrimRight(normalizado, "\n")) {
			continue
		}
		f := finding.Finding{
			Engine:      "gofmt",
			RuleKey:     "gofmt",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        cf.Path,
			Line:        1,
			Message:     "Archivo sin formatear (gofmt)",
			Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
			FixHint:     "Ejecuta `gofmt -w " + cf.Path + "` (es auto-corregible).",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: cf.Path,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
