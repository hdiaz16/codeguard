// Package linters agrupa las compuertas de formato, lint y tipos por lenguaje
// (sección 5 etapa 2, política de bloqueo en sección 7).
package linters

import (
	"path"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// filesWithExt devuelve los archivos vivos (no borrados) con la extensión dada.
func filesWithExt(in engines.Input, ext string) []gitdiff.ChangedFile {
	var out []gitdiff.ChangedFile
	for _, f := range in.Files {
		if f.Status != "D" && strings.EqualFold(path.Ext(f.Path), ext) {
			out = append(out, f)
		}
	}
	return out
}
