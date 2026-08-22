package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"sort"
	"strings"

	"github.com/gobwas/glob"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/engines/semgrep"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// capaDe clasifica UNA capa: qué le pasó al motor y cómo se le cuenta al dev.
func capaDe(motor, rulepack string, aplica bool, err error, hallazgos int, ms int64, motivoSinCorrer string) capas.Capa {
	c := capas.Capa{Motor: motor, Hallazgos: hallazgos, Ms: ms}
	switch {
	case err != nil && isMissingBinary(err):
		c.Estado, c.Detalle = capas.Ausente, "no está instalado en esta máquina"
	case err != nil:
		c.Estado = capas.Degradada
		switch {
		case errors.Is(err, semgrep.ErrSinRulepack):
			c.Detalle = "falta el rulepack " + rulepack + ": sin paridad con el CI"
		case errors.Is(err, context.DeadlineExceeded):
			c.Detalle = "no terminó dentro del plazo"
		default:
			c.Detalle = "falló al ejecutarse"
		}
	case aplica:
		c.Estado = capas.Corrio
	default:
		c.Estado, c.Detalle = capas.NoAplica, motivoSinCorrer
	}
	return c
}

// isMissingBinary distingue "la herramienta no está instalada" de "corrió y falló".
func isMissingBinary(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

// SoloFaltantes indica si todas las capas degradadas son motores ausentes (configuración).
func SoloFaltantes(degraded []string) bool {
	for _, d := range degraded {
		if !strings.HasPrefix(d, "falta:") {
			return false
		}
	}
	return len(degraded) > 0
}

// filterExcluded devuelve los archivos no excluidos y los patrones que no compilaron.
func filterExcluded(cfg *config.Config, files []gitdiff.ChangedFile) ([]gitdiff.ChangedFile, []string) {
	patterns := make([]glob.Glob, 0, len(cfg.Paths.Exclude)+len(cfg.Paths.Generated))
	var invalidos []string
	for _, p := range append(append([]string{}, cfg.Paths.Exclude...), cfg.Paths.Generated...) {
		if g, err := glob.Compile(p, '/'); err == nil {
			patterns = append(patterns, g)
		} else {
			invalidos = append(invalidos, p)
		}
	}
	var kept []gitdiff.ChangedFile
	for _, f := range files {
		excluded := false
		for _, g := range patterns {
			if g.Match(f.Path) {
				excluded = true
				break
			}
		}
		if !excluded {
			kept = append(kept, f)
		}
	}
	return kept, invalidos
}

// consolidate implementa la etapa 7: dedupe por (archivo, línea, regla) y orden por severidad.
func consolidate(fs []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		key := fmt.Sprintf("%s|%d|%s", f.File, f.Line, f.RuleKey)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	rank := map[finding.Severity]int{finding.Error: 0, finding.Warning: 1, finding.Info: 2}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Blocking != out[b].Blocking {
			return out[a].Blocking
		}
		if rank[out[a].Severity] != rank[out[b].Severity] {
			return rank[out[a].Severity] < rank[out[b].Severity]
		}
		if out[a].File != out[b].File {
			return out[a].File < out[b].File
		}
		return out[a].Line < out[b].Line
	})
	return out
}
