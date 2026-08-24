package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"sort"

	"github.com/gobwas/glob"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/engines/semgrep"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// coberturaResumen es el resultado de cruzar el PLAN de un motor con sus
// recibos: cuántas unidades prometió, cuántas completaron y cuáles quedaron a
// medias o sin mirar. Nil para los motores todo-o-nada (no declaran cobertura).
type coberturaResumen struct {
	Planeadas int
	Completas int
	Parciales int
	Omitidas  int
	Rotas     []engines.Unidad // las que no completaron, para nombrarlas en el detalle
}

// hayHueco dice si la capa dejó cobertura sin completar: cualquier unidad
// planeada a medias o sin mirar rompe la garantía de esa capa.
func (r *coberturaResumen) hayHueco() bool {
	return r != nil && (r.Parciales > 0 || r.Omitidas > 0)
}

// resumirCobertura cruza el plan contra los recibos. La identidad de una unidad
// es (Clase, Ruta). Una unidad planeada SIN recibo cuenta como omitida (el
// adaptador prometió mirarla y no dejó prueba de haberlo hecho); un recibo
// parcial u omitido cuenta como hueco aunque el proceso saliera con éxito.
func resumirCobertura(plan []engines.Unidad, recibos []engines.Recibo) *coberturaResumen {
	if len(plan) == 0 {
		// Un motor que declara cobertura pero no planeó nada para esta entrada
		// no tiene hueco que reportar (no había objetivos suyos en el cambio).
		return &coberturaResumen{}
	}
	porUnidad := make(map[engines.Unidad]engines.EstadoCobertura, len(recibos))
	for _, rec := range recibos {
		// Si un objetivo llega dos veces, el peor estado manda: un «parcial» no
		// se borra con un «completo» posterior del mismo objetivo. El primer
		// recibo se toma tal cual (no se compara contra el cero del mapa, que
		// significa «sin recibo» y no «cobertura nula»).
		if prev, ya := porUnidad[rec.Unidad]; ya {
			porUnidad[rec.Unidad] = peorCobertura(prev, rec.Estado)
		} else {
			porUnidad[rec.Unidad] = rec.Estado
		}
	}
	r := &coberturaResumen{Planeadas: len(plan)}
	for _, u := range plan {
		switch porUnidad[u] {
		case engines.CoberturaCompleta:
			r.Completas++
		case engines.CoberturaParcial:
			r.Parciales++
			r.Rotas = append(r.Rotas, u)
		default: // sin recibo o "skipped": la unidad no se llegó a cubrir
			r.Omitidas++
			r.Rotas = append(r.Rotas, u)
		}
	}
	return r
}

// peorCobertura ordena los estados de menor a mayor cobertura para quedarse con
// el peor: omitida < parcial < completa. El cero ("" sin recibo) es lo peor.
func peorCobertura(a, b engines.EstadoCobertura) engines.EstadoCobertura {
	rango := func(e engines.EstadoCobertura) int {
		switch e {
		case engines.CoberturaCompleta:
			return 2
		case engines.CoberturaParcial:
			return 1
		default:
			return 0
		}
	}
	if rango(a) <= rango(b) {
		return a
	}
	return b
}

// capaDe clasifica UNA capa: qué le pasó al motor y cómo se le cuenta al dev.
func capaDe(motor, rulepack string, aplica bool, err error, hallazgos int, ms int64, motivoSinCorrer string, cob *coberturaResumen) capas.Capa {
	c := capas.Capa{Motor: motor, Hallazgos: hallazgos, Ms: ms}
	if cob != nil {
		c.Planeadas, c.Completas, c.Parciales = cob.Planeadas, cob.Completas, cob.Parciales+cob.Omitidas
	}
	switch {
	case err != nil && isMissingBinary(err):
		c.Estado, c.Detalle, c.MotivoCodigo = capas.Ausente, "no está instalado en esta máquina", "no-instalado"
	case err != nil:
		c.Estado = capas.Degradada
		switch {
		case errors.Is(err, semgrep.ErrSinRulepack):
			c.Detalle, c.MotivoCodigo = "falta el rulepack "+rulepack+": sin paridad con el CI", "rulepack-ausente"
		case errors.Is(err, context.DeadlineExceeded):
			c.Detalle, c.MotivoCodigo = "no terminó dentro del plazo", "plazo"
		default:
			c.Detalle, c.MotivoCodigo = "falló al ejecutarse", "error"
		}
	case cob.hayHueco():
		// Corrió y devolvió hallazgos, pero NO cubrió todo lo que prometió: es
		// «había algo que mirar y no se miró del todo». Se degrada con nombres,
		// no se sirve un limpio sobre lo no analizado (W6 Q2).
		c.Estado = capas.Degradada
		c.Detalle, c.MotivoCodigo = detalleCobertura(cob), "cobertura-parcial"
	case aplica:
		c.Estado = capas.Corrio
	default:
		c.Estado, c.Detalle = capas.NoAplica, motivoSinCorrer
	}
	return c
}

// detalleCobertura arma el texto humano del hueco: cuántas de cuántas y el
// primer objetivo afectado, que es lo que el dev necesita para ir a mirarlo.
func detalleCobertura(cob *coberturaResumen) string {
	rotas := cob.Parciales + cob.Omitidas
	msg := fmt.Sprintf("cobertura incompleta: %d de %d objetivo(s) sin analizar del todo", rotas, cob.Planeadas)
	if len(cob.Rotas) > 0 {
		u := cob.Rotas[0]
		msg += fmt.Sprintf(" (%s: %s", u.Clase, u.Ruta)
		if rotas > 1 {
			msg += fmt.Sprintf(", +%d más", rotas-1)
		}
		msg += ")"
	}
	return msg
}

// isMissingBinary distingue "la herramienta no está instalada" de "corrió y falló".
func isMissingBinary(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
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
