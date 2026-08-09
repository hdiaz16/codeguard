package main

import (
	"path/filepath"
	"strings"

	"codeguard/internal/codegraph"
)

// buildOverlay proyecta el último análisis sobre el grafo: cada hallazgo se
// ancla a la función que lo contiene, y los archivos del diff marcan la zona
// tocada. El grafo deja de ser un mapa y se vuelve el radar del agente.
func buildOverlay(g *codegraph.Graph, p *panelPayload) *codegraph.Overlay {
	ov := &codegraph.Overlay{
		Repo:    p.Repo,
		Branch:  p.Branch,
		At:      p.At,
		Verdict: p.Verdict,
	}
	touched := map[string]bool{}
	for _, f := range p.Findings {
		file := filepath.ToSlash(f.File)
		id := g.NodeAt(file, f.Line)
		if id == "" {
			continue // hallazgo fuera de una función (config, sql suelto…)
		}
		ov.Findings = append(ov.Findings, codegraph.OverlayFinding{
			NodeID:   id,
			Pillar:   string(f.Pillar),
			Severity: string(f.Severity),
			Blocking: f.Blocking,
			Rule:     f.RuleKey,
			Message:  f.Message,
			File:     file,
			Line:     f.Line,
		})
		touched[id] = true
	}
	// además, toda función de un archivo tocado por el diff cuenta como zona activa
	changed := map[string]bool{}
	for _, f := range p.Findings {
		changed[filepath.ToSlash(f.File)] = true
	}
	for _, n := range g.Nodes {
		if n.Kind != "query" && changed[strings.TrimPrefix(n.File, "./")] {
			touched[n.ID] = true
		}
	}
	for id := range touched {
		ov.Touched = append(ov.Touched, id)
	}
	return ov
}
