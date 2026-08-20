package main

import (
	"path/filepath"
	"strings"

	"codeguard/internal/codegraph"
)

// buildOverlay proyecta el último análisis sobre el grafo: cada hallazgo se
// ancla a la función que lo contiene, y los archivos del diff marcan la zona
// tocada, hayan salido limpios o no. El grafo deja de ser un mapa y se vuelve
// el radar del agente.
//
// La zona salía SÓLO de p.Findings, así que un archivo que el commit tocó y
// pasó limpio no iluminaba nada: el radar enseñaba dónde dolió, no dónde se
// trabajó. El dato existía —el gancho manda StagedFiles en el Request— pero se
// perdía al construir el payload; ahora llega en p.ChangedFiles.
//
// La zona es la UNIÓN del diff y de los archivos con hallazgos, no sólo el
// diff: el aviso de secreto bloqueado (escritorio.go, comando
// "secreto-bloqueado") llega SIN StagedFiles —el gancho manda ahí únicamente el
// sitio de cada secreto, hook.go:384— y con el diff a secas ese panel habría
// perdido la luz que hoy sí tiene. La unión también cubre al hallazgo que no
// vive en el diff (baseline, motor de repo).
func buildOverlay(g *codegraph.Graph, p *panelPayload) *codegraph.Overlay {
	// Los slices arrancan vacíos, no nil: un nil se serializa como `null` y el
	// explorador reventaba al iterarlo.
	ov := &codegraph.Overlay{
		Repo:     p.Repo,
		Branch:   p.Branch,
		At:       p.At,
		Verdict:  p.Verdict,
		Findings: []codegraph.OverlayFinding{},
		Touched:  []string{},
	}
	touched := map[string]bool{}
	for _, f := range p.Findings {
		file := normPath(f.File)
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
	// además, toda función de un archivo del diff —o de uno con hallazgos, ver
	// el porqué de la unión en el doc de arriba— cuenta como zona activa
	changed := map[string]bool{}
	for _, r := range p.ChangedFiles {
		changed[normPath(r)] = true
	}
	for _, f := range p.Findings {
		changed[normPath(f.File)] = true
	}
	for _, n := range g.Nodes {
		if n.Kind != "query" && changed[normPath(n.File)] {
			touched[n.ID] = true
		}
	}
	for id := range touched {
		ov.Touched = append(ov.Touched, id)
	}
	return ov
}

// normPath deja toda ruta en UN solo criterio —barras normales y sin el "./"
// de delante— para que las claves de changed, las rutas del grafo y las de los
// hallazgos coincidan siempre. Había tres normalizaciones distintas y bastaba
// que un lado trajera "./" o barras invertidas para que la comparación fallara
// en silencio: la función tocada simplemente no se marcaba, sin ningún error.
func normPath(ruta string) string {
	return strings.TrimPrefix(filepath.ToSlash(ruta), "./")
}
