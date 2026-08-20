package main

import (
	"testing"

	"codeguard/internal/codegraph"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
)

func grafoDeDosArchivos() *codegraph.Graph {
	return &codegraph.Graph{Nodes: []codegraph.Node{
		{ID: "demo.Sucia", File: "a.go", Line: 1, Kind: "func"},
		{ID: "demo.Limpia", File: "b.go", Line: 1, Kind: "func"},
		{ID: "demo.Ajena", File: "c.go", Line: 1, Kind: "func"},
	}}
}

func encendidas(ov *codegraph.Overlay) map[string]bool {
	m := map[string]bool{}
	for _, id := range ov.Touched {
		m[id] = true
	}
	return m
}

// La zona activa la marca el DIFF, no sólo los hallazgos: un archivo que el
// commit tocó y salió limpio tiene que encender sus funciones igual que el que
// falló. Antes se derivaba de p.Findings y el radar enseñaba dónde dolió, no
// dónde se trabajó.
func TestLaZonaActivaIluminaLosArchivosLimpiosDelDiff(t *testing.T) {
	p := &panelPayload{
		Findings:     []panelFinding{{Finding: finding.Finding{File: "a.go", Line: 3}}},
		ChangedFiles: []string{"a.go", "b.go"},
	}
	on := encendidas(buildOverlay(grafoDeDosArchivos(), p))
	if !on["demo.Limpia"] {
		t.Error("b.go estaba en el diff y salió limpio: su función tiene que quedar en la zona activa")
	}
	if !on["demo.Sucia"] {
		t.Error("a.go tiene un hallazgo: su función tiene que quedar en la zona activa")
	}
	if on["demo.Ajena"] {
		t.Error("c.go no lo tocó el commit ni tiene hallazgos: no debe iluminarse")
	}
}

// El aviso de secreto bloqueado NO trae StagedFiles (hook.go manda sólo el sitio
// de cada secreto), así que la zona tiene que seguir saliendo de los hallazgos.
// Con un overlay que mirara únicamente el diff, ese panel se quedaba a oscuras.
func TestSinDiffLaZonaSigueSaliendoDeLosHallazgos(t *testing.T) {
	p := &panelPayload{
		Findings: []panelFinding{{Finding: finding.Finding{File: "a.go", Line: 3}}},
	}
	on := encendidas(buildOverlay(grafoDeDosArchivos(), p))
	if !on["demo.Sucia"] {
		t.Error("sin ChangedFiles, el archivo con hallazgo tiene que iluminar su zona")
	}
	if on["demo.Limpia"] {
		t.Error("b.go no tiene hallazgo ni diff: no debe iluminarse")
	}
}

// El dato nace en el Request: si construirPayload lo pierde, el overlay no tiene
// forma de recuperarlo. Este test falla en COMPILACIÓN si alguien quita el campo.
func TestConstruirPayloadPropagaLosArchivosDelDiff(t *testing.T) {
	req := &ipc.Request{
		RepoRoot: `C:\repos\demo`,
		StagedFiles: []gitdiff.ChangedFile{
			{Path: "a.go", Status: "M"},
			{Path: "b.go", Status: "A"},
		},
	}
	p := construirPayload(req, &ipc.Response{}, nil, 10)
	if len(p.ChangedFiles) != 2 || p.ChangedFiles[0] != "a.go" || p.ChangedFiles[1] != "b.go" {
		t.Errorf("el diff no cruzó al payload: %v", p.ChangedFiles)
	}
}

// Un Request sin staged deja el campo nil (no un slice vacío) para que
// `omitempty` lo omita del JSON del panel en vez de mandar [].
func TestSinStagedElCampoNoViajaAlPanel(t *testing.T) {
	p := construirPayload(&ipc.Request{RepoRoot: `C:\repos\demo`}, &ipc.Response{}, nil, 10)
	if p.ChangedFiles != nil {
		t.Errorf("sin staged el campo tiene que quedar nil, quedó %v", p.ChangedFiles)
	}
}
