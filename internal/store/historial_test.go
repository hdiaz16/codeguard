package store

import (
	"path/filepath"
	"testing"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

// El historial es dato que la base ya guardaba y que nadie enseñaba.
//
// Lo importante de esta prueba no son los conteos: es que un bloqueante que
// dejó de aparecer se pueda distinguir de uno que sigue vivo. Sin eso, la
// pestaña de historial contaría la misma historia para las dos cosas.
func TestElHistorialSeparaLoQueSigueVivoDeLoQueYaNoAparece(t *testing.T) {
	st := abrirTemporal(t)
	const repo = "local/demo"
	if err := st.UpsertRepo(repo, "", "demo"); err != nil {
		t.Fatal(err)
	}

	// Corrida 1: dos bloqueantes.
	guardar(t, st, repo, "run-1", pipeline.Block, []finding.Finding{
		bloqueante("ban-drop-column", "db/002.sql", 1),
		bloqueante("adding-required-field", "db/002.sql", 2),
	})
	// Corrida 2: se arregló uno; el otro sigue.
	guardar(t, st, repo, "run-2", pipeline.Block, []finding.Finding{
		bloqueante("adding-required-field", "db/002.sql", 2),
	})

	h, err := st.Historial(repo, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Corridas) != 2 {
		t.Fatalf("esperaba las dos corridas, salieron %d: %+v", len(h.Corridas), h.Corridas)
	}
	// La más reciente primero: el panel lee de arriba abajo.
	if h.Corridas[0].Bloqueantes != 1 || h.Corridas[1].Bloqueantes != 2 {
		t.Errorf("los conteos por corrida salen mal: %+v", h.Corridas)
	}

	if len(h.Cerrados) != 1 {
		t.Fatalf("esperaba UN cerrado (el que dejó de aparecer), salieron %d: %+v",
			len(h.Cerrados), h.Cerrados)
	}
	if h.Cerrados[0].Regla != "ban-drop-column" {
		t.Errorf("el cerrado tiene que ser el que desapareció, no el que sigue vivo: %+v", h.Cerrados[0])
	}
	// Y el que sigue vivo NO puede aparecer como cerrado: sería decirle al dev
	// que arregló algo que sigue bloqueándole el commit.
	for _, c := range h.Cerrados {
		if c.Regla == "adding-required-field" {
			t.Errorf("%s sigue apareciendo en la última corrida y se contó como cerrado", c.Regla)
		}
	}
}

// Un repo sin historia no inventa nada.
func TestUnRepoSinCorridasDevuelveHistorialVacio(t *testing.T) {
	st := abrirTemporal(t)
	h, err := st.Historial("local/nadie", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Corridas) != 0 || len(h.Cerrados) != 0 {
		t.Errorf("un repo sin análisis no tiene historial: %+v", h)
	}
}

func abrirTemporal(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "codeguard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func guardar(t *testing.T, st *Store, repoID, runID string, v pipeline.Verdict, fs []finding.Finding) {
	t.Helper()
	for i := range fs {
		fs[i].ComputeFingerprint()
		fs[i].ID = NewULID()
	}
	err := st.SaveRun(RunMeta{
		RunID: runID, RepoID: repoID, Branch: "master",
		RulepackVer: "test", ConfigHash: "h", Environment: "local",
	}, &pipeline.Result{Verdict: v, Findings: fs},
		pipeline.Finalizar(&pipeline.Result{Verdict: v}, "", nil), 1)
	if err != nil {
		t.Fatal(err)
	}
}

func bloqueante(regla, archivo string, linea int) finding.Finding {
	return finding.Finding{
		Engine: "squawk", RuleKey: regla, Pillar: finding.Data,
		Severity: finding.Error, Blocking: true, Verified: true,
		Source: finding.Deterministic,
		File:   archivo, Line: linea, Message: regla,
		LineContent: regla + archivo,
	}
}
