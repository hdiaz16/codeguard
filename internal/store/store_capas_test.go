package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"codeguard/internal/capas"
	"codeguard/internal/pipeline"
)

func guardarConCapas(t *testing.T, s *Store, repoID string, cs []capas.Capa) {
	t.Helper()
	res := &pipeline.Result{Verdict: pipeline.Pass, Capas: cs}
	err := s.SaveRun(RunMeta{
		RunID: NewULID(), RepoID: repoID, Branch: "master",
		RulepackVer: "x", ConfigHash: "y", Environment: "local",
	}, res, pipeline.Finalizar(res, "", nil), 0)
	if err != nil {
		t.Fatalf("SaveRun con capas falló: %v", err)
	}
}

func salud(t *testing.T, s *Store, repoID, motor string) SaludCapa {
	t.Helper()
	todas, err := s.SaludDeCapas(repoID)
	if err != nil {
		t.Fatalf("SaludDeCapas: %v", err)
	}
	for _, sc := range todas {
		if sc.Motor == motor {
			return sc
		}
	}
	t.Fatalf("no hay salud para %q en %+v", motor, todas)
	return SaludCapa{}
}

// La regla de la racha (síntesis Q3): sube con cada fallo, un no-aplica NI CURA
// NI ROMPE, un fallo con la MISMA reason y otro detalle sigue contando igual, y
// SOLO un éxito (aplicó y completó) la reinicia.
func TestLaSaludDeCapaCuentaRachasYSoloElExitoLaReinicia(t *testing.T) {
	s := bd(t)
	repo := CanonicalRepoID("https://github.com/x/salud")
	if err := s.UpsertRepo(repo, "", "salud"); err != nil {
		t.Fatal(err)
	}

	// Fallo 1.
	guardarConCapas(t, s, repo, []capas.Capa{{Motor: "semgrep", Estado: capas.Degradada, MotivoCodigo: "error"}})
	if sc := salud(t, s, repo, "semgrep"); sc.RachaFallos != 1 {
		t.Fatalf("tras 1 fallo la racha es %d, esperaba 1", sc.RachaFallos)
	} else if sc.PrimerFallo.IsZero() {
		t.Error("un fallo debe fijar el inicio de la racha")
	}

	// No-aplica: la capa no tenía nada que mirar; ni cura ni rompe.
	guardarConCapas(t, s, repo, []capas.Capa{{Motor: "semgrep", Estado: capas.NoAplica}})
	if sc := salud(t, s, repo, "semgrep"); sc.RachaFallos != 1 {
		t.Errorf("un no-aplica movió la racha a %d; debía dejarla en 1", sc.RachaFallos)
	}

	// Fallo 2 con la MISMA reason y otro detalle: cuenta como la misma racha.
	guardarConCapas(t, s, repo, []capas.Capa{{Motor: "semgrep", Estado: capas.Degradada, MotivoCodigo: "error", Detalle: "otro texto"}})
	if sc := salud(t, s, repo, "semgrep"); sc.RachaFallos != 2 {
		t.Errorf("la racha es %d, esperaba 2 (mismo reason, detalle distinto)", sc.RachaFallos)
	}

	// Éxito: aplicó y completó ⇒ reinicia a cero y limpia el motivo.
	guardarConCapas(t, s, repo, []capas.Capa{{Motor: "semgrep", Estado: capas.Corrio}})
	sc := salud(t, s, repo, "semgrep")
	if sc.RachaFallos != 0 {
		t.Errorf("un éxito no reinició la racha: %d", sc.RachaFallos)
	}
	if sc.MotivoCodigo != "" {
		t.Errorf("tras el éxito el motivo debe quedar vacío, quedó %q", sc.MotivoCodigo)
	}
	if sc.UltimoExito.IsZero() {
		t.Error("un éxito debe fijar last_success_at")
	}
	if !sc.PrimerFallo.IsZero() {
		t.Error("tras el éxito el inicio de racha debe limpiarse")
	}
}

// run_layers guarda el recibo de cobertura de cada motor tal cual: los counts y
// el estado/motivo estables, para que el historial muestre no solo QUÉ falló
// sino cuánto cubrió.
func TestRunLayersGuardaLaCoberturaDeCadaMotor(t *testing.T) {
	s := bd(t)
	repo := CanonicalRepoID("https://github.com/x/layers")
	if err := s.UpsertRepo(repo, "", "layers"); err != nil {
		t.Fatal(err)
	}
	runID := NewULID()
	res := &pipeline.Result{Verdict: pipeline.Pass, Capas: []capas.Capa{
		{Motor: "semgrep", Estado: capas.Degradada, MotivoCodigo: "cobertura-parcial",
			Planeadas: 3, Completas: 2, Parciales: 1, Hallazgos: 5, Ms: 42},
		{Motor: "gofmt", Estado: capas.Corrio, Hallazgos: 0},
	}}
	if err := s.SaveRun(RunMeta{RunID: runID, RepoID: repo, Branch: "m", RulepackVer: "x", ConfigHash: "y", Environment: "local"},
		res, pipeline.Finalizar(res, "", nil), 0); err != nil {
		t.Fatal(err)
	}

	var kind, state, reason string
	var planned, complete, partial, findings int
	err := s.db.QueryRow(`SELECT unit_kind, state, reason_code, planned_count, complete_count, partial_count, findings
		FROM run_layers WHERE run_id = ? AND engine = 'semgrep'`, runID).
		Scan(&kind, &state, &reason, &planned, &complete, &partial, &findings)
	if err != nil {
		t.Fatalf("no se guardó la fila de run_layers de semgrep: %v", err)
	}
	if kind != "file" || state != capas.Degradada || reason != "cobertura-parcial" {
		t.Errorf("fila mal: kind=%q state=%q reason=%q", kind, state, reason)
	}
	if planned != 3 || complete != 2 || partial != 1 || findings != 5 {
		t.Errorf("counts mal: planned=%d complete=%d partial=%d findings=%d", planned, complete, partial, findings)
	}

	// El motor sin cobertura declarada corrió como capa entera.
	var gofmtKind string
	if err := s.db.QueryRow(`SELECT unit_kind FROM run_layers WHERE run_id = ? AND engine = 'gofmt'`, runID).Scan(&gofmtKind); err != nil {
		t.Fatal(err)
	}
	if gofmtKind != "layer" {
		t.Errorf("gofmt no declara cobertura fina: unit_kind = %q, esperaba layer", gofmtKind)
	}
}

// El doctor lee la salud SIN migrar (observa, no repara): el lector de solo
// lectura ve lo mismo que escribió SaveRun, y una BD inexistente es «sin
// historial», no un error.
func TestSaludDeCapasSoloLecturaLeeSinMigrar(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "salud.db")
	s, err := Open(ruta)
	if err != nil {
		t.Fatal(err)
	}
	repo := CanonicalRepoID("https://github.com/x/ro")
	if err := s.UpsertRepo(repo, "", "ro"); err != nil {
		t.Fatal(err)
	}
	guardarConCapas(t, s, repo, []capas.Capa{{Motor: "tsc", Estado: capas.Degradada, MotivoCodigo: "plazo"}})
	s.Close()

	salud, err := SaludDeCapasSoloLectura(ruta, repo)
	if err != nil {
		t.Fatalf("lectura de solo lectura: %v", err)
	}
	if len(salud) != 1 || salud[0].Motor != "tsc" || salud[0].RachaFallos != 1 || salud[0].MotivoCodigo != "plazo" {
		t.Fatalf("el read-only no coincide con lo escrito: %+v", salud)
	}

	// Una BD que no existe todavía es «sin historial», no una avería.
	vac, err := SaludDeCapasSoloLectura(filepath.Join(t.TempDir(), "noexiste.db"), repo)
	if err != nil || vac != nil {
		t.Errorf("BD inexistente debe dar vacío sin error: err=%v filas=%+v", err, vac)
	}
}

// Cada run guarda CÓMO se calculó su riesgo: la versión del algoritmo y la
// huella de los pesos (W6, defecto #1). Un run legacy que no los trae guarda
// NULL, no un cero que se confundiría con «fórmula 0».
func TestSaveRunPersisteLaIdentidadDeLaFormulaDeRiesgo(t *testing.T) {
	s := bd(t)
	repo := CanonicalRepoID("https://github.com/x/riesgo")
	if err := s.UpsertRepo(repo, "", "riesgo"); err != nil {
		t.Fatal(err)
	}
	res := &pipeline.Result{Verdict: pipeline.Pass}

	runID := NewULID()
	if err := s.SaveRun(RunMeta{RunID: runID, RepoID: repo, Branch: "m", RulepackVer: "x",
		ConfigHash: "y", Environment: "local", RiskFormulaVersion: 1, RiskConfigHash: "abc123"},
		res, pipeline.Finalizar(res, "", nil), 0); err != nil {
		t.Fatal(err)
	}
	var fv sql.NullInt64
	var ch sql.NullString
	if err := s.db.QueryRow(`SELECT risk_formula_version, risk_config_hash FROM runs WHERE id = ?`, runID).
		Scan(&fv, &ch); err != nil {
		t.Fatal(err)
	}
	if !fv.Valid || fv.Int64 != 1 || !ch.Valid || ch.String != "abc123" {
		t.Errorf("no se persistió la identidad de la fórmula: fv=%v ch=%v", fv, ch)
	}

	// Legacy: sin valores → NULL, no 0.
	legacy := NewULID()
	if err := s.SaveRun(RunMeta{RunID: legacy, RepoID: repo, Branch: "m", Environment: "local"},
		res, pipeline.Finalizar(res, "", nil), 0); err != nil {
		t.Fatal(err)
	}
	var fv2 sql.NullInt64
	if err := s.db.QueryRow(`SELECT risk_formula_version FROM runs WHERE id = ?`, legacy).Scan(&fv2); err != nil {
		t.Fatal(err)
	}
	if fv2.Valid {
		t.Error("un run sin fórmula debe guardar NULL, no 0")
	}
}
