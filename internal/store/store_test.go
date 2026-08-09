package store

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

func bd(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "prueba.db"))
	if err != nil {
		t.Fatalf("no se pudo abrir la BD (¿migraciones rotas?): %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// La misma URL en sus tres formas habituales debe dar el MISMO id: si ssh y
// https produjeran ids distintos, la telemetría de un repo se partiría en dos.
func TestCanonicalRepoIDUnificaLasFormas(t *testing.T) {
	formas := []string{
		"git@github.com:hdiaz16/codeguard.git",
		"https://github.com/hdiaz16/codeguard.git",
		"https://github.com/hdiaz16/codeguard",
		"HTTPS://GITHUB.COM/hdiaz16/codeguard",
	}
	primero := CanonicalRepoID(formas[0])
	if len(primero) != 64 {
		t.Fatalf("el id debe ser sha256 hex: %q", primero)
	}
	for _, f := range formas[1:] {
		if got := CanonicalRepoID(f); got != primero {
			t.Errorf("%s produjo un id distinto:\n  %s\n  %s", f, got, primero)
		}
	}
	if CanonicalRepoID("git@github.com:otro/repo.git") == primero {
		t.Error("repos distintos no pueden compartir id")
	}
}

func TestMigracionesSonIdempotentes(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "doble.db")
	s1, err := Open(ruta)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()
	// Abrir de nuevo re-ejecuta migrate(): no debe fallar ni duplicar nada.
	s2, err := Open(ruta)
	if err != nil {
		t.Fatalf("la segunda apertura falló: las migraciones no son idempotentes: %v", err)
	}
	s2.Close()
}

func TestUpsertRepoEsIdempotente(t *testing.T) {
	s := bd(t)
	id := CanonicalRepoID("https://github.com/x/y")
	if err := s.UpsertRepo(id, "https://github.com/x/y", "y"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRepo(id, "https://github.com/x/y", "y"); err != nil {
		t.Fatalf("el segundo upsert del mismo repo falló: %v", err)
	}
}

func guardarRun(t *testing.T, s *Store, runID, repoID, verdict string, findings []finding.Finding) {
	t.Helper()
	v := pipeline.Pass
	if verdict == "block" {
		v = pipeline.Block
	}
	err := s.SaveRun(RunMeta{
		RunID: runID, RepoID: repoID, Branch: "master",
		RulepackVer: "2026.08.2", ConfigHash: "abc", Environment: "local",
	}, &pipeline.Result{Verdict: v, Degraded: []string{}, Findings: findings}, len(findings))
	if err != nil {
		t.Fatal(err)
	}
}

// El ciclo completo de la calibración: run → hallazgo → feedback → la regla
// con exceso de falsos positivos se degrada sola. Es la única palanca de
// ajuste del sistema (§17) y no tenía prueba.
func TestElFeedbackDegradaLaReglaRuidosa(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/prueba")
	if err := s.UpsertRepo(repoID, "", "prueba"); err != nil {
		t.Fatal(err)
	}

	// 5 hallazgos de la misma regla; 4 marcados como falso positivo.
	ids := make([]string, 5)
	for i := range ids {
		f := finding.Finding{
			ID: NewULID(), Engine: "semgrep", RuleKey: "regla-ruidosa",
			Pillar: finding.Quality, Severity: finding.Warning, Source: finding.Deterministic,
			File: "a.go", Line: i + 1, Message: "aviso", Fingerprint: NewULID(),
		}
		ids[i] = f.ID
		guardarRun(t, s, NewULID(), repoID, "pass", []finding.Finding{f})
	}
	for i, id := range ids {
		verdict := "false_positive"
		if i == 0 {
			verdict = "useful"
		}
		if err := s.SaveFeedback(id, verdict, ""); err != nil {
			t.Fatal(err)
		}
	}

	// 5 votos, 80% de falsos positivos > umbral 20%: se degrada.
	demoted, err := s.DemotedRules(repoID, 5, 0.20)
	if err != nil {
		t.Fatal(err)
	}
	if !demoted["semgrep/regla-ruidosa"] {
		t.Error("una regla con 4/5 falsos positivos debía degradarse")
	}

	// Con el mínimo de votos más alto, todavía no: pocas muestras no deciden.
	demoted, err = s.DemotedRules(repoID, 6, 0.20)
	if err != nil {
		t.Fatal(err)
	}
	if demoted["semgrep/regla-ruidosa"] {
		t.Error("con menos votos que el mínimo no debe degradarse nada")
	}
}

func TestFeedbackRechazaVeredictosInventados(t *testing.T) {
	s := bd(t)
	if err := s.SaveFeedback("f1", "me-gusta", ""); err == nil {
		t.Error("un veredicto fuera del contrato debe rechazarse")
	}
}

func TestDiffCache(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/cache")
	s.UpsertRepo(repoID, "", "cache")

	if _, hit := s.DiffCacheGet(repoID, "sha1", "2026.08.2", "cfg1", "modelo"); hit {
		t.Fatal("caché vacía no puede dar hit")
	}
	if err := s.DiffCachePut(repoID, "sha1", "2026.08.2", "cfg1", "modelo", `{"ok":true}`); err != nil {
		t.Fatal(err)
	}
	got, hit := s.DiffCacheGet(repoID, "sha1", "2026.08.2", "cfg1", "modelo")
	if !hit || got != `{"ok":true}` {
		t.Errorf("hit=%v valor=%q", hit, got)
	}
	// La clave incluye el modelo: cambiarlo invalida el resultado cacheado.
	if _, hit := s.DiffCacheGet(repoID, "sha1", "2026.08.2", "cfg1", "OTRO-modelo"); hit {
		t.Error("cambiar de modelo debe invalidar la caché del diff")
	}
}

// El tope de presupuesto se alimenta de esto: si la suma del mes se pierde,
// el corte nunca llega y la factura tampoco tiene techo.
func TestGastoDelMes(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/gasto")
	s.UpsertRepo(repoID, "", "gasto")
	guardarRun(t, s, "01RUN", repoID, "pass", nil)

	// 3,500,000 micros = $3.50
	for _, micros := range []int64{1_000_000, 2_500_000} {
		if err := s.SaveLLMCall(LLMCall{RunID: "01RUN", Pillar: "security", Model: "m", Status: "ok", CostMicros: micros}); err != nil {
			t.Fatal(err)
		}
	}
	gastado, err := s.GastoDelMesUSD()
	if err != nil {
		t.Fatal(err)
	}
	if gastado != 3.5 {
		t.Errorf("gasto del mes: %.6f, se esperaban 3.50", gastado)
	}
}

func TestExportarRunsFiltraYEscribeCSV(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/export")
	s.UpsertRepo(repoID, "", "export")
	guardarRun(t, s, "01A", repoID, "block", []finding.Finding{{
		ID: NewULID(), Engine: "semgrep", RuleKey: "r", Pillar: finding.Security,
		Severity: finding.Error, Source: finding.Deterministic, Blocking: true,
		File: "a.go", Line: 1, Message: "m", Fingerprint: NewULID(),
	}})
	guardarRun(t, s, "01B", repoID, "pass", nil)

	destino := filepath.Join(t.TempDir(), "runs.csv")
	n, err := s.ExportarRuns(destino, FiltroExport{Repo: repoID, Solo: "block"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("con filtro block debía exportar 1 run, exportó %d", n)
	}
	f, err := os.Open(destino)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	filas, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("el CSV no es legible: %v", err)
	}
	if len(filas) != 2 { // cabecera + 1
		t.Fatalf("filas en el CSV: %d", len(filas))
	}
	if filas[1][3] != "block" {
		t.Errorf("veredicto exportado: %q", filas[1][3])
	}

	// Y el punto de la parametrización: un valor hostil es un VALOR, no SQL.
	n, err = s.ExportarRuns(filepath.Join(t.TempDir(), "h.csv"),
		FiltroExport{Repo: "x' OR '1'='1"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("una inyección en el filtro devolvió %d filas: la consulta no está parametrizada", n)
	}
}

func TestResumenSemanal(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/resumen")
	s.UpsertRepo(repoID, "", "resumen")

	if r, err := s.ResumenSemanal(repoID); err != nil || !strings.Contains(r, "sin análisis") {
		t.Errorf("sin runs: %q (err=%v)", r, err)
	}
	guardarRun(t, s, "01C", repoID, "pass", nil)
	r, err := s.ResumenSemanal(repoID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r, "1") {
		t.Errorf("con un run limpio el resumen debe contarlo: %q", r)
	}
}
