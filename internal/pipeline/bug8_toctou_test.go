package pipeline_test

// EXPERIMENTO del bug #8, dimensión TOCTOU (síntesis del consejo, turno 54):
// el sha de la clave de caché se lee del worktree en el momento del diff
// (gitdiff_hunks.go:190-197) y los motores leen el worktree DESPUÉS, en el
// suyo. Si el archivo cambia entre ambos instantes —un autosave basta—, los
// hallazgos del contenido v2 se guardan bajo la clave sha(v1): una entrada
// que MIENTE sobre qué contenido analizó. Cuando el archivo vuelve a v1, el
// acierto sirve las líneas de v2 sobre un contenido cuya violación vive en
// otra línea — el síntoma exacto de la bitácora (~55 ms uniformes, línea
// desactualizada, todos los motores comparten SHA256De).
//
// Aquí no hay carreras dormidas: el experimento ES la ventana — se toma el
// diff (sha de v1), se muta el archivo a v2, y solo entonces se analiza.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
	"codeguard/internal/rulepack"
	"codeguard/internal/store"
)

func TestBug8ElVenenoDelTOCTOUNoSePuedeCachear(t *testing.T) {
	if testing.Short() {
		t.Skip("corre motores reales")
	}
	_, repo, datos := prepararCache(t)

	cfg, err := config.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(datos, "codeguard", "codeguard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	repoID := store.RepoIDDe(repo, "")
	cache := daemon.CachePorArchivo(st, repoID, "", "bug8", cfg, repo)
	if cache == nil {
		t.Fatal("sin caché no hay experimento")
	}

	analizar := func() *pipeline.Result {
		t.Helper()
		// El INSTANTE UNO: el diff congela sha(contenido actual del worktree).
		diff, err := gitdiff.Staged(repo)
		if err != nil {
			t.Fatal(err)
		}
		res, err := pipeline.Run(context.Background(), pipeline.Options{
			Config:       cfg,
			Diff:         diff,
			Secrets:      nil,
			Engines:      daemon.Engines(cfg, false, cache),
			Rulepack:     func() string { id, _ := rulepack.Resolver(repo, cfg.Rulepack); return id.Path }(),
			Timeout:      3 * time.Minute,
			Suppressions: func() map[string]bool { m, _ := baseline.Load(repo); return m }(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	lineaDeBandit := func(res *pipeline.Result, archivo string) int {
		t.Helper()
		for _, f := range res.Findings {
			if f.Engine == "bandit" && f.File == archivo && f.RuleKey == "B602" {
				return f.Line
			}
		}
		t.Fatalf("sin hallazgo de bandit en %s entre %d hallazgos", archivo, len(res.Findings))
		return 0
	}

	// LA VENTANA EN FRÍO — la única donde puede nacer el veneno. Con caché
	// caliente el acierto corta ANTES de leer el archivo (medido: la primera
	// versión de este experimento calentaba primero y el hit de la ventana
	// sirvió la línea de v1, correcta para el commit). En frío no hay
	// acierto que corte: sha(v1) congelado en el diff, el archivo muta a v2
	// —un autosave en medio de un análisis de 30 s—, y el motor ANALIZA v2.
	diff, err := gitdiff.Staged(repo)
	if err != nil {
		t.Fatal(err)
	}
	base := 5 // la violación de elDefecto vive en su línea 5
	escribir(t, repo, "app/inseguro.py", "# uno\n# dos\n# tres\n"+elDefecto)
	res, err := pipeline.Run(context.Background(), pipeline.Options{
		Config:       cfg,
		Diff:         diff, // el snapshot VIEJO, con sha(v1)
		Secrets:      nil,
		Engines:      daemon.Engines(cfg, false, cache),
		Rulepack:     func() string { id, _ := rulepack.Resolver(repo, cfg.Rulepack); return id.Path }(),
		Timeout:      3 * time.Minute,
		Suppressions: map[string]bool{},
	})
	if err != nil {
		t.Fatal(err)
	}
	enVentana := lineaDeBandit(res, "app/inseguro.py")
	t.Logf("en la ventana (índice v1, disco v2) el motor reportó la línea %d "+
		"(la del commit es %d; la del disco, %d)", enVentana, base, base+3)
	// La otra mitad del fix (punto 4 de la síntesis): el reporte de la ventana
	// no se puede corregir sin reabrir la carrera, pero SÍ tiene que decirse.
	if !contieneAviso(res.Degraded, "cambió durante el análisis") {
		t.Fatalf("la corrida de la ventana no avisó de que el worktree cambió: Degraded = %v", res.Degraded)
	}

	// EL VENENO: el archivo vuelve a v1 (el autosave se deshizo). git no
	// cambió en ningún momento. Si la corrida de la ventana guardó los
	// hallazgos de v2 bajo sha(v1), este acierto sirve la línea 8 sobre un
	// contenido cuya violación vive en la 5 — el bug #8 en vivo, persistente.
	escribir(t, repo, "app/inseguro.py", elDefecto)
	resFinal := analizar()
	final := lineaDeBandit(resFinal, "app/inseguro.py")
	if final != base {
		t.Fatalf("BUG #8 REPRODUCIDO: el contenido es v1 (violación en línea %d) y el caché "+
			"sirvió la línea %d — la entrada nació en la ventana TOCTOU etiquetada con el "+
			"sha de un contenido que no analizó", base, final)
	}
	// Y sin mutación no hay aviso: un aviso que sale siempre no avisa de nada.
	if contieneAviso(resFinal.Degraded, "cambió durante el análisis") {
		t.Fatalf("la corrida estable avisó de un cambio que no ocurrió: Degraded = %v", resFinal.Degraded)
	}
}

func contieneAviso(degraded []string, fragmento string) bool {
	for _, d := range degraded {
		if strings.Contains(d, fragmento) {
			return true
		}
	}
	return false
}
