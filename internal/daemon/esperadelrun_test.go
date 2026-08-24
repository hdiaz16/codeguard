package daemon

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite" // para leer la BD de la prueba sin pasar por el store

	"codeguard/internal/pipeline"
	"codeguard/internal/store"
)

// abrirDosProcesos devuelve dos conexiones al MISMO archivo, como en producción:
// una es el daemon (donde corre la sombra) y otra el hook (que persiste el run).
// Son dos procesos distintos sobre un SQLite compartido, y esa es toda la
// historia de este fallo.
func abrirDosProcesos(t *testing.T) (daemonSt, hookSt *store.Store, ruta string) {
	t.Helper()
	ruta = filepath.Join(t.TempDir(), "codeguard.db")
	abrir := func(quien string) *store.Store {
		st, err := store.Open(ruta)
		if err != nil {
			t.Fatalf("abriendo la BD del %s: %v", quien, err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	return abrir("daemon"), abrir("hook"), ruta
}

// LA CARRERA QUE EL SLEEP DE DOS SEGUNDOS PERDÍA.
//
// El daemon lanzaba la sombra tras `time.Sleep(2 * time.Second)`, apostando a
// que para entonces el proceso del hook ya habría escrito la fila del run. Con
// el antivirus mirando, el disco ocupado o el propio empuje oportunista
// peleando por la misma base, esa apuesta se pierde: la sombra actualiza un run
// que aún no existe, el UPDATE no toca ninguna fila —que en database/sql no es
// error— y el riesgo se pierde entero y en silencio.
//
// Aquí el hook tarda 2.5 s a propósito: medio segundo más de lo que duraba la
// apuesta. Con la espera de verdad el dato llega igual; con el sleep fijo, no.
func TestLaSombraEsperaAlRunEnVezDeDormirDosSegundos(t *testing.T) {
	daemonSt, hookSt, ruta := abrirDosProcesos(t)
	repoID := store.RepoIDDe("C:/repos/tardio", "")
	if err := hookSt.UpsertRepo(repoID, "", "tardio"); err != nil {
		t.Fatal(err)
	}
	runID := store.NewULID()

	const tardanzaDelHook = 2500 * time.Millisecond
	errHook := make(chan error, 1)
	go func() {
		time.Sleep(tardanzaDelHook)
		errHook <- hookSt.SaveRun(store.RunMeta{
			RunID: runID, RepoID: repoID, Branch: "master",
			RulepackVer: "2026.08.2", ConfigHash: "abc", Environment: "local",
		}, &pipeline.Result{Verdict: pipeline.Pass, Degraded: []string{}},
			pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), 1)
	}()

	inicio := time.Now()
	if !esperarRunPersistido(context.Background(), daemonSt, runID, esperaMaximaDelRun) {
		t.Fatal("la espera se rindió con un run que sí llegó a existir")
	}
	if transcurrido := time.Since(inicio); transcurrido < 2*time.Second {
		t.Fatalf("la espera terminó en %s: el montaje ya no reproduce la carrera "+
			"(la fila tiene que llegar DESPUÉS de los dos segundos del sleep viejo)", transcurrido)
	}

	// La sombra anota AQUÍ, en cuanto la espera dice que puede, sin esperar a
	// nadie más — igual que en el daemon. El orden importa y costó una versión
	// de este test: leer antes el resultado del hook lo sincronizaba por la
	// puerta de atrás y la prueba pasaba incluso con el sleep fijo, que es
	// justo el fallo que tiene que delatar.
	if err := daemonSt.UpdateRunLLM(runID, 7, true); err != nil {
		t.Fatalf("el riesgo se perdió: %v", err)
	}
	if err := <-errHook; err != nil {
		t.Fatalf("el hook no pudo persistir el run: %v", err)
	}
	verificar, err := sql.Open("sqlite", ruta+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer verificar.Close()
	var risk, usado int
	if err := verificar.QueryRow(`SELECT risk_score, llm_used FROM runs WHERE id = ?`, runID).
		Scan(&risk, &usado); err != nil {
		t.Fatal(err)
	}
	if risk != 7 || usado != 1 {
		t.Errorf("el run quedó sin riesgo: risk_score=%d llm_used=%d, se esperaba 7 y 1", risk, usado)
	}
}

// Si el run no aparece nunca —el desarrollador abortó el commit con Ctrl-C
// entre la respuesta y el guardado—, la espera TERMINA y dice que no. Ni
// goroutines colgadas para siempre, ni una sombra que gastaría tokens en un
// análisis sin dónde guardarse.
func TestSiElRunNuncaLlegaLaEsperaSeRindeYNoCorreLaSombra(t *testing.T) {
	daemonSt, _, _ := abrirDosProcesos(t)
	inicio := time.Now()
	if esperarRunPersistido(context.Background(), daemonSt, store.NewULID(), 200*time.Millisecond) {
		t.Fatal("dijo que el run existe sin que nadie lo haya escrito")
	}
	switch transcurrido := time.Since(inicio); {
	case transcurrido < 200*time.Millisecond:
		t.Errorf("se rindió en %s, antes de agotar el tope de 200ms", transcurrido)
	case transcurrido > 5*time.Second:
		t.Errorf("tardó %s en rendirse con un tope de 200ms", transcurrido)
	}
}

// El apagado del daemon no puede quedarse esperando media hora a un run que ya
// no va a llegar: cancelar el contexto corta la espera en el acto.
func TestElApagadoDelDaemonCortaLaEspera(t *testing.T) {
	daemonSt, _, _ := abrirDosProcesos(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	inicio := time.Now()
	if esperarRunPersistido(ctx, daemonSt, store.NewULID(), esperaMaximaDelRun) {
		t.Fatal("dijo que el run existe sin que nadie lo haya escrito")
	}
	if transcurrido := time.Since(inicio); transcurrido > 3*time.Second {
		t.Errorf("el apagado tardó %s en cortar una espera con tope de %s", transcurrido, esperaMaximaDelRun)
	}
}
