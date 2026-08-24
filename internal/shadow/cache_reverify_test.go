package shadow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/store"
)

// EL ACIERTO TAMBIÉN SE VERIFICA (plan W1, turnos 61-69 del consejo). Hasta
// aquí el diff_cache guardaba hallazgos YA verificados y el hit los
// re-registraba sin mirarlos: un verify() que aprendiera a rechazar más
// seguía sirviendo lo aprobado por su versión anterior, el worktree podía
// haber cambiado desde el cacheo (la línea citada ya no existir), y una
// entrada inyectada en la BD llegaba al informe sin pasar por ninguna aduana.
// El contrato nuevo: se cachea lo CRUDO, y cada acierto re-pasa por el MISMO
// verify() de la etapa 6 — nunca por un juego de chequeos reducido.

// hallazgosDelRun cuenta lo que de verdad quedó registrado para un run: el
// informe se alimenta de la tabla, así que la tabla es lo que hay que mirar.
func hallazgosDelRun(t *testing.T, st *store.Store, runID string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM findings WHERE run_id = ?`, runID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// segundoRun registra otro run del mismo repo (clave foránea de findings) y
// devuelve la petición que lo analiza: mismo diff, run nuevo.
func segundoRun(t *testing.T, r *Runner, req0 ipc.Request) ipc.Request {
	t.Helper()
	req := req0
	req.RunID = store.NewULID()
	if err := r.Store.SaveRun(store.RunMeta{
		RunID: req.RunID, RepoID: req.RepoID, Branch: "main",
		RulepackVer: req.RulepackVersion, ConfigHash: req.ConfigHash, Environment: "local",
	}, &pipeline.Result{Verdict: pipeline.Pass},
		pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), 1); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestElHitReVerificaContraElMundoDeHoy(t *testing.T) {
	var llamadas atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		llamadas.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(respuestaSSE(hallazgoValido)))
	}))
	defer srv.Close()

	r, cfg, req := entornoDePrueba(t, srv.URL)
	r.Run(context.Background(), cfg, req, nil)
	if n := hallazgosDelRun(t, r.Store, req.RunID); n == 0 {
		t.Fatal("la primera corrida debía registrar el hallazgo válido (línea 4 existe)")
	}
	trasPrimera := llamadas.Load()

	// El worktree CAMBIA después del cacheo: app.go pierde la línea 4. El
	// mismo diff vuelve (mismo sha, acierto seguro) y el hallazgo cacheado
	// cita una línea que hoy no existe.
	if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "app.go"), []byte("package app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	req2 := segundoRun(t, r, *req)
	r.Run(context.Background(), cfg, &req2, nil)

	if llamadas.Load() != trasPrimera {
		t.Errorf("el segundo run debía ser un acierto de caché sin llamadas al modelo: hubo %d nuevas",
			llamadas.Load()-trasPrimera)
	}
	if n := hallazgosDelRun(t, r.Store, req2.RunID); n != 0 {
		t.Errorf("el acierto sirvió %d hallazgo(s) cuya línea ya no existe: el hit no re-verificó contra el mundo de hoy", n)
	}
}

// La aceptación literal del plan: «hallazgo fuera-de-diff inyectado en caché
// LLM no se registra». Se inyecta una entrada directamente en la BD —el
// escenario del veneno— con un pilar citando un archivo que NO está en el
// diff y otro con el hallazgo legítimo: la aduana deja pasar exactamente uno.
func TestUnaEntradaEnvenenadaNoLlegaAlInforme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("hubo acierto de caché: el modelo no debía recibir ninguna llamada")
	}))
	defer srv.Close()

	r, cfg, req := entornoDePrueba(t, srv.URL)
	// fuera.go EXISTE en el repo y su línea 1 es real: si no existiera, lo
	// rechazaría el chequeo de línea por otra razón y esta prueba dejaría de
	// fijar la aduana que dice fijar (el archivo citado DEBE estar en el diff).
	if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "fuera.go"),
		[]byte("package app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	veneno := `{"findings":[{"file":"fuera.go","line":1,"rule_key":"ad-hoc","severity":"warning","confidence":0.9,"message":"inyectado","why":"w","fix_hint":"f"}]}`
	entrada, err := json.Marshal(sombraCacheada{Version: versionVerificador, Crudas: map[string]string{
		"security": veneno,
		"quality":  hallazgoValido,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Store.DiffCachePut(req.RepoID, sha256hex(req.DiffUnified),
		req.RulepackVersion, req.ConfigHash, claveDelCache(cfg), string(entrada)); err != nil {
		t.Fatal(err)
	}

	r.Run(context.Background(), cfg, req, nil)

	if n := hallazgosDelRun(t, r.Store, req.RunID); n != 1 {
		t.Errorf("debía registrarse SOLO el hallazgo legítimo, se registraron %d", n)
	}
	var inyectados int
	if err := r.Store.DB().QueryRow(`SELECT COUNT(*) FROM findings WHERE run_id = ? AND file_path = 'fuera.go'`,
		req.RunID).Scan(&inyectados); err != nil {
		t.Fatal(err)
	}
	if inyectados != 0 {
		t.Error("el hallazgo inyectado (archivo fuera del diff) llegó al informe: la aduana del hit no existe")
	}
}

// Una entrada con otra versión del formato no se finge entendida: se cae al
// análisis real. (Las entradas del contrato v1 ni siquiera llegan aquí — la
// clave nueva las deja huérfanas — pero la guarda cubre el futuro v3 y una
// BD manipulada.)
func TestUnaEntradaDeOtraVersionSeReanaliza(t *testing.T) {
	var llamadas atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		llamadas.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(respuestaSSE(hallazgoValido)))
	}))
	defer srv.Close()

	r, cfg, req := entornoDePrueba(t, srv.URL)
	entrada, _ := json.Marshal(sombraCacheada{Version: versionVerificador + 1,
		Crudas: map[string]string{"quality": hallazgoValido}})
	if err := r.Store.DiffCachePut(req.RepoID, sha256hex(req.DiffUnified),
		req.RulepackVersion, req.ConfigHash, claveDelCache(cfg), string(entrada)); err != nil {
		t.Fatal(err)
	}

	r.Run(context.Background(), cfg, req, nil)

	if llamadas.Load() == 0 {
		t.Error("una entrada de otra versión del verificador se sirvió como acierto: debía re-analizarse")
	}
}
