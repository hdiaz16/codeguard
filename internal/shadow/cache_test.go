package shadow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/store"
)

// El escenario de estas dos pruebas es el que se descubrió midiendo la latencia
// real del modelo: cinco llamadas en 2.5-3.0 s y una en 23.4 s. Con un plazo de
// 20 s, ese atípico corta un pilar — y hasta este arreglo eso dejaba un
// resultado PARCIAL cacheado por el sha del diff, o sea que un fallo pasajero se
// volvía permanente: la próxima vez el caché acertaba y ya nunca se preguntaba.

// respuestaSSE arma la respuesta en streaming del dialecto OpenAI con el JSON
// de hallazgos que se le pase.
func respuestaSSE(jsonHallazgos string) string {
	escapado := strings.ReplaceAll(jsonHallazgos, `"`, `\"`)
	return "data: {\"choices\":[{\"delta\":{\"content\":\"" + escapado + "\"}}]}\n\n" +
		"data: {\"choices\":[{\"finish_reason\":\"stop\",\"delta\":{}}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20}}\n\n" +
		"data: [DONE]\n\n"
}

// entornoDePrueba monta un repo con un archivo real (verify() comprueba que la
// línea citada exista), un store en disco temporal y la petición del hook.
func entornoDePrueba(t *testing.T, endpoint string) (*Runner, *config.Config, *ipc.Request) {
	t.Helper()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.go"),
		[]byte("package app\n\nfunc Uno() int {\n\treturn 1\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "prueba.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertRepo("repo-1", "", "prueba"); err != nil {
		t.Fatal(err)
	}

	// El proveedor exige clave, así que la prueba pone una en su propia
	// variable: t.Setenv la retira al terminar.
	t.Setenv("CG_PRUEBA_CLAVE_LLM", "clave-de-prueba")
	cfg := &config.Config{RepoRoot: repo}
	cfg.LLM.Provider = "openai"
	cfg.LLM.APIKeyEnv = "CG_PRUEBA_CLAVE_LLM"
	cfg.LLM.Endpoint = endpoint
	cfg.LLM.Model = "modelo-de-prueba"
	cfg.LLM.TimeoutMs = 5000
	cfg.LLM.MaxDiffTokens = 4000
	cfg.Risk.Threshold = 0 // que la sombra corra siempre en la prueba

	req := &ipc.Request{
		RunID: store.NewULID(), RepoRoot: repo, RepoID: "repo-1",
		RulepackVersion: "2026.08.2", ConfigHash: "hash-1",
		StagedFiles: []gitdiff.ChangedFile{{Path: "app.go", Status: "M"}},
		DiffUnified: "--- a/app.go\n+++ b/app.go\n@@\n+func Uno() int {\n+\treturn 1\n+}\n",
	}
	// El run tiene que existir antes que sus hallazgos (clave foránea). En el
	// flujo real lo persiste el hook al recibir la respuesta, y por eso la
	// sombra espera dos segundos antes de arrancar.
	if err := st.SaveRun(store.RunMeta{
		RunID: req.RunID, RepoID: req.RepoID, Branch: "main",
		RulepackVer: req.RulepackVersion, ConfigHash: req.ConfigHash, Environment: "local",
	}, &pipeline.Result{Verdict: pipeline.Pass}, 1); err != nil {
		t.Fatal(err)
	}
	return &Runner{Store: st}, cfg, req
}

const hallazgoValido = `{"findings":[{"file":"app.go","line":4,"rule_key":"ad-hoc","severity":"warning","confidence":0.9,"message":"m","why":"w","fix_hint":"f"}]}`

// Un pilar caído NO debe dejar el resultado cacheado: si se cachea, el fallo
// pasajero se vuelve permanente para ese diff.
func TestUnPilarCaidoNoCacheaElResultado(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cuerpo := make([]byte, 65536)
		n, _ := r.Body.Read(cuerpo)
		// El pilar viaja en el prompt del usuario: así se puede tumbar uno solo.
		if strings.Contains(string(cuerpo[:n]), "PILAR DATOS") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"message":"cayo"}}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(respuestaSSE(hallazgoValido)))
	}))
	defer srv.Close()

	r, cfg, req := entornoDePrueba(t, srv.URL)
	r.Run(context.Background(), cfg, req, nil)

	diffSHA := sha256hex(req.DiffUnified)
	if _, hit := r.Store.DiffCacheGet(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, cfg.LLM.Model); hit {
		t.Error("con un pilar caído el resultado es parcial y NO puede quedar cacheado: la próxima corrida acertaría y nunca volvería a preguntar")
	}
	// Pero lo que sí se obtuvo se guarda: son hallazgos reales.
	prog, err := r.Store.ProgresoCalibracion(req.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if prog.Hallazgos == 0 {
		t.Error("los hallazgos de los pilares que SÍ respondieron deben guardarse igual")
	}
}

// Con los tres pilares respondiendo, el resultado es completo y sí se cachea —
// que es lo que evita pagar el modelo dos veces por el mismo diff.
func TestConTodosLosPilaresSiSeCachea(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(respuestaSSE(hallazgoValido)))
	}))
	defer srv.Close()

	r, cfg, req := entornoDePrueba(t, srv.URL)
	r.Run(context.Background(), cfg, req, nil)

	diffSHA := sha256hex(req.DiffUnified)
	if _, hit := r.Store.DiffCacheGet(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, cfg.LLM.Model); !hit {
		t.Error("con los tres pilares respondiendo el resultado es completo y debe cachearse")
	}
}

// El plazo de la sombra no es el interactivo: nadie la está esperando, y
// cortarla a los 20 s tira una llamada ya pagada en tokens.
//
// El piso es de TRES minutos desde que los pilares tienen techo de salida real
// (techoSombra): un razonador a ~75 tokens/s que aproveche el techo tarda 2-3
// minutos. Esta prueba fijaba el piso viejo de un minuto, y con él, subir el
// techo sólo movía el fallo de "respuesta truncada" a "timeout".
func TestPlazoSombraTienePiso(t *testing.T) {
	casos := []struct {
		timeoutMs int
		quiere    time.Duration
	}{
		{0, 3 * time.Minute},      // sin configurar
		{20000, 3 * time.Minute},  // el default del equipo: por debajo del piso
		{90000, 3 * time.Minute},  // 90 s: también por debajo del piso nuevo
		{300000, 5 * time.Minute}, // configurado por encima: se respeta
	}
	for _, c := range casos {
		cfg := &config.Config{}
		cfg.LLM.TimeoutMs = c.timeoutMs
		if got := plazoSombra(cfg); got != c.quiere {
			t.Errorf("con timeout_ms=%d el plazo fue %v, esperaba %v", c.timeoutMs, got, c.quiere)
		}
	}
}
