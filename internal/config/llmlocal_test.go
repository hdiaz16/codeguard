package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const configConEndpointDelEquipo = `version: 1
rulepack: "2026.08.2"
languages: [go]
llm:
  provider: "azure-foundry"
  endpoint: "https://equipo.example.com/openai/v1"
  api_key_env: "FOUNDRY_API_KEY"
  model: "modelo-del-equipo"
`

const endpointHostil = "https://atacante.example.net/recoge"

// El repositorio que acabas de clonar NO puede configurarte el modelo.
//
// RutaLLMLocal componía la ruta con filepath.Join sobre LOCALAPPDATA sin
// comprobar nada. Con esa variable vacía —cuenta de servicio, entorno filtrado,
// proceso lanzado con un bloque de entorno acotado— el Join no falla: devuelve
// `codeguard\llm-local.yaml`, que es RELATIVA, y relativa significa relativa al
// directorio de trabajo, que durante un commit es el repo que se está
// analizando. A partir de ahí basta con que el repo traiga ese archivo para que
// el endpoint al que se mandan los diffs sea el que él diga.
//
// Y es silencioso por partida doble: aplicarLLMLocal ignora todos los errores,
// y se aplica DESPUÉS del hash de paridad, así que la anulación no altera el
// hash ni produce diagnóstico.
func TestUnRepoAjenoNoPuedeSecuestrarElEndpointDelModelo(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")

	repo := repoConConfig(t, configConEndpointDelEquipo)

	// El cebo, dentro del repo, exactamente donde aterriza la ruta relativa.
	cebo := filepath.Join(repo, "codeguard")
	if err := os.MkdirAll(cebo, 0o755); err != nil {
		t.Fatal(err)
	}
	hostil := "llm:\n  endpoint: \"" + endpointHostil + "\"\n  model: \"modelo-del-atacante\"\n"
	if err := os.WriteFile(filepath.Join(cebo, "llm-local.yaml"), []byte(hostil), 0o644); err != nil {
		t.Fatal(err)
	}

	// El commit se analiza desde dentro del repo: es lo que hace que una ruta
	// relativa apunte al cebo.
	t.Chdir(repo)

	cfg, err := Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("el repo está enrolado: Load no debía devolver nil")
	}

	if cfg.LLM.Endpoint == endpointHostil {
		t.Errorf("el repo secuestró el endpoint del modelo: los diffs se mandarían a %q", cfg.LLM.Endpoint)
	}
	if cfg.LLM.Endpoint != "https://equipo.example.com/openai/v1" {
		t.Errorf("debía mandar el endpoint del equipo, y quedó %q", cfg.LLM.Endpoint)
	}
	if cfg.LLM.Model == "modelo-del-atacante" {
		t.Error("el repo también impuso el modelo")
	}
	if cfg.LLMLocal {
		t.Error("no hay anulación PERSONAL ninguna: marcarla haría que la UI llamara suyo a lo que puso el repo")
	}
}

// La ruta personal es absoluta o no es. Una relativa apunta a donde sea que
// esté el directorio de trabajo, y eso es justo lo que no puede pasar: el
// invariante que el comentario de la función declara ("fuera del repo") hay que
// imponerlo, no confiarlo.
func TestRutaLLMLocalNuncaEsRelativa(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
		quieroVacia  bool
	}{
		{"variable ausente", "", true},
		{"variable en blanco", "   ", true},
		{"valor relativo puesto a mano", `datos\local`, true},
		{"valor absoluto normal", t.TempDir(), false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", c.localappdata)
			got := RutaLLMLocal()
			if c.quieroVacia {
				if got != "" {
					t.Errorf("LOCALAPPDATA=%q debía dar \"\" y dio %q", c.localappdata, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("LOCALAPPDATA=%q debía dar una ruta y dio \"\"", c.localappdata)
			}
			if !filepath.IsAbs(got) {
				t.Errorf("RutaLLMLocal devolvió una ruta relativa: %q", got)
			}
			if !strings.HasSuffix(got, filepath.Join("codeguard", "llm-local.yaml")) {
				t.Errorf("RutaLLMLocal cambió de sitio: %q", got)
			}
		})
	}
}

// Sin ruta resoluble no se lee NADA. Es la mitad del arreglo que vive en
// aplicarLLMLocal: aunque la ruta vacía ya haría fallar el ReadFile, apoyarse
// en eso sería volver a confiar en un accidente.
func TestSinRutaPersonalNoSeAplicaAnulacion(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	cfg := &Config{LLM: LLM{Endpoint: "https://equipo.example.com/openai/v1", Model: "modelo-del-equipo"}}
	aplicarLLMLocal(cfg)
	if cfg.LLMLocal {
		t.Error("sin ruta personal no hay anulación que marcar")
	}
	if cfg.LLM.Endpoint != "https://equipo.example.com/openai/v1" || cfg.LLM.Model != "modelo-del-equipo" {
		t.Errorf("cfg.LLM fue tocado sin haber archivo personal: %+v", cfg.LLM)
	}
}
