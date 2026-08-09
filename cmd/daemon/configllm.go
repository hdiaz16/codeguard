package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/sys/windows/registry"

	"codeguard/internal/config"
	"codeguard/internal/llm"
)

// Configuración del modelo desde la interfaz. Tres reglas que no se negocian:
//
//  1. La API key NUNCA se escribe en un archivo de CodeGuard. Si el
//     desarrollador la pega en la pantalla, va a una variable de entorno de su
//     usuario y de ahí no sale.
//  2. La elección personal vive fuera del repo, para que no viaje en un commit
//     ni cambie el hash de la configuración del equipo.
//  3. Lo que el equipo versiona sigue siendo el valor por defecto: la pantalla
//     dice con todas sus letras cuándo se está usando algo distinto.

type proveedorUI struct {
	ID          string   `json:"id"`
	Nombre      string   `json:"nombre"`
	Endpoint    string   `json:"endpoint"`
	VarEntorno  string   `json:"var_entorno"`
	Modelos     []string `json:"modelos"`
	Comentario  string   `json:"comentario"`
	NecesitaKey bool     `json:"necesita_key"`
	Dialecto    string   `json:"dialecto"`
}

type estadoConfigLLM struct {
	Proveedores []proveedorUI `json:"proveedores"`
	Provider    string        `json:"provider"`
	Endpoint    string        `json:"endpoint"`
	APIKeyEnv   string        `json:"api_key_env"`
	Model       string        `json:"model"`
	ModelFast   string        `json:"model_fast"`
	TimeoutMs   int           `json:"timeout_ms"`
	// EsLocal: la configuración activa es la personal, no la del equipo.
	EsLocal bool `json:"es_local"`
	// HayKey: si la variable de entorno tiene valor. Nunca se manda el valor.
	HayKey bool `json:"hay_key"`
	// RutaLocal se muestra para que nadie tenga que adivinar dónde quedó.
	RutaLocal string `json:"ruta_local"`
	// DelEquipo describe lo que dice el repo, para poder volver a ello.
	DelEquipo string `json:"del_equipo"`
}

func leerConfigLLM(repoRoot string) estadoConfigLLM {
	e := estadoConfigLLM{RutaLocal: config.RutaLLMLocal(), TimeoutMs: 20000}
	for _, p := range llm.Proveedores {
		e.Proveedores = append(e.Proveedores, proveedorUI{
			ID: p.ID, Nombre: p.Nombre, Endpoint: p.Endpoint, VarEntorno: p.VarEntorno,
			Modelos: p.Modelos, Comentario: p.Comentario, NecesitaKey: p.NecesitaKey,
			Dialecto: string(p.Dialecto),
		})
	}
	cfg, err := config.Load(repoRoot)
	if err != nil || cfg == nil {
		return e
	}
	e.Provider, e.Endpoint = cfg.LLM.Provider, cfg.LLM.Endpoint
	e.APIKeyEnv, e.Model, e.ModelFast = cfg.LLM.APIKeyEnv, cfg.LLM.Model, cfg.LLM.ModelFast
	e.EsLocal = cfg.LLMLocal
	if cfg.LLM.TimeoutMs > 0 {
		e.TimeoutMs = cfg.LLM.TimeoutMs
	}
	if cfg.LLM.APIKeyEnv != "" {
		e.HayKey = os.Getenv(cfg.LLM.APIKeyEnv) != ""
	}
	// Lo que dice el repo, leído sin la anulación personal encima.
	if delEquipo := llmDelRepo(repoRoot); delEquipo != "" {
		e.DelEquipo = delEquipo
	}
	return e
}

// llmDelRepo describe en una línea el modelo que versiona el equipo, para que
// quien anuló la configuración sepa a qué puede volver.
func llmDelRepo(repoRoot string) string {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".codeguard", "config.yaml"))
	if err != nil {
		return ""
	}
	var modelo, endpoint string
	dentro := false
	for _, l := range strings.Split(string(raw), "\n") {
		t := strings.TrimRight(l, "\r")
		if strings.HasPrefix(t, "llm:") {
			dentro = true
			continue
		}
		if dentro && len(t) > 0 && t[0] != ' ' && t[0] != '\t' {
			break // se acabó el bloque
		}
		if !dentro {
			continue
		}
		campo := strings.TrimSpace(t)
		switch {
		case strings.HasPrefix(campo, "model:"):
			modelo = strings.Trim(strings.TrimSpace(strings.TrimPrefix(campo, "model:")), `"`)
		case strings.HasPrefix(campo, "endpoint:"):
			endpoint = strings.Trim(strings.TrimSpace(strings.TrimPrefix(campo, "endpoint:")), `"`)
		}
	}
	if modelo == "" && endpoint == "" {
		return ""
	}
	return strings.TrimSpace(modelo + " · " + endpoint)
}

// decodificarConfigLLM saca el formulario del evento. Wails entrega el dato
// tal como llegó de JavaScript, así que se pasa por JSON en vez de adivinar
// el tipo concreto.
func decodificarConfigLLM(e *application.CustomEvent) (guardarConfigLLM, error) {
	var g guardarConfigLLM
	if e == nil || e.Data == nil {
		return g, fmt.Errorf("evento vacío")
	}
	raw, err := json.Marshal(e.Data)
	if err != nil {
		return g, err
	}
	var lista []guardarConfigLLM
	if json.Unmarshal(raw, &lista) == nil && len(lista) > 0 {
		return lista[0], nil
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return g, err
	}
	return g, nil
}

// nonEmptyStr evita repetir el patrón "si está vacío, usa el otro" en cada
// campo opcional del formulario.
func nonEmptyStr(s, alterno string) string {
	if strings.TrimSpace(s) == "" {
		return alterno
	}
	return s
}

func escaparHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

type guardarConfigLLM struct {
	Provider  string `json:"provider"`
	Endpoint  string `json:"endpoint"`
	APIKeyEnv string `json:"api_key_env"`
	Model     string `json:"model"`
	ModelFast string `json:"model_fast"`
	// APIKey llega sólo si el desarrollador la escribió. Va a una variable de
	// entorno del usuario; jamás a un archivo nuestro.
	APIKey string `json:"api_key"`
	// Restaurar: borrar la configuración personal y volver a la del equipo.
	Restaurar bool `json:"restaurar"`
}

func guardarLLMLocal(g guardarConfigLLM) error {
	ruta := config.RutaLLMLocal()
	if g.Restaurar {
		if err := os.Remove(ruta); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("no se pudo borrar %s: %w", ruta, err)
		}
		return nil
	}
	if g.Endpoint == "" {
		return fmt.Errorf("falta el endpoint")
	}
	if g.Model == "" {
		return fmt.Errorf("falta el modelo")
	}
	if g.APIKey != "" {
		if g.APIKeyEnv == "" {
			return fmt.Errorf("para guardar la clave hace falta el nombre de la variable de entorno")
		}
		if err := guardarVariableUsuario(g.APIKeyEnv, g.APIKey); err != nil {
			return fmt.Errorf("no se pudo guardar la clave en tu entorno: %w", err)
		}
		// Que el daemon la vea sin reiniciar sesión.
		os.Setenv(g.APIKeyEnv, g.APIKey)
	}
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		return err
	}
	contenido := fmt.Sprintf(`# Configuración PERSONAL del modelo de CodeGuard.
# Escrita desde la pantalla de configuración del agente.
#
# Sustituye el bloque llm del repositorio SOLO en esta máquina. No viaja en
# ningún commit y no altera la paridad con el CI: el modelo nunca bloquea.
# Bórralo (o pulsa "volver a la del equipo") para usar el del equipo.
#
# Aquí no va ninguna clave: solo el NOMBRE de la variable que la contiene.
llm:
  provider: %q
  endpoint: %q
  api_key_env: %q
  model: %q
  model_fast: %q
`, g.Provider, g.Endpoint, g.APIKeyEnv, g.Model, nonEmptyStr(g.ModelFast, g.Model))
	return os.WriteFile(ruta, []byte(contenido), 0o644)
}

// guardarVariableUsuario escribe en el entorno del usuario (HKCU\Environment),
// que es lo mismo que hace `setx` pero sin su límite de 1024 caracteres —
// varias claves modernas lo superan.
func guardarVariableUsuario(nombre, valor string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(nombre, valor)
}

// probarConfigLLM traduce el formulario y delega en el paquete llm, que es
// donde vive la prueba de verdad (la comparte `codeguard config --probar`).
func probarConfigLLM(g guardarConfigLLM) (string, error) {
	return llm.Probar(config.LLM{
		Provider:  g.Provider,
		Endpoint:  g.Endpoint,
		APIKeyEnv: g.APIKeyEnv,
		Model:     g.Model,
	}, g.APIKey)
}
