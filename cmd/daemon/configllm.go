package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/config"
	"codeguard/internal/engines/proc"
	"codeguard/internal/llm"
	"codeguard/internal/secreto"
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
		// Se refresca antes de mirar: si la clave se guardó desde otro proceso
		// (otra sesión, otro arranque del daemon), está en el registro y este
		// proceso no la tiene. Decir "sin configurar" en ese caso era una
		// mentira que dejó la capa LLM dormida durante días.
		//
		// Con la clave en la bóveda ese modo de fallo desaparece —se lee en el
		// momento de usarla—, pero el refresco se queda por las instalaciones
		// que aún no han migrado y por las claves puestas a mano en el entorno.
		proc.RefrescarVariables()
		e.HayKey = llm.ClaveDe(cfg.LLM) != ""
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

// escaparHTML delega en html.EscapeString y no en un replacer propio. Hoy sus
// tres llamadores interpolan en TEXTO (dentro de <code>), donde una comilla es
// inofensiva, así que no había agujero abierto; se cambia porque el replacer
// dejaba fuera `"` y `'` y el nombre de la función invita a usarla también
// dentro de un atributo (title="…", value="…"), y ahí la comilla sí lo rompe.
// La stdlib cubre el conjunto completo y no hay que mantenerlo a mano.
func escaparHTML(s string) string {
	return html.EscapeString(s)
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
	// claveEnmascarada llega cuando el formulario devuelve la clave que
	// /config-llm.json sirvió tapada: significa "no la toqué", no una clave
	// nueva. Guardarla tal cual escribiría el centinela como credencial y
	// dejaría la capa de consejo con un 401 imposible de explicar. Así que
	// ese caso NO toca la bóveda: se conserva la clave que ya está guardada.
	if g.APIKey != "" && g.APIKey != claveEnmascarada {
		if g.APIKeyEnv == "" {
			return fmt.Errorf("para guardar la clave hace falta el nombre de la variable de entorno")
		}
		if err := guardarClave(g.APIKeyEnv, g.APIKey); err != nil {
			return err
		}
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

// Puntos de sustitución para las pruebas. Las ramas de error que quedan aquí
// —la bóveda acepta la escritura y al releerla devuelve otra cosa, o el
// registro se niega a soltar la copia vieja— no se pueden provocar contra el
// Administrador de credenciales ni contra el registro reales, y son justo las
// que dejan un secreto a medio mover si están mal escritas.
//
// El de la escritura está por una razón añadida: sin él, comprobar que la
// RELECTURA falla obligaba a escribir antes una credencial de verdad en el
// Administrador de credenciales del usuario, que se queda ahí si la prueba
// muere antes de su limpieza.
var (
	guardarEnBoveda = secreto.Guardar
	leerDeBoveda    = secreto.Leer
)

// retirarCopiasDelEntorno quita la copia del proceso actual una vez que la
// bóveda ya la tiene, para que no se herede a procesos hijos (trivy, tsc, git).
func retirarCopiasDelEntorno(nombre string) error {
	return os.Unsetenv(nombre)
}

// guardarClave deja la clave en el Administrador de credenciales del usuario y
// se asegura de que NO quede una copia suelta en el entorno del proceso.
func guardarClave(nombre, valor string) error {
	if err := guardarEnBoveda(nombre, valor); err != nil {
		return fmt.Errorf("no se pudo guardar la clave en el Administrador de credenciales: %w", err)
	}
	guardada, err := leerDeBoveda(nombre)
	if err != nil {
		return fmt.Errorf("la clave se escribió en el Administrador de credenciales pero no se pudo releer: %w", err)
	}
	if guardada != valor {
		return fmt.Errorf("el Administrador de credenciales devolvió una clave distinta de la guardada para %s", nombre)
	}
	if err := retirarCopiasDelEntorno(nombre); err != nil {
		log.Printf("aviso: la clave quedó guardada, pero no se pudo limpiar la copia en el entorno del proceso: %v", err)
	}
	return nil
}

// migrarClaveSiHaceFalta mira qué variable usa la configuración de esta máquina
// y migra esa, además de las de los proveedores conocidos.
func migrarClaveSiHaceFalta() {
	for _, v := range clavesAMigrar() {
		MigrarClaveDelEntorno(v)
	}
}

// clavesAMigrar dice QUÉ variables hay que revisar, sin repetir ninguna.
func clavesAMigrar() []string {
	var nombres []string
	vistas := map[string]bool{}
	agregar := func(v string) {
		if v == "" || vistas[v] {
			return
		}
		vistas[v] = true
		nombres = append(nombres, v)
	}
	if cfg, err := config.Load("."); err == nil && cfg != nil {
		agregar(cfg.LLM.APIKeyEnv)
	}
	for _, p := range llm.Proveedores {
		agregar(p.VarEntorno)
	}
	return nombres
}

// MigrarClaveDelEntorno mueve a la bóveda una clave que estuviera en el entorno
// del proceso si la bóveda aún no la tiene, y limpia la copia en memoria.
// No interactúa con el registro de Windows.
func MigrarClaveDelEntorno(nombreVar string) {
	if nombreVar == "" {
		return
	}
	valor := os.Getenv(nombreVar)
	if valor == "" {
		return
	}

	_, err := leerDeBoveda(nombreVar)
	switch {
	case err == nil:
		// Ya hay clave en la bóveda y manda: solo limpiamos del proceso.
	case secreto.NoEncontrado(err):
		if err := guardarEnBoveda(nombreVar, valor); err != nil {
			log.Printf("no se pudo migrar %s al Administrador de credenciales: %v", nombreVar, err)
			return
		}
		log.Printf("%s se movió del entorno al Administrador de credenciales", nombreVar)
	default:
		log.Printf("no se pudo comprobar la bóveda para %s (%v); se pospone la migración", nombreVar, err)
		return
	}
	_ = retirarCopiasDelEntorno(nombreVar)
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
