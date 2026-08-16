package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/sys/windows/registry"

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
	guardarEnBoveda   = secreto.Guardar
	leerDeBoveda      = secreto.Leer
	borrarDelRegistro = borrarVariableUsuario
)

// retirarCopiasDelEntorno quita las copias sueltas de la clave una vez que la
// bóveda ya la tiene: la de HKCU\Environment y la de ESTE proceso.
//
// Existe porque los dos caminos que guardan en la bóveda —la pantalla de
// configuración y la migración del arranque— tienen que hacer exactamente lo
// mismo, y tenerlo escrito por separado fue el fallo: la pantalla limpiaba el
// registro y la migración también, pero ninguna de las dos desenganchaba el
// proceso, y el daemon se quedaba con la clave en os.Environ() para heredarla a
// trivy, tsc y git.
//
// El desenganche del proceso se hace AUNQUE el borrado del registro falle, y no
// al revés: la clave ya está a salvo en la bóveda, así que la copia del proceso
// sólo puede hacer daño. Que eso no reabra el problema —proceso limpio pero
// registro sucio, o sea variable "ausente" y por tanto incorporable en el
// siguiente refresco— depende de la barrera de proc.incorporar, que nunca
// importa lo que la bóveda gestiona.
func retirarCopiasDelEntorno(nombre string) error {
	err := borrarDelRegistro(nombre)
	_ = os.Unsetenv(nombre)
	return err
}

// guardarClave deja la clave en el Administrador de credenciales del usuario y
// se asegura de que NO quede una copia suelta en el entorno.
//
// Antes se escribía en HKCU\Environment, en texto plano, que es donde la
// dejaría `setx`. El entorno acotado de los motores impedía que la clave bajara
// a gitleaks o a semgrep, pero no impedía nada de lado: cualquier programa del
// usuario la leía con un `Get-ChildItem Env:`.
//
// Las dos mitades del cambio importan por igual, y la segunda es la que se
// olvida: guardar en la bóveda sin BORRAR la copia vieja del registro deja el
// secreto exactamente igual de expuesto que antes, con la diferencia de que
// ahora nadie mira ahí. Por eso se borra aunque acabe de escribirse en la
// bóveda, y por eso borrar la variable no aborta la operación si falla — la
// clave ya está guardada, y dejarla a medias sería peor.
//
// Aquí había además un os.Setenv, resto del diseño anterior, que era la misma
// fuga por la puerta de al lado: el daemon lanza hijos sin entorno acotado y un
// exec.Command sin cmd.Env hereda os.Environ() entero, así que la clave volvía
// a viajar a herramientas de terceros. Era encima innecesario, porque
// llm.ClaveDe consulta la bóveda en CADA uso y no al arrancar: la clave recién
// guardada ya se ve en la siguiente petición. De quitar las copias sueltas —la
// del registro y la del proceso— se encarga retirarCopiasDelEntorno.
//
// Sin esa copia en el entorno, una escritura que se pierda en silencio dejaría
// la pantalla diciendo "guardada" y la capa LLM apagada. Por eso se relee lo
// escrito y se falla en voz alta si no coincide.
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
		log.Printf("aviso: la clave quedó guardada, pero no se pudo borrar la copia vieja de %s en el entorno: %v", nombre, err)
	}
	return nil
}

// borrarVariableUsuario quita el valor de HKCU\Environment. Que no exista no es
// un error: la mayoría de las instalaciones nuevas no tendrán nada que migrar.
func borrarVariableUsuario(nombre string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(nombre); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// migrarClaveSiHaceFalta mira qué variable usa la configuración de esta máquina
// y migra esa, además de las de los proveedores conocidos.
//
// Se cubren los proveedores conocidos y no sólo el activo porque cambiar de
// proveedor no borra la clave del anterior: quien probó Azure y se pasó a
// Anthropic tiene DOS claves en el registro, y la que dejó de usar es
// justamente la que nadie va a volver a tocar.
func migrarClaveSiHaceFalta() {
	for _, v := range clavesAMigrar() {
		MigrarClaveDelEntorno(v)
	}
}

// clavesAMigrar dice QUÉ variables hay que revisar, sin repetir ninguna.
//
// Va separada de la migración en sí para poder probar esta parte —que es donde
// se decide el alcance— sin tocar ninguna credencial real: una prueba de
// migrarClaveSiHaceFalta de extremo a extremo tendría que borrar y restaurar la
// clave de verdad del usuario, y basta con que la maten a media ejecución para
// dejarlo sin ella.
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

// MigrarClaveDelEntorno mueve a la bóveda una clave que quedó en el registro de
// una versión anterior, y borra el original.
//
// Se llama al arrancar el daemon. Es silenciosa cuando no hay nada que migrar,
// que es el caso de cualquier instalación nueva; sólo habla cuando hace algo,
// porque un aviso que sale siempre deja de leerse.
func MigrarClaveDelEntorno(nombreVar string) {
	if nombreVar == "" {
		return
	}
	// Lo que hay en el registro se lee SIEMPRE, aunque la bóveda ya tenga algo.
	//
	// La primera versión salía aquí en cuanto encontraba la clave en la bóveda,
	// y así dejaba la copia del registro intacta para siempre en cualquier
	// máquina donde las dos coexistieran — que es exactamente el fallo del que
	// avisa el comentario de guardarClave, cometido tres funciones más abajo.
	// Se descubrió copiando la clave real a la bóveda para una comprobación: el
	// original se quedaba, y nadie iba a volver a mirarlo.
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	valor, _, err := k.GetStringValue(nombreVar)
	k.Close()
	if err != nil || valor == "" {
		return // no hay nada que migrar ni que limpiar
	}

	// Si la bóveda ya tiene una clave, esa MANDA: puede ser una más nueva,
	// guardada desde la pantalla después de que el registro quedara obsoleto.
	// Pisarla con la del registro devolvería una clave caducada y un 401
	// imposible de explicar. Pero la copia vieja se borra igual.
	if _, err := leerDeBoveda(nombreVar); err != nil {
		if err := guardarEnBoveda(nombreVar, valor); err != nil {
			log.Printf("no se pudo migrar %s al Administrador de credenciales: %v", nombreVar, err)
			return
		}
	}
	// Con la clave ya a salvo, fuera las dos copias sueltas. La del PROCESO
	// importa tanto como la del registro y se olvidaba: RefrescarVariables corre
	// unas líneas antes que esta migración en el arranque del daemon
	// (main.go:216 y main.go:228), así que para cuando se llega aquí la clave ya
	// está dentro de os.Environ() y de ahí la heredan trivy, tsc y git.
	if err := retirarCopiasDelEntorno(nombreVar); err != nil {
		log.Printf("%s está en la bóveda pero no se pudo borrar del entorno del usuario: %v", nombreVar, err)
		return
	}
	log.Printf("%s se movió del entorno del usuario al Administrador de credenciales", nombreVar)
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
