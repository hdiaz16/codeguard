// codeguard-daemon — el compañero (§12): daemon con tray y panel lateral.
// Compilar con -ldflags "-H windowsgui" para no abrir consola.
package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

//go:embed all:frontend
var assets embed.FS

const panelWidth = 480

// panelFinding es lo que pinta el panel: el hallazgo + su código señalado.
type panelFinding struct {
	finding.Finding
	Snippet []snippetLine `json:"snippet"`
	// Tono §12.2: determinista se enuncia como hecho; el LLM (fase 3+) como observación.
	IsFact bool `json:"is_fact"`
}

type snippetLine struct {
	No      int    `json:"no"`
	Text    string `json:"text"`
	Culprit bool   `json:"culprit"`
}

// rootsDelEvento saca las rutas de un evento del frontend. Wails entrega el
// dato como llegó de JavaScript, y las dos formas de Emit del runtime lo
// mandan distinto: una como arreglo, otra como valor suelto.
func rootsDelEvento(e *application.CustomEvent) []string {
	if e == nil || e.Data == nil {
		return nil
	}
	raw, err := json.Marshal(e.Data)
	if err != nil {
		return nil
	}
	var roots []string
	if json.Unmarshal(raw, &roots) == nil && len(roots) > 0 {
		return roots
	}
	var uno string
	if json.Unmarshal(raw, &uno) == nil && uno != "" {
		return []string{uno}
	}
	return nil
}

type panelPayload struct {
	Repo        string `json:"repo"`
	RepoRoot    string `json:"repo_root"`
	Branch      string `json:"branch"`
	AIGenerated bool   `json:"ai_generated"`
	Suppressed  int    `json:"suppressed"`
	// TODOS los proyectos enrolados con su estado: "marca|nombre|ruta|activo".
	// Cambiar de contexto desde el panel no altera el estado de nadie.
	OtrosRepos []string       `json:"otros_repos,omitempty"`
	Verdict    string         `json:"verdict"`
	Blocking   int            `json:"blocking"`
	Advisory   int            `json:"advisory"`
	CIParity   bool           `json:"ci_parity"`
	Degraded   []string       `json:"degraded"`
	Findings   []panelFinding `json:"findings"`
	MaxShow    int            `json:"max_show"`
	ElapsedMs  int64          `json:"elapsed_ms"`
	At         string         `json:"at"`
}

func snippet(repoRoot, rel string, line int) []snippetLine {
	if line < 1 {
		return nil
	}
	// Confinado al repo: una ruta manipulada en la salida de un escáner no
	// debe poder mostrar archivos de fuera (gosec G304/G703).
	full := filepath.Clean(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if !strings.HasPrefix(full, filepath.Clean(repoRoot)+string(filepath.Separator)) {
		return nil
	}
	f, err := os.Open(full)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []snippetLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	no := 0
	for sc.Scan() {
		no++
		if no < line-3 {
			continue
		}
		if no > line+3 {
			break
		}
		out = append(out, snippetLine{No: no, Text: sc.Text(), Culprit: no == line})
	}
	return out
}

// resumenHallazgos describe el resultado en una frase, con los plurales bien.
// Un "0 bloqueantes, 1 avisos" obliga a descifrar dos números y encima está
// mal escrito; esto se entiende sin pensarlo.
func resumenHallazgos(bloqueantes, avisos int) string {
	switch {
	case bloqueantes == 0 && avisos == 0:
		return "sin observaciones"
	case bloqueantes == 0:
		return plural(avisos, "1 sugerencia", "%d sugerencias")
	case avisos == 0:
		return plural(bloqueantes, "1 problema por resolver", "%d problemas por resolver")
	}
	return fmt.Sprintf("%s y %s",
		plural(bloqueantes, "1 problema por resolver", "%d problemas por resolver"),
		plural(avisos, "1 sugerencia", "%d sugerencias"))
}

func plural(n int, uno, varios string) string {
	if n == 1 {
		return uno
	}
	return fmt.Sprintf(varios, n)
}

// orbStateFor traduce el veredicto de UN proyecto al clima del orbe.
func orbStateFor(p *panelPayload) string {
	switch {
	case p.Verdict == "block":
		return "blocked"
	case p.Advisory > 0:
		return "idle"
	default:
		return "pass"
	}
}

type trayState struct {
	tray  *application.SystemTray
	reset *time.Timer
	emit  func(state, tooltip string)
}

func (t *trayState) set(state, tooltip string) {
	t.tray.SetIcon(trayIcon(state))
	t.tray.SetLabel("CodeGuard: " + state)
	t.tray.SetTooltip("CodeGuard — " + tooltip)
	// La burbuja flotante escucha el mismo estado.
	if t.emit != nil {
		t.emit(state, tooltip)
	}
}

// pass vuelve a idle a los 15 s — con 10 el verde pasaba desapercibido.
func (t *trayState) setPass(tooltip string) {
	t.set("pass", tooltip)
	if t.reset != nil {
		t.reset.Stop()
	}
	t.reset = time.AfterFunc(15*time.Second, func() { t.set("idle", tooltip) })
}

// version la inyecta build-dist con -X main.version desde setup.iss — una
// sola fuente de verdad. "dev" delata un binario compilado a mano.
var version = "dev"

// abrirLog manda el registro al archivo del usuario. El daemon corre sin
// consola (-H windowsgui): sin este log, cualquier fallo es invisible. Vive
// junto a la BD del usuario.
func abrirLog(refrescadas int) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return
	}
	dir := filepath.Join(base, "codeguard")
	_ = os.MkdirAll(dir, 0o755) // best-effort: el OpenFile del log de abajo reportaría el fallo
	f, err := os.OpenFile(filepath.Join(dir, "daemon.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.Printf("=== daemon %s arrancado ===", version)
	if refrescadas > 0 {
		log.Printf("entorno: %d variable(s) del usuario incorporadas del registro", refrescadas)
	}
}

// main es la raíz de composición y nada más: cablea las piezas en el orden en
// que dependen unas de otras. Lo que cada pieza HACE vive en escritorio.go —
// aquí sólo se ve el arranque completo de un vistazo.
func main() {
	// El PATH del registro antes que nada: el daemon lo lanza la clave Run al
	// iniciar sesión, y si el agente se instaló DURANTE la sesión en curso su
	// entorno no tiene los motores. Sin esto, la compuerta de secretos bloquea
	// commits pidiendo un gitleaks que está instalado.
	proc.RefrescarPATH()
	// Y las demás variables del usuario, que es donde vive la clave del modelo:
	// sin esto, cada reinicio del daemon apagaba la capa LLM en silencio.
	refrescadas := proc.RefrescarVariables()
	abrirLog(refrescadas)

	// El escritorio nace antes que la aplicación: Wails pide el manejador HTTP
	// al construirse y ese manejador sirve el estado que vive en el escritorio.
	e := nuevoEscritorio()
	e.app = application.New(application.Options{
		Name:        "CodeGuard",
		Description: "Agente de análisis pre-commit con paridad hacia CI",
		// La identidad del agente es el mismo orbe que el desarrollador ve en
		// la esquina de su pantalla, no un ícono genérico.
		Icon: iconoOficial(),
		Assets: application.AssetOptions{
			// BundledAssetFileServer sirve también /wails/runtime.js,
			// que el panel importa para los eventos.
			Handler: e.manejadorHTTP(),
		},
	})
	e.construirVentanas()
	e.construirBandeja()
	e.registrarEventos()

	srv := e.construirServidorIPC(e.arrancarSombra())

	// Anclar el orbe en su esquina al arrancar (con reintentos).
	e.app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		e.anclarBurbujaSeguro()
	})

	ctx, cancel := context.WithCancel(context.Background())
	e.app.OnShutdown(cancel)
	go func() {
		// El tray refleja "working" mientras el server atiende: el propio
		// handler emite el estado al entrar la petición (ver ipc hook abajo).
		if err := srv.Serve(ctx); err != nil {
			log.Println("servidor IPC:", err)
		}
	}()

	if err := e.app.Run(); err != nil {
		log.Fatal(err)
	}
}
