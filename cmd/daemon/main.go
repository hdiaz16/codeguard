// codeguard-daemon — el compañero (§12): daemon con tray y panel lateral.
// Compilar con -ldflags "-H windowsgui" para no abrir consola.
package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"codeguard/internal/codegraph"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/registry"
	"codeguard/internal/shadow"
	"codeguard/internal/store"
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

func main() {
	// El daemon corre sin consola (-H windowsgui): sin este log, cualquier
	// fallo es invisible. Vive junto a la BD del usuario.
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		dir := filepath.Join(base, "codeguard")
		os.MkdirAll(dir, 0o755)
		if f, err := os.OpenFile(filepath.Join(dir, "daemon.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			log.SetOutput(f)
			log.Printf("=== daemon arrancado ===")
		}
	}

	frontend, err := fs.Sub(assets, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	// El grafo puede pesar cientos de KB: viaja por HTTP interno, no por el
	// bus de eventos (ahí llegaba vacío). El explorador hace fetch("/graph.json").
	var graphJSON atomic.Value // []byte
	graphJSON.Store([]byte(`{"nodes":[],"edges":[]}`))

	assetsFS := application.BundledAssetFileServer(frontend)
	handler := http.NewServeMux()
	handler.HandleFunc("/graph.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(graphJSON.Load().([]byte))
	})
	// Igual que el grafo: la configuración se sirve por HTTP y no por eventos.
	// Raíz desde la que se lee la configuración del modelo. Se actualiza con
	// cada análisis; sin ninguno todavía, sirve cualquier repo enrolado —la
	// configuración del modelo suele ser la misma para todos.
	var raizConfig atomic.Value // string
	handler.HandleFunc("/config-llm.json", func(w http.ResponseWriter, r *http.Request) {
		raiz, _ := raizConfig.Load().(string)
		if raiz == "" {
			if repos := registry.Load(); len(repos) > 0 {
				raiz = repos[0].Root
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(leerConfigLLM(filepath.FromSlash(raiz)))
	})
	handler.Handle("/", assetsFS)

	app := application.New(application.Options{
		Name:        "CodeGuard",
		Description: "Agente de análisis pre-commit con paridad hacia CI",
		// La identidad del agente es el mismo orbe que el desarrollador ve en
		// la esquina de su pantalla, no un ícono genérico.
		Icon: iconoOficial(),
		Assets: application.AssetOptions{
			// BundledAssetFileServer sirve también /wails/runtime.js,
			// que el panel importa para los eventos.
			Handler: handler,
		},
	})

	// Sin ventana principal: el panel y la burbuja son las únicas ventanas.
	// Una ventana oculta extra costaba un renderer de WebView2 (~60 MB).
	panel := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:         "CodeGuard",
		Frameless:     true,
		AlwaysOnTop:   true,
		Hidden:        true, // §12.2: oculto mientras no haya nada que mostrar
		Width:         panelWidth,
		Height:        600,
		DisableResize: true,
		URL:           "/",
		// Transparente puro: el acrílico cubría todo el rectángulo de la
		// ventana y se veía como un fondo doble alrededor de la tarjeta.
		BackgroundType:   application.BackgroundTypeTransparent,
		BackgroundColour: application.RGBA{Red: 0, Green: 0, Blue: 0, Alpha: 0},
		Windows: application.WindowsWindow{
			HiddenOnTaskbar:                   true,
			DisableFramelessWindowDecorations: true,
		},
	})

	// Tarjeta flotante anclada sobre el orbe (abajo-derecha), no muro completo.
	// Redimensionar un WebView en cada apertura causa lag: solo se acomoda
	// cuando el área de trabajo cambió (otro monitor, taskbar movida).
	var lastDock struct{ w, h int }
	dockPanel := func() {
		screen := app.Screen.GetPrimary()
		if screen == nil {
			return
		}
		w := screen.WorkArea
		if lastDock.w == w.Width && lastDock.h == w.Height {
			return
		}
		lastDock.w, lastDock.h = w.Width, w.Height
		h := w.Height * 84 / 100
		if h > 940 {
			h = 940
		}
		panel.SetSize(panelWidth, h)
		panel.SetPosition(w.X+w.Width-panelWidth-2, w.Y+w.Height-h-108)
	}
	// showPanel siempre via este helper: el contenido "emerge" desde el
	// indicador (animación de entrada disparada por el evento panel-show).
	showPanel := func() {
		dockPanel()
		panel.Show()
		app.Event.Emit("panel-show", nil)
	}

	// Burbuja de estado: widget flotante abajo a la izquierda (§12.1),
	// transparente, siempre visible, con ondas animadas por estado.
	// Más ancho que alto: deja espacio para el "susurro" de estado.
	const widgetW, widgetH = 210, 150
	widget := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard estado",
		Frameless:        true,
		AlwaysOnTop:      true,
		Width:            widgetW,
		Height:           widgetH,
		DisableResize:    true,
		BackgroundType:   application.BackgroundTypeTransparent,
		BackgroundColour: application.RGBA{Red: 0, Green: 0, Blue: 0, Alpha: 0},
		URL:              "/widget.html",
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
			// Sin esto, Windows dibuja borde y sombra alrededor de la
			// ventana frameless — el "borde feo".
			DisableFramelessWindowDecorations: true,
		},
	})
	// Abajo a la DERECHA: el panel lateral emerge visualmente del indicador.
	dockWidget := func() {
		screen := app.Screen.GetPrimary()
		if screen == nil {
			return
		}
		w := screen.WorkArea
		x, y := w.X+w.Width-widgetW-2, w.Y+w.Height-widgetH-2
		widget.SetPosition(x, y)
		// Verificar de verdad: si la ventana aún no estaba realizada, el
		// SetPosition se pierde en silencio y el orbe queda centrado.
		if gx, gy := widget.Position(); gx != x || gy != y {
			log.Printf("orbe: reposicionando (%d,%d)→(%d,%d)", gx, gy, x, y)
			widget.SetPosition(x, y)
		}
	}
	// El evento ApplicationStarted llega antes de que la ventana exista:
	// se reintenta hasta que el orbe quede en su esquina.
	dockWidgetSeguro := func() {
		go func() {
			for _, d := range []time.Duration{0, 300 * time.Millisecond, 1 * time.Second, 3 * time.Second} {
				time.Sleep(d)
				application.InvokeAsync(dockWidget)
			}
		}()
	}

	tray := app.SystemTray.New()
	ts := &trayState{tray: tray, emit: func(state, tooltip string) {
		app.Event.Emit("state", map[string]string{"state": state, "tooltip": tooltip})
	}}
	ts.set("idle", "aún no has commiteado en un proyecto vigilado")

	// Clic en la burbuja: alterna el panel (cierre con animación de plegado).
	app.Event.On("widget-click", func(*application.CustomEvent) {
		application.InvokeAsync(func() {
			if panel.IsVisible() {
				app.Event.Emit("panel-hide", nil)
			} else {
				showPanel()
			}
		})
	})
	// La burbuja pide su estado al cargar.
	app.Event.On("widget-ready", func(*application.CustomEvent) {})

	menu := application.NewMenu()
	menu.Add("Mostrar panel").OnClick(func(*application.Context) { showPanel() })
	menu.Add("Ocultar panel").OnClick(func(*application.Context) { app.Event.Emit("panel-hide", nil) })
	menu.Add("Mostrar/ocultar burbuja").OnClick(func(*application.Context) {
		application.InvokeAsync(func() {
			if widget.IsVisible() {
				widget.Hide()
			} else {
				dockWidget()
				widget.Show()
			}
		})
	})
	menu.AddSeparator()
	menu.Add("Explorador de código 3D").OnClick(func(*application.Context) {
		app.Event.Emit("open-graph", nil)
	})
	menu.Add("Guía de uso").OnClick(func(*application.Context) {
		app.Event.Emit("open-guide", nil)
	})
	menu.AddSeparator()
	menu.Add("Demo de estados (12 s)").OnClick(func(*application.Context) {
		go func() {
			states := []string{"idle", "working", "pass", "blocked", "degraded", "offline"}
			for _, s := range states {
				ts.set(s, "demo del estado «"+s+"»")
				time.Sleep(2 * time.Second)
			}
			ts.set("idle", "demo terminada")
		}()
	})
	menu.AddSeparator()
	menu.Add("Salir de CodeGuard").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(menu)

	// Clic izquierdo en el ícono: alterna el panel (§12 — consultable siempre
	// desde la bandeja; cerrarlo nunca detiene el daemon).
	tray.OnClick(func() {
		application.InvokeAsync(func() {
			if panel.IsVisible() {
				app.Event.Emit("panel-hide", nil)
			} else {
				showPanel()
			}
		})
	})

	// El ✕ del panel solo lo oculta; el proceso sigue en la bandeja.
	app.Event.On("panel-close", func(*application.CustomEvent) {
		application.InvokeAsync(func() { panel.Hide() })
	})

	// ── Contexto POR PROYECTO ──────────────────────────────────────────────
	// Cada repo mantiene su propio estado y su propia historia. El orbe
	// refleja SIEMPRE el proyecto del último análisis — un bloqueo en el
	// repo A jamás secuestra el verde del repo B. Los demás proyectos se
	// listan en el panel para poder cambiar de contexto, nada más.
	var lastPayload *panelPayload           // contexto activo (el último analizado)
	repoState := map[string]*panelPayload{} // contexto de cada proyecto
	var stateMu sync.Mutex

	// Proyectos enrolados en la máquina (desde `codeguard init`), aunque aún
	// no hayan commiteado: aparecen en la lista desde el primer día.
	for _, r := range registry.Load() {
		repoState[filepath.ToSlash(r.Root)] = &panelPayload{
			Repo: r.Nombre, RepoRoot: filepath.ToSlash(r.Root), Verdict: "—", At: "sin análisis",
		}
	}

	// listaProyectos: TODOS los proyectos con su estado (incluido el activo),
	// para que de un vistazo se vea cuál está en verde y cuál bloqueado.
	listaProyectos := func(activeRoot string) []string {
		stateMu.Lock()
		defer stateMu.Unlock()
		var out []string
		for root, p := range repoState {
			// Un proyecto cuya carpeta ya no existe no es un proyecto. El
			// daemon añade a repoState cada repo que analiza y antes no lo
			// quitaba nunca: un repo borrado seguía en el panel hasta
			// reiniciar el agente. Se olvida aquí y también del registro.
			if _, err := os.Stat(filepath.FromSlash(root)); err != nil {
				delete(repoState, root)
				go registry.Remove(root)
				continue
			}
			mark := "○" // sin análisis todavía
			switch p.Verdict {
			case "block":
				mark = "⛔"
			case "pass", "skipped":
				mark = "✓"
			}
			activo := "0"
			if root == activeRoot {
				activo = "1"
			}
			// formato: marca|nombre|ruta|activo
			out = append(out, fmt.Sprintf("%s|%s|%s|%s", mark, p.Repo, root, activo))
		}
		sort.Slice(out, func(i, j int) bool {
			return strings.SplitN(out[i], "|", 3)[1] < strings.SplitN(out[j], "|", 3)[1]
		})
		return out
	}

	// Feedback del panel → tabla feedback (etapa 9).
	app.Event.On("feedback", func(e *application.CustomEvent) {
		raw, _ := json.Marshal(e.Data)
		var items []struct {
			FindingID string `json:"finding_id"`
			Verdict   string `json:"verdict"`
		}
		if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
			log.Println("feedback ilegible:", err)
			return
		}
		st, err := store.Open(store.DefaultPath())
		if err != nil {
			log.Println("feedback: no se pudo abrir la BD:", err)
			return
		}
		defer st.Close()
		for _, it := range items {
			if err := st.SaveFeedback(it.FindingID, it.Verdict, ""); err != nil {
				log.Println("feedback:", err)
			}
		}
	})

	// El panel pide el contexto activo al abrirse.
	app.Event.On("panel-ready", func(*application.CustomEvent) {
		if lastPayload != nil {
			app.Event.Emit("analysis", lastPayload)
		}
	})

	// Cambio de contexto: el panel pide ver otro proyecto. Cada uno conserva
	// su propio análisis; cambiar de contexto no altera el estado de nadie.
	app.Event.On("switch-repo", func(e *application.CustomEvent) {
		raw, _ := json.Marshal(e.Data)
		var roots []string
		if json.Unmarshal(raw, &roots) != nil || len(roots) == 0 {
			var one string
			if json.Unmarshal(raw, &one) == nil {
				roots = []string{one}
			}
		}
		if len(roots) == 0 {
			return
		}
		stateMu.Lock()
		p := repoState[roots[0]]
		stateMu.Unlock()
		if p == nil {
			return
		}
		p.OtrosRepos = listaProyectos(p.RepoRoot)
		lastPayload = p // el contexto activo pasa a ser el elegido
		raizConfig.Store(p.RepoRoot)
		app.Event.Emit("analysis", p)
		ts.set(orbStateFor(p), fmt.Sprintf("%s · rama %s · %s",
			p.Repo, p.Branch, resumenHallazgos(p.Blocking, p.Advisory)))
	})

	// Botón 🕸: el explorador de código en su PROPIA ventana del agente
	// (nada de navegador) con el análisis proyectado encima.
	var explorer *application.WebviewWindow
	var pendingGraph *codegraph.Graph
	// La página avisa cuando cargó; recién entonces se le manda el grafo.
	app.Event.On("explorer-ready", func(*application.CustomEvent) {
		if pendingGraph != nil {
			app.Event.Emit("graph-data", pendingGraph)
		}
	})
	// openGraph construye el explorador de UN proyecto (nunca mezcla sistemas)
	// e incluye la lista de los demás para poder cambiar de contexto.
	openGraph := func(root string) {
		stateMu.Lock()
		payload := repoState[root]
		var proyectos []codegraph.Proyecto
		for r, p := range repoState {
			proyectos = append(proyectos, codegraph.Proyecto{
				Nombre: p.Repo, Root: r, Activo: r == root, Estado: p.Verdict,
			})
		}
		stateMu.Unlock()
		sort.Slice(proyectos, func(i, j int) bool { return proyectos[i].Nombre < proyectos[j].Nombre })
		repoRoot := filepath.FromSlash(root)
		nombre := filepath.Base(repoRoot)
		if payload != nil {
			nombre = payload.Repo
		}
		go func() {
			// La ventana se abre SIEMPRE. Antes, cualquiera de estos fallos
			// hacía que el botón no hiciera absolutamente nada: sin ventana,
			// sin mensaje, sólo una línea en un log que nadie mira.
			cg, err := codegraph.Build(repoRoot)
			var motivo string
			switch {
			case err != nil:
				motivo = "No pude leer el código de este proyecto: " + err.Error()
			case cg == nil || len(cg.Nodes) == 0:
				motivo = "No encontré funciones que mapear en " + nombre + ".\n\n" +
					"El explorador entiende Go (por go.mod) y TypeScript/JavaScript " +
					"(por package.json). Si este proyecto usa otro lenguaje, todavía no está cubierto."
			}
			if motivo != "" {
				log.Printf("grafo de %s no disponible: %s", nombre, strings.SplitN(motivo, "\n", 2)[0])
				cg = &codegraph.Graph{Root: root, Error: motivo}
			} else if payload != nil {
				// Sin análisis previo no hay hallazgos que superponer, pero el
				// mapa del código se puede ver igual.
				cg.Overlay = buildOverlay(cg, payload)
			}
			cg.Proyectos = proyectos
			data, err := json.Marshal(cg)
			if err != nil {
				log.Println("grafo: no se pudo serializar:", err)
				data = []byte(`{"nodes":[],"edges":[],"error":"no se pudo preparar el grafo"}`)
			}
			graphJSON.Store(data)
			if motivo == "" {
				log.Printf("grafo de %s: %d nodos, %d aristas (%d KB servidos en /graph.json)",
					nombre, len(cg.Nodes), len(cg.Edges), len(data)/1024)
			}
			application.InvokeAsync(func() {
				if explorer != nil {
					explorer.Close()
					explorer = nil
				}
				w, h := 1280, 820
				if screen := app.Screen.GetPrimary(); screen != nil {
					if screen.WorkArea.Width < w+80 {
						w = screen.WorkArea.Width - 80
					}
					if screen.WorkArea.Height < h+80 {
						h = screen.WorkArea.Height - 80
					}
				}
				explorer = app.Window.NewWithOptions(application.WebviewWindowOptions{
					Title:            "CodeGuard — explorador de código",
					Width:            w,
					Height:           h,
					URL:              "/explorer.html",
					BackgroundColour: application.RGBA{Red: 11, Green: 14, Blue: 17, Alpha: 255},
				})
				explorer.Center()
				explorer.Show()
			})
		}()
	}

	// ── Configuración del modelo, en su propia ventana ──
	var ventanaConfig *application.WebviewWindow
	app.Event.On("open-config", func(*application.CustomEvent) {
		application.InvokeAsync(func() {
			if ventanaConfig != nil {
				ventanaConfig.Close()
			}
			ventanaConfig = app.Window.NewWithOptions(application.WebviewWindowOptions{
				Title:            "CodeGuard — configuración del modelo",
				Width:            860,
				Height:           820,
				URL:              "/config.html",
				BackgroundColour: application.RGBA{Red: 14, Green: 17, Blue: 20, Alpha: 255},
			})
			ventanaConfig.Center()
			ventanaConfig.Show()
		})
	})
	responderConfig := func(bien bool, mensaje string, recargar bool) {
		app.Event.Emit("llm-resultado", map[string]any{
			"bien": bien, "mensaje": mensaje, "recargar": recargar,
		})
	}
	app.Event.On("llm-probar", func(e *application.CustomEvent) {
		g, err := decodificarConfigLLM(e)
		if err != nil {
			responderConfig(false, "no entendí el formulario: "+err.Error(), false)
			return
		}
		go func() {
			detalle, err := probarConfigLLM(g)
			if err != nil {
				responderConfig(false, "<b>No respondió.</b><br><code>"+escaparHTML(err.Error())+"</code>", false)
				return
			}
			responderConfig(true, "<b>Conexión correcta.</b> "+escaparHTML(detalle), false)
		}()
	})
	app.Event.On("llm-guardar", func(e *application.CustomEvent) {
		g, err := decodificarConfigLLM(e)
		if err != nil {
			responderConfig(false, "no entendí el formulario: "+err.Error(), false)
			return
		}
		if err := guardarLLMLocal(g); err != nil {
			responderConfig(false, "<b>No se pudo guardar.</b><br><code>"+escaparHTML(err.Error())+"</code>", false)
			return
		}
		if g.Restaurar {
			log.Println("configuración del modelo: se restauró la del equipo")
			responderConfig(true, "<b>Listo.</b> Vuelves a usar la configuración del equipo.", true)
			return
		}
		log.Printf("configuración del modelo: %s · %s (local)", g.Provider, g.Model)
		responderConfig(true, "<b>Guardado.</b> Se aplica desde el próximo commit.", true)
	})

	app.Event.On("open-graph", func(e *application.CustomEvent) {
		// El panel manda la raíz del proyecto que se está viendo. Sin ella
		// —p.ej. desde el menú de la bandeja— se cae al último analizado.
		if roots := rootsDelEvento(e); len(roots) > 0 && roots[0] != "" {
			openGraph(roots[0])
			return
		}
		if lastPayload == nil {
			log.Println("grafo: aún no hay proyecto activo")
			return
		}
		openGraph(lastPayload.RepoRoot)
	})

	// Guía de uso paso a paso, en su propia ventana.
	var guia *application.WebviewWindow
	app.Event.On("open-guide", func(*application.CustomEvent) {
		application.InvokeAsync(func() {
			if guia != nil {
				guia.Close()
			}
			w, h := 1020, 760
			if screen := app.Screen.GetPrimary(); screen != nil {
				if screen.WorkArea.Width < w+80 {
					w = screen.WorkArea.Width - 80
				}
				if screen.WorkArea.Height < h+80 {
					h = screen.WorkArea.Height - 80
				}
			}
			guia = app.Window.NewWithOptions(application.WebviewWindowOptions{
				Title:            "CodeGuard — guía de uso",
				Width:            w,
				Height:           h,
				URL:              "/guia.html",
				BackgroundColour: application.RGBA{Red: 18, Green: 20, Blue: 23, Alpha: 255},
			})
			guia.Center()
			guia.Show()
		})
	})
	// El explorador pide cambiar al grafo de otro proyecto.
	app.Event.On("graph-switch", func(e *application.CustomEvent) {
		if roots := rootsDelEvento(e); len(roots) > 0 {
			openGraph(roots[0])
		}
	})

	shadowStore, err := store.Open(store.DefaultPath())
	if err != nil {
		log.Println("sombra desactivada — no se pudo abrir la BD:", err)
	}
	var shadowRunner *shadow.Runner
	if shadowStore != nil {
		// El razonamiento del modelo se transmite al panel, con acelerador:
		// muchos deltas pequeños → una emisión cada ~350 ms con la cola.
		var thinkMu sync.Mutex
		var thinkBuf string
		var lastEmit time.Time
		shadowRunner = &shadow.Runner{
			Store: shadowStore,
			OnThinking: func(pillar, text string) {
				if pillar == "" && text == "" {
					app.Event.Emit("thinking", map[string]string{"pillar": "", "text": ""})
					return
				}
				thinkMu.Lock()
				defer thinkMu.Unlock()
				thinkBuf += text
				if len(thinkBuf) > 140 {
					thinkBuf = thinkBuf[len(thinkBuf)-140:]
				}
				if time.Since(lastEmit) < 350*time.Millisecond {
					return
				}
				lastEmit = time.Now()
				app.Event.Emit("thinking", map[string]string{"pillar": pillar, "text": thinkBuf})
			},
		}
	}

	srv := &daemon.Server{
		Shadow: shadowRunner,
		// La CLI pide acciones de UI: el explorador abre en la ventana del
		// agente, nunca en un navegador.
		OnCommand: func(cmd, root string) {
			switch cmd {
			case "open-graph":
				openGraph(filepath.ToSlash(root))
			case "open-config":
				if root != "" {
					raizConfig.Store(filepath.ToSlash(root))
				}
				app.Event.Emit("open-config", nil)
			default:
				log.Println("comando desconocido desde la CLI:", cmd)
			}
		},
		OnRequest: func(req *ipc.Request) {
			// Re-anclar por si cambió la resolución o se movió la barra.
			application.InvokeAsync(dockWidget)
			repo := filepath.Base(req.RepoRoot)
			ts.set("working", "revisando "+repo+" · rama "+req.Branch)
			app.Event.Emit("working", map[string]string{"repo": repo, "branch": req.Branch})
		},
		OnResult: func(req *ipc.Request, resp *ipc.Response) {
			cfg, _ := config.Load(req.RepoRoot)
			maxShow := 7
			autoOpen := "on_block"
			if cfg != nil {
				if cfg.UI.MaxVisibleFindings > 0 {
					maxShow = cfg.UI.MaxVisibleFindings
				}
				if cfg.UI.AutoOpenPanel != "" {
					autoOpen = cfg.UI.AutoOpenPanel
				}
			}
			payload := &panelPayload{
				Repo:        filepath.Base(req.RepoRoot),
				RepoRoot:    filepath.ToSlash(req.RepoRoot),
				Branch:      req.Branch,
				AIGenerated: req.AIGenerated,
				Suppressed:  resp.Suppressed,
				Verdict:     resp.Verdict,
				Blocking:    resp.BlockingFindings,
				Advisory:    resp.AdvisoryFindings,
				CIParity:    resp.CIParity,
				Degraded:    resp.Degraded,
				MaxShow:     maxShow,
				ElapsedMs:   resp.ElapsedMs,
				At:          time.Now().Format("15:04:05"),
			}
			for _, f := range resp.Findings {
				payload.Findings = append(payload.Findings, panelFinding{
					Finding: f,
					Snippet: snippet(req.RepoRoot, f.File, f.Line),
					IsFact:  f.Source == finding.Deterministic,
				})
			}
			// cada proyecto guarda su contexto; el activo pasa a ser este
			stateMu.Lock()
			repoState[payload.RepoRoot] = payload
			stateMu.Unlock()
			payload.OtrosRepos = listaProyectos(payload.RepoRoot)
			lastPayload = payload
			raizConfig.Store(payload.RepoRoot)

			// "3 bloqueantes, 1 avisos" es un contador, no una frase. Esto se
			// lee de un vistazo y en singular cuando toca.
			tooltip := fmt.Sprintf("%s · rama %s · %s", payload.Repo, payload.Branch,
				resumenHallazgos(payload.Blocking, payload.Advisory))
			// motores ausentes = asunto de configuración, no degradación real:
			// un trivy no instalado no debe pintar de naranja cada commit.
			realDegraded := len(resp.Degraded) > 0 && !pipeline.SoloFaltantes(resp.Degraded)
			// El orbe habla SOLO del proyecto que acabas de tocar.
			switch {
			case resp.Verdict == "block":
				ts.set("blocked", tooltip)
			case realDegraded:
				ts.set("degraded", tooltip+" — no corrió: "+strings.Join(resp.Degraded, ", "))
			default:
				ts.setPass(tooltip)
			}

			app.Event.Emit("analysis", payload)
			shouldOpen := autoOpen == "on_findings" && len(resp.Findings) > 0 ||
				autoOpen != "never" && resp.Verdict == "block"
			if shouldOpen {
				// Las ventanas se tocan desde el hilo de la UI.
				application.InvokeAsync(showPanel)
			}

			// Diferenciador D1: el modelo explica los bloqueantes en español
			// claro, sobre TU código. Async, cacheado por fingerprint — el
			// commit ya fue decidido; esto solo enriquece el panel.
			if cfg != nil && resp.Verdict == "block" {
				go explainBlockers(app, cfg, req, resp)
			}
		},
	}

	// Anclar el orbe en su esquina al arrancar (con reintentos).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		dockWidgetSeguro()
	})

	ctx, cancel := context.WithCancel(context.Background())
	app.OnShutdown(cancel)
	go func() {
		// El tray refleja "working" mientras el server atiende: el propio
		// handler emite el estado al entrar la petición (ver ipc hook abajo).
		if err := srv.Serve(ctx); err != nil {
			log.Println("servidor IPC:", err)
		}
	}()

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
