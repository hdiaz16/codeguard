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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/shadow"
	"codeguard/internal/store"
)

//go:embed all:frontend
var assets embed.FS

const panelWidth = 420

// panelFinding es lo que pinta el panel: el hallazgo + su código señalado.
type panelFinding struct {
	finding.Finding
	Snippet      []snippetLine `json:"snippet"`
	// Tono §12.2: determinista se enuncia como hecho; el LLM (fase 3+) como observación.
	IsFact bool `json:"is_fact"`
}

type snippetLine struct {
	No      int    `json:"no"`
	Text    string `json:"text"`
	Culprit bool   `json:"culprit"`
}

type panelPayload struct {
	Repo        string `json:"repo"`
	RepoRoot    string `json:"repo_root"`
	Branch      string `json:"branch"`
	AIGenerated bool   `json:"ai_generated"`
	Suppressed  int    `json:"suppressed"`
	Verdict   string         `json:"verdict"`
	Blocking  int            `json:"blocking"`
	Advisory  int            `json:"advisory"`
	CIParity  bool           `json:"ci_parity"`
	Degraded  []string       `json:"degraded"`
	Findings  []panelFinding `json:"findings"`
	MaxShow   int            `json:"max_show"`
	ElapsedMs int64          `json:"elapsed_ms"`
	At        string         `json:"at"`
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

type trayState struct {
	tray  *application.SystemTray
	reset *time.Timer
	emit  func(state, tooltip string)
}

func (t *trayState) set(state, tooltip string) {
	t.tray.SetIcon(trayIcon(state))
	t.tray.SetLabel("CodeGuard: " + state)
	t.tray.SetTooltip("CodeGuard [" + state + "] — " + tooltip)
	// La burbuja flotante escucha el mismo estado.
	if t.emit != nil {
		t.emit(state, tooltip)
	}
}

// pass vuelve a idle a los 10 s (§12.1).
func (t *trayState) setPass(tooltip string) {
	t.set("pass", tooltip)
	if t.reset != nil {
		t.reset.Stop()
	}
	t.reset = time.AfterFunc(10*time.Second, func() { t.set("idle", tooltip) })
}

func main() {
	frontend, err := fs.Sub(assets, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	app := application.New(application.Options{
		Name: "CodeGuard",
		Assets: application.AssetOptions{
			// BundledAssetFileServer sirve también /wails/runtime.js,
			// que el panel importa para los eventos.
			Handler: application.BundledAssetFileServer(frontend),
		},
	})

	// Sin ventana principal: el panel y la burbuja son las únicas ventanas.
	// Una ventana oculta extra costaba un renderer de WebView2 (~60 MB).
	panel := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard",
		Frameless:        true,
		AlwaysOnTop:      true,
		Hidden:           true, // §12.2: oculto mientras no haya nada que mostrar
		Width:            panelWidth,
		Height:           600,
		DisableResize:    true,
		URL:              "/",
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
	dockPanel := func() {
		if screen := app.Screen.GetPrimary(); screen != nil {
			w := screen.WorkArea
			h := w.Height * 72 / 100
			if h > 780 {
				h = 780
			}
			panel.SetSize(panelWidth, h)
			panel.SetPosition(w.X+w.Width-panelWidth-2, w.Y+w.Height-h-108)
		}
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
		if screen := app.Screen.GetPrimary(); screen != nil {
			w := screen.WorkArea
			widget.SetPosition(w.X+w.Width-widgetW-2, w.Y+w.Height-widgetH-2)
		}
	}

	tray := app.SystemTray.New()
	ts := &trayState{tray: tray, emit: func(state, tooltip string) {
		app.Event.Emit("state", map[string]string{"state": state, "tooltip": tooltip})
	}}
	ts.set("idle", "sin análisis todavía")

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

	var lastPayload *panelPayload

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

	// El panel pide el último resultado al abrirse.
	app.Event.On("panel-ready", func(*application.CustomEvent) {
		if lastPayload != nil {
			app.Event.Emit("analysis", lastPayload)
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
		OnRequest: func(req *ipc.Request) {
			repo := filepath.Base(req.RepoRoot)
			ts.set("working", "analizando "+repo+"@"+req.Branch+"…")
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
				Verdict:   resp.Verdict,
				Blocking:  resp.BlockingFindings,
				Advisory:  resp.AdvisoryFindings,
				CIParity:  resp.CIParity,
				Degraded:  resp.Degraded,
				MaxShow:   maxShow,
				ElapsedMs: resp.ElapsedMs,
				At:        time.Now().Format("15:04:05"),
			}
			for _, f := range resp.Findings {
				payload.Findings = append(payload.Findings, panelFinding{
					Finding: f,
					Snippet: snippet(req.RepoRoot, f.File, f.Line),
					IsFact:  f.Source == finding.Deterministic,
				})
			}
			lastPayload = payload

			tooltip := fmt.Sprintf("%s@%s: %d bloqueantes, %d avisos (%s)",
				payload.Repo, payload.Branch, payload.Blocking, payload.Advisory, payload.At)
			switch {
			case resp.Verdict == "block":
				ts.set("blocked", tooltip)
			case len(resp.Degraded) > 0:
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

	// Anclar la burbuja abajo a la izquierda al arrancar.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		dockWidget()
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
