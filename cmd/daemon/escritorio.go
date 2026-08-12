package main

import (
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

// 300x180 aloja el orbe de 84 px anclado abajo-derecha más la burbuja, que
// crece hacia arriba y a la izquierda. Si cambia el tamaño del orbe en
// widget.html, esto no necesita cambiar: el orbe se ancla solo.
const widgetW, widgetH = 300, 180

// escritorio agrupa lo que antes vivía suelto dentro de main(): las ventanas,
// el contexto de cada proyecto y lo que el orbe muestra. Todo ese estado
// estaba atrapado en cierres de una sola función de 744 líneas, y por eso no
// había forma de probar nada —ni el sembrado del panel al reiniciar— sin
// arrancar Wails y mirar la pantalla. Aquí es estado con nombre y con métodos.
type escritorio struct {
	app *application.App
	// Sin ventana principal: el panel y la burbuja son las únicas ventanas
	// permanentes. Una ventana oculta extra costaba un renderer de WebView2
	// (~60 MB). Las otras tres nacen y mueren con su botón.
	panel         *application.WebviewWindow
	widget        *application.WebviewWindow
	explorador    *application.WebviewWindow
	ventanaConfig *application.WebviewWindow
	guia          *application.WebviewWindow
	tray          *trayState

	// ── Contexto POR PROYECTO ──────────────────────────────────────────────
	// Cada repo mantiene su propio estado y su propia historia. El orbe
	// refleja SIEMPRE el proyecto del último análisis — un bloqueo en el
	// repo A jamás secuestra el verde del repo B. Los demás proyectos se
	// listan en el panel para poder cambiar de contexto, nada más.
	mu          sync.Mutex
	porProyecto map[string]*panelPayload // contexto de cada proyecto
	activo      *panelPayload            // contexto activo (el último analizado)

	// raizConfig es la raíz desde la que se lee la configuración del modelo.
	// Se actualiza con cada análisis; sin ninguno todavía, sirve cualquier
	// repo enrolado —la configuración del modelo suele ser la misma para todos.
	raizConfig atomic.Value // string
	// El grafo puede pesar cientos de KB: viaja por HTTP interno, no por el
	// bus de eventos (ahí llegaba vacío). El explorador hace fetch("/graph.json").
	grafoJSON atomic.Value // []byte
	// grafoPendiente es el grafo que el explorador recibiría por el bus en
	// cuanto avisa que cargó. Desde que el grafo viaja por HTTP nadie lo
	// llena, y el manejador de explorer-ready no encuentra nada que mandar.
	grafoPendiente *codegraph.Graph

	// Redimensionar un WebView en cada apertura causa lag: el panel solo se
	// acomoda cuando el área de trabajo cambió (otro monitor, taskbar movida).
	ultimoAnclaje struct{ w, h int }

	// cargarRepos y olvidarRepo son la puerta al registro de proyectos de la
	// máquina. Son campos y no llamadas directas a registry porque el sembrado
	// del panel es justo la lógica que se rompió en producción y hay que poder
	// ejercitarla en una prueba sin tocar el registro real del usuario.
	cargarRepos func() []registry.Repo
	olvidarRepo func(raiz string)
}

// nuevoEscritorio deja el estado listo ANTES de que exista la aplicación: el
// manejador HTTP se construye desde aquí y Wails lo pide al crearse.
func nuevoEscritorio() *escritorio {
	e := &escritorio{
		porProyecto: map[string]*panelPayload{},
		cargarRepos: registry.Load,
		olvidarRepo: func(raiz string) { go registry.Remove(raiz) },
	}
	e.grafoJSON.Store([]byte(`{"nodes":[],"edges":[]}`))
	// Proyectos enrolados en la máquina (desde `codeguard init`), aunque aún
	// no hayan commiteado: aparecen en la lista desde el primer día.
	e.altaDeProyectosEnrolados()
	return e
}

// ── Servidor interno ─────────────────────────────────────────────────────────

// manejadorHTTP monta lo que sirve la aplicación: los assets embebidos y las
// dos rutas propias.
func (e *escritorio) manejadorHTTP() http.Handler {
	frontend, err := fs.Sub(assets, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	assetsFS := application.BundledAssetFileServer(frontend)
	handler := http.NewServeMux()
	handler.HandleFunc("/graph.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(e.grafoJSON.Load().([]byte))
	})
	// Igual que el grafo: la configuración se sirve por HTTP y no por eventos.
	handler.HandleFunc("/config-llm.json", func(w http.ResponseWriter, r *http.Request) {
		raiz, _ := e.raizConfig.Load().(string)
		if raiz == "" {
			if repos := e.cargarRepos(); len(repos) > 0 {
				raiz = repos[0].Root
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(leerConfigLLM(filepath.FromSlash(raiz)))
	})
	handler.Handle("/", assetsFS)
	return handler
}

// ── Ventanas ─────────────────────────────────────────────────────────────────

// construirVentanas crea las dos ventanas permanentes. El panel nace oculto
// (§12.2: oculto mientras no haya nada que mostrar); la burbuja, visible.
func (e *escritorio) construirVentanas() {
	e.panel = e.construirPanel()
	e.widget = e.construirBurbuja()
}

func (e *escritorio) construirPanel() *application.WebviewWindow {
	return e.app.Window.NewWithOptions(application.WebviewWindowOptions{
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
}

// construirBurbuja arma el widget flotante de estado (§12.1), transparente,
// siempre visible, con ondas animadas por estado.
//
// El orbe se ancla abajo-derecha; el resto de la ventana es aire transparente
// para que la burbuja quepa arriba y a la izquierda sin recortarse. Agrandarla
// no mueve el orbe: sigue en la misma esquina.
func (e *escritorio) construirBurbuja() *application.WebviewWindow {
	return e.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard estado",
		Frameless:        true,
		AlwaysOnTop:      true,
		Width:            widgetW,
		Height:           widgetH,
		DisableResize:    true,
		BackgroundType:   application.BackgroundTypeTransparent,
		BackgroundColour: application.RGBA{Red: 0, Green: 0, Blue: 0, Alpha: 0},
		URL:              "/widget.html",
		// OJO: no usar IgnoreMouseEvents aquí. En Windows Wails lo implementa
		// añadiendo WS_EX_LAYERED junto a WS_EX_TRANSPARENT, y una ventana
		// layered deja de componerse con transparencia real: el orbe se
		// convierte en un rectángulo blanco opaco. Se probó y se revirtió.
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
			// Sin esto, Windows dibuja borde y sombra alrededor de la
			// ventana frameless — el "borde feo".
			DisableFramelessWindowDecorations: true,
		},
	})
}

// anclarPanel deja la tarjeta flotante anclada sobre el orbe (abajo-derecha),
// no muro completo. Redimensionar un WebView en cada apertura causa lag: solo
// se acomoda cuando el área de trabajo cambió (otro monitor, taskbar movida).
func (e *escritorio) anclarPanel() {
	screen := e.app.Screen.GetPrimary()
	if screen == nil {
		return
	}
	w := screen.WorkArea
	if e.ultimoAnclaje.w == w.Width && e.ultimoAnclaje.h == w.Height {
		return
	}
	e.ultimoAnclaje.w, e.ultimoAnclaje.h = w.Width, w.Height
	h := w.Height * 84 / 100
	if h > 940 {
		h = 940
	}
	e.panel.SetSize(panelWidth, h)
	e.panel.SetPosition(w.X+w.Width-panelWidth-2, w.Y+w.Height-h-108)
}

// mostrarPanel: el panel se muestra SIEMPRE por aquí, para que el contenido
// "emerja" desde el indicador (animación de entrada disparada por panel-show).
func (e *escritorio) mostrarPanel() {
	e.anclarPanel()
	e.panel.Show()
	e.app.Event.Emit("panel-show", nil)
}

// alternarPanel es lo que hacen el clic en la burbuja y el clic izquierdo en
// el ícono de la bandeja: si el panel está visible se cierra con animación de
// plegado; si no, emerge.
func (e *escritorio) alternarPanel() {
	if e.panel.IsVisible() {
		e.app.Event.Emit("panel-hide", nil)
	} else {
		e.mostrarPanel()
	}
}

// anclarBurbuja deja el orbe abajo a la DERECHA: el panel lateral emerge
// visualmente del indicador.
func (e *escritorio) anclarBurbuja() {
	screen := e.app.Screen.GetPrimary()
	if screen == nil {
		return
	}
	w := screen.WorkArea
	x, y := w.X+w.Width-widgetW-2, w.Y+w.Height-widgetH-2
	e.widget.SetPosition(x, y)
	// Verificar de verdad: si la ventana aún no estaba realizada, el
	// SetPosition se pierde en silencio y el orbe queda centrado.
	if gx, gy := e.widget.Position(); gx != x || gy != y {
		log.Printf("orbe: reposicionando (%d,%d)→(%d,%d)", gx, gy, x, y)
		e.widget.SetPosition(x, y)
	}
}

// anclarBurbujaSeguro insiste: el evento ApplicationStarted llega antes de que
// la ventana exista, así que se reintenta hasta que el orbe quede en su esquina.
func (e *escritorio) anclarBurbujaSeguro() {
	go func() {
		for _, d := range []time.Duration{0, 300 * time.Millisecond, 1 * time.Second, 3 * time.Second} {
			time.Sleep(d)
			application.InvokeAsync(e.anclarBurbuja)
		}
	}()
}

// tamanoQueQuepa recorta el tamaño pedido para que la ventana entre en el área
// de trabajo con margen. Las ventanas grandes (explorador, guía) nacen así.
func (e *escritorio) tamanoQueQuepa(w, h int) (int, int) {
	if screen := e.app.Screen.GetPrimary(); screen != nil {
		if screen.WorkArea.Width < w+80 {
			w = screen.WorkArea.Width - 80
		}
		if screen.WorkArea.Height < h+80 {
			h = screen.WorkArea.Height - 80
		}
	}
	return w, h
}

// abrirConfig abre la configuración del modelo, en su propia ventana.
func (e *escritorio) abrirConfig() {
	if e.ventanaConfig != nil {
		e.ventanaConfig.Close()
	}
	e.ventanaConfig = e.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard — configuración del modelo",
		Width:            860,
		Height:           820,
		URL:              "/config.html",
		BackgroundColour: application.RGBA{Red: 14, Green: 17, Blue: 20, Alpha: 255},
	})
	e.ventanaConfig.Center()
	e.ventanaConfig.Show()
}

// abrirGuia abre la guía de uso paso a paso, en su propia ventana.
func (e *escritorio) abrirGuia() {
	if e.guia != nil {
		e.guia.Close()
	}
	w, h := e.tamanoQueQuepa(1020, 760)
	e.guia = e.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard — guía de uso",
		Width:            w,
		Height:           h,
		URL:              "/guia.html",
		BackgroundColour: application.RGBA{Red: 18, Green: 20, Blue: 23, Alpha: 255},
	})
	e.guia.Center()
	e.guia.Show()
}

// ── Bandeja ──────────────────────────────────────────────────────────────────

func (e *escritorio) construirBandeja() {
	tray := e.app.SystemTray.New()
	e.tray = &trayState{tray: tray, emit: func(state, tooltip string) {
		e.app.Event.Emit("state", map[string]string{"state": state, "tooltip": tooltip})
	}}
	e.tray.set("idle", "aún no has commiteado en un proyecto vigilado")
	tray.SetMenu(e.menuBandeja())
	// Clic izquierdo en el ícono: alterna el panel (§12 — consultable siempre
	// desde la bandeja; cerrarlo nunca detiene el daemon).
	tray.OnClick(func() {
		application.InvokeAsync(e.alternarPanel)
	})
}

func (e *escritorio) menuBandeja() *application.Menu {
	menu := application.NewMenu()
	// La versión instalada, visible donde el usuario ya mira: era invisible
	// (ni el menú, ni el panel, ni `codeguard version` la decían).
	menu.Add("CodeGuard " + version).SetEnabled(false)
	menu.AddSeparator()
	menu.Add("Mostrar panel").OnClick(func(*application.Context) { e.mostrarPanel() })
	menu.Add("Ocultar panel").OnClick(func(*application.Context) { e.app.Event.Emit("panel-hide", nil) })
	menu.Add("Mostrar/ocultar burbuja").OnClick(func(*application.Context) {
		application.InvokeAsync(func() {
			if e.widget.IsVisible() {
				e.widget.Hide()
			} else {
				e.anclarBurbuja()
				e.widget.Show()
			}
		})
	})
	menu.AddSeparator()
	menu.Add("Explorador de código 3D").OnClick(func(*application.Context) {
		e.app.Event.Emit("open-graph", nil)
	})
	menu.Add("Guía de uso").OnClick(func(*application.Context) {
		e.app.Event.Emit("open-guide", nil)
	})
	menu.AddSeparator()
	menu.Add("Demo de estados (12 s)").OnClick(func(*application.Context) {
		go func() {
			states := []string{"idle", "working", "pass", "blocked", "degraded", "offline"}
			for _, s := range states {
				e.tray.set(s, "demo del estado «"+s+"»")
				time.Sleep(2 * time.Second)
			}
			e.tray.set("idle", "demo terminada")
		}()
	})
	menu.AddSeparator()
	menu.Add("Salir de CodeGuard").OnClick(func(*application.Context) { e.app.Quit() })
	return menu
}

// ── Eventos ──────────────────────────────────────────────────────────────────

// registrarEventos conecta el bus de la aplicación con el escritorio. Son
// catorce manejadores y todos son cableado: cada uno delega en un método.
func (e *escritorio) registrarEventos() {
	e.registrarEventosPanel()
	e.registrarEventosVentanas()
	e.registrarEventosModelo()
}

func (e *escritorio) registrarEventosPanel() {
	// Clic en la burbuja: alterna el panel (cierre con animación de plegado).
	e.app.Event.On("widget-click", func(*application.CustomEvent) {
		application.InvokeAsync(e.alternarPanel)
	})
	// La burbuja pide su estado al cargar.
	e.app.Event.On("widget-ready", func(*application.CustomEvent) {})
	// El ✕ del panel solo lo oculta; el proceso sigue en la bandeja.
	e.app.Event.On("panel-close", func(*application.CustomEvent) {
		application.InvokeAsync(func() { e.panel.Hide() })
	})
	// Feedback del panel → tabla feedback (etapa 9).
	e.app.Event.On("feedback", guardarFeedback)
	// El panel pide el contexto activo al abrirse.
	e.app.Event.On("panel-ready", func(*application.CustomEvent) {
		e.mostrarContextoActivo()
	})
	// Cambio de contexto: el panel pide ver otro proyecto. Cada uno conserva
	// su propio análisis; cambiar de contexto no altera el estado de nadie.
	e.app.Event.On("switch-repo", func(ev *application.CustomEvent) {
		raw, _ := json.Marshal(ev.Data)
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
		e.cambiarDeProyecto(roots[0])
	})
}

func (e *escritorio) registrarEventosVentanas() {
	// La página avisa cuando cargó; recién entonces se le manda el grafo.
	e.app.Event.On("explorer-ready", func(*application.CustomEvent) {
		if e.grafoPendiente != nil {
			e.app.Event.Emit("graph-data", e.grafoPendiente)
		}
	})
	// Botón 🕸: el explorador de código en su PROPIA ventana del agente
	// (nada de navegador) con el análisis proyectado encima.
	e.app.Event.On("open-graph", func(ev *application.CustomEvent) {
		// El panel manda la raíz del proyecto que se está viendo. Sin ella
		// —p.ej. desde el menú de la bandeja— se cae al último analizado.
		if roots := rootsDelEvento(ev); len(roots) > 0 && roots[0] != "" {
			e.abrirGrafo(roots[0])
			return
		}
		if e.activo == nil {
			log.Println("grafo: aún no hay proyecto activo")
			return
		}
		e.abrirGrafo(e.activo.RepoRoot)
	})
	// El explorador pide cambiar al grafo de otro proyecto.
	e.app.Event.On("graph-switch", func(ev *application.CustomEvent) {
		if roots := rootsDelEvento(ev); len(roots) > 0 {
			e.abrirGrafo(roots[0])
		}
	})
	e.app.Event.On("open-config", func(*application.CustomEvent) {
		application.InvokeAsync(e.abrirConfig)
	})
	e.app.Event.On("open-guide", func(*application.CustomEvent) {
		application.InvokeAsync(e.abrirGuia)
	})
}

func (e *escritorio) registrarEventosModelo() {
	e.app.Event.On("llm-probar", func(ev *application.CustomEvent) {
		g, err := decodificarConfigLLM(ev)
		if err != nil {
			e.responderConfig(false, "no entendí el formulario: "+err.Error(), false)
			return
		}
		go func() {
			detalle, err := probarConfigLLM(g)
			if err != nil {
				e.responderConfig(false, "<b>No respondió.</b><br><code>"+escaparHTML(err.Error())+"</code>", false)
				return
			}
			e.responderConfig(true, "<b>Conexión correcta.</b> "+escaparHTML(detalle), false)
		}()
	})
	e.app.Event.On("llm-guardar", func(ev *application.CustomEvent) {
		g, err := decodificarConfigLLM(ev)
		if err != nil {
			e.responderConfig(false, "no entendí el formulario: "+err.Error(), false)
			return
		}
		if err := guardarLLMLocal(g); err != nil {
			e.responderConfig(false, "<b>No se pudo guardar.</b><br><code>"+escaparHTML(err.Error())+"</code>", false)
			return
		}
		if g.Restaurar {
			log.Println("configuración del modelo: se restauró la del equipo")
			e.responderConfig(true, "<b>Listo.</b> Vuelves a usar la configuración del equipo.", true)
			return
		}
		log.Printf("configuración del modelo: %s · %s (local)", g.Provider, g.Model)
		e.responderConfig(true, "<b>Guardado.</b> Se aplica desde el próximo commit.", true)
	})
}

func (e *escritorio) responderConfig(bien bool, mensaje string, recargar bool) {
	e.app.Event.Emit("llm-resultado", map[string]any{
		"bien": bien, "mensaje": mensaje, "recargar": recargar,
	})
}

// guardarFeedback lleva el pulgar arriba/abajo del panel a la tabla feedback.
func guardarFeedback(ev *application.CustomEvent) {
	raw, _ := json.Marshal(ev.Data)
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
}

// ── Contexto de los proyectos ────────────────────────────────────────────────

// altaDeProyectosEnrolados añade al mapa los proyectos del registro que aún no
// estén, con su estado placeholder. Exige el candado tomado (o que nadie más
// pueda ver el mapa todavía, como al construir el escritorio).
func (e *escritorio) altaDeProyectosEnrolados() {
	for _, r := range e.cargarRepos() {
		root := filepath.ToSlash(r.Root)
		if _, ya := e.porProyecto[root]; !ya {
			e.porProyecto[root] = &panelPayload{
				Repo: r.Nombre, RepoRoot: root, Verdict: "—", At: "sin análisis",
				// CIParity en true a propósito: el panel enseña el aviso de
				// paridad cuando es false, y el cero de Go es false. Sin esta
				// línea, un proyecto que NUNCA se ha analizado aparecía
				// afirmando "tu rulepack no coincide — no puedo garantizar que
				// pase el CI", que es una acusación inventada sobre un repo
				// perfectamente sano. Pasó con bds.portal en cuanto se sembró
				// el panel desde el registro (1.3.0). La paridad sólo se puede
				// romper cuando un análisis la comprueba; mientras no lo haya,
				// no hay nada que avisar.
				CIParity: true,
			}
		}
	}
}

// listaProyectos: TODOS los proyectos con su estado (incluido el activo),
// para que de un vistazo se vea cuál está en verde y cuál bloqueado.
func (e *escritorio) listaProyectos(raizActiva string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	// El registro se relee AQUÍ, no sólo al arrancar. `codeguard init`
	// escribe en repos.json el proyecto recién enrolado, pero el daemon ya
	// estaba corriendo con su copia en memoria: el repo no aparecía en el
	// panel hasta el primer commit, contradiciendo lo que init promete al
	// terminar ("aparece en el panel sin esperar al primer commit"). Pasó
	// al enrolar bds.portal.
	e.altaDeProyectosEnrolados()
	var out []string
	for root, p := range e.porProyecto {
		// Un proyecto cuya carpeta ya no existe no es un proyecto. El
		// daemon añade a porProyecto cada repo que analiza y antes no lo
		// quitaba nunca: un repo borrado seguía en el panel hasta
		// reiniciar el agente. Se olvida aquí y también del registro.
		if _, err := os.Stat(filepath.FromSlash(root)); err != nil {
			delete(e.porProyecto, root)
			e.olvidarRepo(root)
			continue
		}
		activo := "0"
		if root == raizActiva {
			activo = "1"
		}
		// formato: marca|nombre|ruta|activo
		out = append(out, fmt.Sprintf("%s|%s|%s|%s", marcaProyecto(p.Verdict), p.Repo, root, activo))
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.SplitN(out[i], "|", 3)[1] < strings.SplitN(out[j], "|", 3)[1]
	})
	return out
}

// marcaProyecto es el semáforo que el panel pinta junto al nombre del repo.
func marcaProyecto(veredicto string) string {
	switch veredicto {
	case "block":
		return "⛔"
	case "pass", "skipped":
		return "✓"
	}
	return "○" // sin análisis todavía
}

// sembrarDesdeRegistro llena el contexto activo cuando no hay ninguno.
//
// Daemon recién reiniciado: sin análisis en memoria, pero los proyectos
// enrolados EXISTEN. Un panel vacío aquí se lee como "se perdieron mis repos"
// — pasó tras actualizar a 1.2.0. Se muestra el primero del registro con su
// estado placeholder; el primer commit lo llena de verdad.
func (e *escritorio) sembrarDesdeRegistro() {
	if e.activo != nil {
		return
	}
	repos := e.cargarRepos()
	if len(repos) == 0 {
		return
	}
	root := filepath.ToSlash(repos[0].Root)
	lista := e.listaProyectos(root) // siembra porProyecto desde el registro
	e.mu.Lock()
	p := e.porProyecto[root]
	e.mu.Unlock()
	if p == nil {
		return
	}
	p.OtrosRepos = lista
	e.activo = p
}

// mostrarContextoActivo responde al panel cuando se abre: le manda el contexto
// activo, sembrándolo del registro si el daemon acaba de arrancar.
func (e *escritorio) mostrarContextoActivo() {
	e.sembrarDesdeRegistro()
	if e.activo != nil {
		e.app.Event.Emit("analysis", e.activo)
	}
}

// cambiarDeProyecto pone al frente el contexto de otro repo ya conocido. No
// altera el estado de nadie: cada proyecto conserva su propio análisis.
func (e *escritorio) cambiarDeProyecto(raiz string) {
	e.mu.Lock()
	p := e.porProyecto[raiz]
	e.mu.Unlock()
	if p == nil {
		return
	}
	p.OtrosRepos = e.listaProyectos(p.RepoRoot)
	e.activo = p // el contexto activo pasa a ser el elegido
	e.raizConfig.Store(p.RepoRoot)
	e.app.Event.Emit("analysis", p)
	e.tray.set(orbStateFor(p), fmt.Sprintf("%s · rama %s · %s",
		p.Repo, p.Branch, resumenHallazgos(p.Blocking, p.Advisory)))
}

// registrarAnalisis guarda el contexto de este proyecto y lo vuelve el activo.
func (e *escritorio) registrarAnalisis(payload *panelPayload) {
	// cada proyecto guarda su contexto; el activo pasa a ser este
	e.mu.Lock()
	e.porProyecto[payload.RepoRoot] = payload
	e.mu.Unlock()
	payload.OtrosRepos = e.listaProyectos(payload.RepoRoot)
	e.activo = payload
	e.raizConfig.Store(payload.RepoRoot)
}

// ── Explorador de código ─────────────────────────────────────────────────────

// contextoGrafo es lo que abrirGrafo saca del estado compartido antes de
// soltar el candado: leer el código y serializarlo es lento y no se hace con
// el mutex tomado.
type contextoGrafo struct {
	raiz      string
	repoRoot  string
	nombre    string
	payload   *panelPayload
	proyectos []codegraph.Proyecto
}

// abrirGrafo construye el explorador de UN proyecto (nunca mezcla sistemas)
// e incluye la lista de los demás para poder cambiar de contexto.
func (e *escritorio) abrirGrafo(raiz string) {
	c := e.contextoDelGrafo(raiz)
	go func() {
		e.prepararGrafo(c)
		application.InvokeAsync(e.abrirVentanaExplorador)
	}()
}

func (e *escritorio) contextoDelGrafo(raiz string) contextoGrafo {
	e.mu.Lock()
	c := contextoGrafo{raiz: raiz, payload: e.porProyecto[raiz]}
	for r, p := range e.porProyecto {
		c.proyectos = append(c.proyectos, codegraph.Proyecto{
			Nombre: p.Repo, Root: r, Activo: r == raiz, Estado: p.Verdict,
		})
	}
	e.mu.Unlock()
	sort.Slice(c.proyectos, func(i, j int) bool { return c.proyectos[i].Nombre < c.proyectos[j].Nombre })
	c.repoRoot = filepath.FromSlash(raiz)
	c.nombre = filepath.Base(c.repoRoot)
	if c.payload != nil {
		c.nombre = c.payload.Repo
	}
	return c
}

// prepararGrafo deja el grafo servido en /graph.json. La ventana se abre
// SIEMPRE, pase lo que pase aquí: antes, cualquiera de estos fallos hacía que
// el botón no hiciera absolutamente nada — sin ventana, sin mensaje, sólo una
// línea en un log que nadie mira.
func (e *escritorio) prepararGrafo(c contextoGrafo) {
	cg, err := codegraph.Build(c.repoRoot)
	var motivo string
	switch {
	case err != nil:
		motivo = "No pude leer el código de este proyecto: " + err.Error()
	case cg == nil || len(cg.Nodes) == 0:
		motivo = "No encontré funciones que mapear en " + c.nombre + ".\n\n" +
			"El explorador entiende Go y TypeScript/JavaScript, estén donde estén " +
			"en el repo. Si este proyecto usa otro lenguaje, todavía no está cubierto."
	}
	if motivo != "" {
		log.Printf("grafo de %s no disponible: %s", c.nombre, strings.SplitN(motivo, "\n", 2)[0])
		cg = &codegraph.Graph{Root: c.raiz, Error: motivo}
	} else if c.payload != nil {
		// Sin análisis previo no hay hallazgos que superponer, pero el
		// mapa del código se puede ver igual.
		cg.Overlay = buildOverlay(cg, c.payload)
	}
	cg.Proyectos = c.proyectos
	data, err := json.Marshal(cg)
	if err != nil {
		log.Println("grafo: no se pudo serializar:", err)
		data = []byte(`{"nodes":[],"edges":[],"error":"no se pudo preparar el grafo"}`)
	}
	e.grafoJSON.Store(data)
	if motivo == "" {
		log.Printf("grafo de %s: %d nodos, %d aristas (%d KB servidos en /graph.json)",
			c.nombre, len(cg.Nodes), len(cg.Edges), len(data)/1024)
	}
}

func (e *escritorio) abrirVentanaExplorador() {
	if e.explorador != nil {
		e.explorador.Close()
		e.explorador = nil
	}
	w, h := e.tamanoQueQuepa(1280, 820)
	e.explorador = e.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard — explorador de código",
		Width:            w,
		Height:           h,
		URL:              "/explorer.html",
		BackgroundColour: application.RGBA{Red: 11, Green: 14, Blue: 17, Alpha: 255},
	})
	e.explorador.Center()
	e.explorador.Show()
}

// ── Sombra y servidor IPC ────────────────────────────────────────────────────

// arrancarSombra prepara el corredor de la sombra. Sin BD no hay sombra, pero
// el daemon sigue: el análisis determinista no depende de ella.
func (e *escritorio) arrancarSombra() *shadow.Runner {
	shadowStore, err := store.Open(store.DefaultPath())
	if err != nil {
		log.Println("sombra desactivada — no se pudo abrir la BD:", err)
	}
	if shadowStore == nil {
		return nil
	}
	// El razonamiento del modelo se transmite al panel, con acelerador:
	// muchos deltas pequeños → una emisión cada ~350 ms con la cola.
	var thinkMu sync.Mutex
	var thinkBuf string
	var lastEmit time.Time
	return &shadow.Runner{
		Store: shadowStore,
		OnThinking: func(pillar, text string) {
			if pillar == "" && text == "" {
				e.app.Event.Emit("thinking", map[string]string{"pillar": "", "text": ""})
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
			e.app.Event.Emit("thinking", map[string]string{"pillar": pillar, "text": thinkBuf})
		},
	}
}

func (e *escritorio) construirServidorIPC(sombra *shadow.Runner) *daemon.Server {
	return &daemon.Server{
		Shadow:    sombra,
		OnCommand: e.alComandoDeLaCLI,
		OnRequest: e.alEmpezarAnalisis,
		OnResult:  e.alTerminarAnalisis,
	}
}

// alComandoDeLaCLI atiende las acciones de UI que pide la CLI: el explorador
// abre en la ventana del agente, nunca en un navegador.
func (e *escritorio) alComandoDeLaCLI(cmd, root string) {
	switch cmd {
	case "open-graph":
		e.abrirGrafo(filepath.ToSlash(root))
	case "open-config":
		if root != "" {
			e.raizConfig.Store(filepath.ToSlash(root))
		}
		e.app.Event.Emit("open-config", nil)
	default:
		log.Println("comando desconocido desde la CLI:", cmd)
	}
}

func (e *escritorio) alEmpezarAnalisis(req *ipc.Request) {
	// Re-anclar por si cambió la resolución o se movió la barra.
	application.InvokeAsync(e.anclarBurbuja)
	repo := filepath.Base(req.RepoRoot)
	e.tray.set("working", "revisando "+repo+" · rama "+req.Branch)
	e.app.Event.Emit("working", map[string]string{"repo": repo, "branch": req.Branch})
}

func (e *escritorio) alTerminarAnalisis(req *ipc.Request, resp *ipc.Response) {
	cfg, _ := config.Load(req.RepoRoot)
	maxShow, autoOpen := opcionesUI(cfg)
	payload := construirPayload(req, resp, maxShow)
	e.registrarAnalisis(payload)
	e.actualizarOrbe(payload)

	e.app.Event.Emit("analysis", payload)
	shouldOpen := autoOpen == "on_findings" && len(resp.Findings) > 0 ||
		autoOpen != "never" && resp.Verdict == "block"
	if shouldOpen {
		// Las ventanas se tocan desde el hilo de la UI.
		application.InvokeAsync(e.mostrarPanel)
	}

	// Diferenciador D1: el modelo explica los bloqueantes en español
	// claro, sobre TU código. Async, cacheado por fingerprint — el
	// commit ya fue decidido; esto solo enriquece el panel.
	if cfg != nil && resp.Verdict == "block" {
		go explainBlockers(e.app, cfg, req, resp)
	}
}

// opcionesUI saca del proyecto cuántos hallazgos mostrar y cuándo abrir solo
// el panel. Sin configuración legible, los valores por defecto de §12.
func opcionesUI(cfg *config.Config) (maxShow int, autoOpen string) {
	maxShow, autoOpen = 7, "on_block"
	if cfg == nil {
		return maxShow, autoOpen
	}
	if cfg.UI.MaxVisibleFindings > 0 {
		maxShow = cfg.UI.MaxVisibleFindings
	}
	if cfg.UI.AutoOpenPanel != "" {
		autoOpen = cfg.UI.AutoOpenPanel
	}
	return maxShow, autoOpen
}

// construirPayload arma lo que el panel pinta de un análisis terminado.
func construirPayload(req *ipc.Request, resp *ipc.Response, maxShow int) *panelPayload {
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
	return payload
}

// actualizarOrbe pone el clima del orbe tras un análisis.
func (e *escritorio) actualizarOrbe(p *panelPayload) {
	// "3 bloqueantes, 1 avisos" es un contador, no una frase. Esto se
	// lee de un vistazo y en singular cuando toca.
	tooltip := fmt.Sprintf("%s · rama %s · %s", p.Repo, p.Branch,
		resumenHallazgos(p.Blocking, p.Advisory))
	// motores ausentes = asunto de configuración, no degradación real:
	// un trivy no instalado no debe pintar de naranja cada commit.
	realDegraded := len(p.Degraded) > 0 && !pipeline.SoloFaltantes(p.Degraded)
	// El orbe habla SOLO del proyecto que acabas de tocar.
	switch {
	case p.Verdict == "block":
		e.tray.set("blocked", tooltip)
	case realDegraded:
		e.tray.set("degraded", tooltip+" — no corrió: "+strings.Join(p.Degraded, ", "))
	default:
		e.tray.setPass(tooltip)
	}
}
