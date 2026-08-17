package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/capas"
	"codeguard/internal/codegraph"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines/proc"
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
	//
	// Los tres campos de abajo son UN SOLO invariante, no tres cosas sueltas,
	// y lo tocan a la vez el servidor IPC —que atiende cada conexión en su
	// propia goroutine—, los manejadores de eventos de Wails y las goroutines
	// que este mismo archivo lanza para serializar el grafo. Dos reglas, y
	// las dos son de las que si se rompen no avisan:
	//
	//  1. e.mu cubre el invariante COMPLETO, no un campo. Antes cubría sólo
	//     porProyecto y activo quedaba al aire: un análisis recién terminado
	//     podía perderse entero porque sembrarDesdeRegistro comprobaba activo
	//     y lo escribía después, con todo el cálculo de la lista en medio.
	//  2. Un payload PUBLICADO no se muta jamás. Lo que sale de aquí hacia el
	//     bus de eventos o hacia otra goroutine es una copia de la que el
	//     receptor es dueño; los objetos de porProyecto y activo son del
	//     escritorio y sólo cambian con e.mu tomado. Antes se entregaba el
	//     puntero del mapa y luego se le reescribía OtrosRepos por debajo,
	//     mientras Wails o el explorador lo estaban serializando.
	//
	// Y cada operación es UNA sola sección crítica. Partirla en dos deja al
	// mapa y al activo contándose historias distintas en el hueco.
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

	// emitir manda un evento al frontend. Es un campo por la misma razón que
	// los dos de arriba: publicar el contexto activo es la lógica que se rompió
	// al enrolar un repo con el agente ya corriendo, y ejercitarla exigía
	// arrancar Wails entero. En producción se queda en nil y emitirEvento pasa
	// por el bus de la aplicación; sólo las pruebas lo llenan.
	emitir func(nombre string, datos any)

	// enCurso es el análisis que corre AHORA: el marcador que el orbe enseña en
	// vivo y el vigilante que corta un «revisando» que no vuelve. Ver progreso.go.
	enCurso analisisEnCurso
	// plazoVigilante lo acortan las pruebas para no esperar los segundos de
	// producción; en cero se calcula del plazo que manda el hook.
	plazoVigilante time.Duration

	// abrirPanel muestra la ventana. Mismo motivo que emitir: tocar la ventana
	// exige el hilo de la UI de Wails (application.InvokeAsync), y eso panica
	// sin una aplicación viva — así que la lógica de CUÁNDO abrir no se podía
	// probar sin arrancar Wails entero. En producción se queda en nil.
	abrirPanel func()

	// apagar termina la aplicación POR EL CAMINO BUENO — el mismo que el botón
	// «Salir de CodeGuard» del menú. Mismo patrón inyectable que los de arriba.
	//
	// Existe porque el desinstalador no tenía forma de pedirlo: mataba el
	// proceso con Stop-Process -Force, y un proceso fusilado no llega a quitar
	// su icono de la bandeja. Windows deja el icono pintado —el famoso orbe
	// fantasma— hasta que algo refresca el área de notificación, y en la
	// bandeja nueva de Windows 11 no hay forma programática decente de
	// refrescarla sin reiniciar Explorer. La única salida limpia es no matar:
	// pedir. app.Quit() desmonta la bandeja antes de morir.
	apagar func()
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
	e.mu.Lock()
	e.altaDeProyectosEnroladosLocked()
	e.mu.Unlock()
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
	// La demo de estados sólo existe en compilaciones de depuración: conduce el
	// orbe a estados inventados, y el orbe es un indicador de seguridad. Ver
	// demoestados.go.
	e.anadirDemoDeEstados(menu)
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

// zonaDelEvento traduce lo que manda la página —su caja en píxeles CSS más el
// factor de escala— a píxeles físicos, que es en lo que habla SetWindowRgn.
//
// La escala la manda la página (devicePixelRatio) en vez de preguntarla aquí:
// es la misma que usó para medirse, así que no puede desincronizarse. En un
// monitor al 150% eso es la diferencia entre recortar donde está el orbe y
// recortar a dos tercios de camino.
func zonaDelEvento(ev *application.CustomEvent) (string, []Rect) {
	if ev == nil || ev.Data == nil {
		return "", nil
	}
	raw, err := json.Marshal(ev.Data)
	if err != nil {
		return "", nil
	}
	var msg struct {
		Ventana string  `json:"ventana"`
		Escala  float64 `json:"escala"`
		Zonas   []struct {
			X, Y, W, H, Radio float64
		} `json:"zonas"`
	}
	if json.Unmarshal(raw, &msg) != nil || msg.Ventana == "" {
		return "", nil
	}
	if msg.Escala <= 0 {
		msg.Escala = 1
	}
	px := func(v float64) int { return int(v*msg.Escala + 0.5) }
	zonas := make([]Rect, 0, len(msg.Zonas))
	for _, z := range msg.Zonas {
		zonas = append(zonas, Rect{
			X: px(z.X), Y: px(z.Y), W: px(z.W), H: px(z.H), Radio: px(z.Radio),
		})
	}
	return msg.Ventana, zonas
}

func (e *escritorio) registrarEventosPanel() {
	// Clic en la burbuja: alterna el panel (cierre con animación de plegado).
	e.app.Event.On("widget-click", func(*application.CustomEvent) {
		application.InvokeAsync(e.alternarPanel)
	})
	// La burbuja pide su estado al cargar.
	e.app.Event.On("widget-ready", func(*application.CustomEvent) {})
	// Cada ventana transparente dice dónde acabó su contenido, y la ventana se
	// recorta a esa forma. Sin esto, el aire que rodea al orbe y la mitad vacía
	// del panel se comen los clics de esa zona de la pantalla.
	e.app.Event.On("zona-activa", func(ev *application.CustomEvent) {
		titulo, zonas := zonaDelEvento(ev)
		if titulo == "" {
			return
		}
		application.InvokeAsync(func() { RecortarA(titulo, zonas) })
	})
	// El ✕ del panel solo lo oculta; el proceso sigue en la bandeja.
	e.app.Event.On("panel-close", func(*application.CustomEvent) {
		application.InvokeAsync(func() { e.panel.Hide() })
	})
	// Feedback del panel → tabla feedback (etapa 9).
	e.app.Event.On("feedback", guardarFeedback)
	// La pestaña de historial pide sus datos al abrirse. Va en su propia
	// goroutine: abre la base y consulta, y el hilo de la UI no puede quedarse
	// esperando a un disco.
	e.app.Event.On("pedir-historial", func(ev *application.CustomEvent) {
		var raiz string
		if rs := rootsDelEvento(ev); len(rs) > 0 {
			raiz = rs[0]
		}
		go e.alPedirHistorial(raiz)
	})
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
		p := e.activoActual()
		if p == nil {
			log.Println("grafo: aún no hay proyecto activo")
			return
		}
		e.abrirGrafo(p.RepoRoot)
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

// altaDeProyectosEnroladosLocked añade al mapa los proyectos del registro que
// aún no estén, con su estado placeholder. Exige e.mu tomado.
func (e *escritorio) altaDeProyectosEnroladosLocked() {
	for _, r := range e.cargarRepos() {
		root := filepath.ToSlash(r.Root)
		if _, ya := e.porProyecto[root]; !ya {
			// El stack y las capas se saben SIN analizar nada: el stack está
			// escrito en el config desde el `init` y las capas salen de
			// preguntarle a cada motor por el árbol. Sin esto, la ficha nacía
			// con la cabecera vacía y el dev que acababa de instalar veía un
			// producto que no sabía nada de su repo, justo después de que
			// `init` le hubiera dicho por pantalla qué stack había detectado.
			// Es lo primero que se mira y era lo último que se rellenaba.
			//
			// config.Load devolviendo error no es un fallo: es el repo de quien
			// corrió `install` y todavía no `init`. Ahí no hay stack que
			// enseñar y no se inventa ninguno.
			var langs, capasDelRepo []string
			if cfg, err := config.Load(filepath.FromSlash(root)); err == nil && cfg != nil {
				langs = cfg.Languages
				capasDelRepo = daemon.CapasDelRepoEn(cfg, filepath.FromSlash(root))
			}
			e.porProyecto[root] = &panelPayload{
				Repo: r.Nombre, RepoRoot: root, Verdict: "—", At: "sin análisis",
				Languages: langs, CapasRepo: capasDelRepo,
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
func (e *escritorio) listaProyectos(raizActiva string) []proyectoEnLista {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.listaProyectosLocked(raizActiva)
}

// listaProyectosLocked es la lista de verdad, y exige e.mu tomado.
//
// Existe separada de listaProyectos porque sync.Mutex no es reentrante: quien
// necesitaba la lista dentro de su propia sección crítica no podía llamar a la
// versión que toma el candado, así que soltaba el suyo antes y publicaba
// después. En ese hueco es donde se colaban las dos carreras que este archivo
// tenía. Con las dos capas separadas, toda publicación cabe en un solo Lock.
func (e *escritorio) listaProyectosLocked(raizActiva string) []proyectoEnLista {
	// El registro se relee AQUÍ, no sólo al arrancar. `codeguard init`
	// escribe en repos.json el proyecto recién enrolado, pero el daemon ya
	// estaba corriendo con su copia en memoria: el repo no aparecía en el
	// panel hasta el primer commit, contradiciendo lo que init promete al
	// terminar ("aparece en el panel sin esperar al primer commit"). Pasó
	// al enrolar bds.portal.
	e.altaDeProyectosEnroladosLocked()
	var out []proyectoEnLista
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
		out = append(out, proyectoEnLista{
			Marca:    marcaProyecto(p),
			Nombre:   p.Repo,
			Ruta:     root,
			Activo:   root == raizActiva,
			Verdict:  p.Verdict,
			Blocking: p.Blocking,
			Advisory: p.Advisory,
			Cuando:   p.At,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nombre < out[j].Nombre })
	return out
}

// marcaProyecto es el semáforo que el panel pinta junto al nombre del repo.
//
// El ✓ no es un adorno: el panel lo rotula «limpio — el último commit pasó todas
// las compuertas». Sobre un análisis OMITIDO no pasó ninguna, así que el salto se
// va al ○, que es la marca que no afirma nada. Es el mismo ✓ falso del orbe en
// pequeño, y llegaba al sitio donde se mira de reojo el estado de los demás
// proyectos.
//
// Una degradación real SÍ conserva su ✓ y es a propósito: ahí el análisis corrió
// y lo que corrió pasó. El agujero de cobertura se cuenta donde hay sitio para
// decirlo con precisión —el orbe se pone en piedra y el panel escribe «No se
// revisó: …» a partir de p.degraded—, no apretándolo en un glifo que el panel
// rotula «sin analizar todavía» y que sería una inexactitud nueva.
//
// Las tres marcas son las que el panel sabe nombrar con palabras (index.html);
// cualquier otra cae en su ○ por defecto y se quedaría sin rótulo correcto.
func marcaProyecto(p *panelPayload) string {
	switch {
	case p == nil:
		return "○"
	case p.Verdict == "block":
		return "⛔"
	// Omitido: el embudo se paró en la etapa 0. No hay revisión que enseñar,
	// igual que un proyecto que todavía no se ha analizado nunca.
	case p.Verdict == "skipped":
		return "○"
	case p.Verdict == "pass":
		return "✓"
	}
	return "○" // "—" y cualquier otro: sin análisis todavía
}

// paraPublicar saca del estado compartido la copia que se entrega a otra
// goroutine —el bus de eventos, el explorador—. Exige e.mu tomado.
//
// La copia es superficial y basta: los campos de slice (OtrosRepos, Degraded,
// Findings) se sustituyen enteros, nunca se editan elemento a elemento, así
// que quien se quedó con el slice viejo se queda con un array que ya nadie
// escribe. Si algún día se muta un slice en su sitio, esto deja de bastar.
func paraPublicar(p *panelPayload) *panelPayload {
	if p == nil {
		return nil
	}
	copia := *p
	return &copia
}

// publicarLocked es LA operación sobre el contexto: recalcula la lista de
// proyectos, se la deja al contexto de raiz, lo vuelve el activo y devuelve la
// copia que viaja al panel. Todo en una sola sección crítica — exige e.mu.
//
// Devuelve nil si raiz no tiene contexto (p.ej. su carpeta ya no existe y la
// lista acaba de darlo de baja).
func (e *escritorio) publicarLocked(raiz string) *panelPayload {
	// La lista primero: da de alta los enrolados y da de baja los borrados,
	// así que decide si raiz sigue siendo un proyecto.
	lista := e.listaProyectosLocked(raiz)
	p := e.porProyecto[raiz]
	if p == nil {
		return nil
	}
	p.OtrosRepos = lista
	e.activo = p
	return paraPublicar(p)
}

// activoActual entrega una copia del contexto activo, o nil si no hay ninguno.
// Es la ÚNICA forma de leer e.activo desde fuera de una sección crítica.
func (e *escritorio) activoActual() *panelPayload {
	e.mu.Lock()
	defer e.mu.Unlock()
	return paraPublicar(e.activo)
}

// sembrarDesdeRegistro llena el contexto activo cuando no hay ninguno y
// devuelve la copia que el panel tiene que pintar (nil si no hay nada).
//
// Daemon recién reiniciado: sin análisis en memoria, pero los proyectos
// enrolados EXISTEN. Un panel vacío aquí se lee como "se perdieron mis repos"
// — pasó tras actualizar a 1.2.0. Se muestra el primero del registro con su
// estado placeholder; el primer commit lo llena de verdad.
//
// Comprobar el activo y sembrarlo son el mismo paso: partidos en dos, un
// análisis que entraba por el IPC en medio se perdía entero, y el usuario veía
// "sin análisis" justo después de commitear.
func (e *escritorio) sembrarDesdeRegistro() *panelPayload {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.activo != nil {
		// Se RECALCULA la lista, no se devuelve la foto guardada.
		//
		// Aquí había un `return paraPublicar(e.activo)` con el argumento de que
		// "ya hay contexto: sembrar no pisa nada". Cierto para el contexto, y
		// falso para la lista: publicarLocked es lo único que da de alta a los
		// repos recién enrolados y da de baja a los que ya no están en disco,
		// y por este atajo abrir el panel no hacía ninguna de las dos cosas.
		// La limpieza sólo corría al analizar o al cambiar de proyecto, así que
		// un repo borrado seguía listado durante toda la vida del agente y la
		// única salida era reiniciarlo a mano — que es justo lo que un
		// desarrollador no va a hacer, ni tiene por qué saber que existe.
		// Se anota ANTES de republicar: publicarLocked da de alta los enrolados,
		// así que después ya no se puede distinguir quién estaba.
		_, estabaEnElMapa := e.porProyecto[e.activo.RepoRoot]
		if p := e.publicarLocked(e.activo.RepoRoot); p != nil {
			return p
		}
		if !estabaEnElMapa {
			// Contexto activo que nunca estuvo en el mapa de proyectos. No es un
			// repo dado de baja: es un análisis recién llegado, y sembrar no
			// puede pisarlo — es el invariante que defiende
			// TestSembrarDesdeRegistroNoPisaElAnalisisEnCurso.
			return paraPublicar(e.activo)
		}
		// Sí estaba y ya no: su carpeta desapareció y la lista acaba de darlo de
		// baja. Se suelta y se busca otro abajo, porque enseñar el estado de una
		// carpeta que ya no existe es peor que no enseñar nada.
		e.activo = nil
	}
	// El primero del registro que siga existiendo. No vale quedarse con
	// repos[0] a ciegas: el registro puede tener carpetas borradas —su baja es
	// asíncrona— y ese camino devolvía nil dejando el panel vacío, que se lee
	// como "se perdieron mis repos".
	for _, r := range e.cargarRepos() {
		if p := e.publicarLocked(filepath.ToSlash(r.Root)); p != nil {
			return p
		}
	}
	return nil
}

// mostrarContextoActivo responde al panel cuando se abre: le manda el contexto
// activo, sembrándolo del registro si el daemon acaba de arrancar.
func (e *escritorio) mostrarContextoActivo() {
	if p := e.sembrarDesdeRegistro(); p != nil {
		e.app.Event.Emit("analysis", p)
	}
}

// pedirPanel abre el panel respetando la voluntad del usuario.
//
// No basta con emitir "panel-show": el panel nace oculto y sólo lo muestra
// panel.Show(). Y emitir ese evento a secas hace daño — el JS de la burbuja
// marca panelAbierto y con esa bandera el susurro y el tooltip del orbe dejan
// de responder, así que el agente se quedaba MUDO hasta que el usuario abría y
// cerraba el panel a mano.
//
// Se respeta `ui.auto_open_panel: never`: quien lo pone está diciendo que el
// panel no se abre solo, y enrolar un repo no es excusa para desobedecerlo.
func (e *escritorio) pedirPanel(cfg *config.Config) {
	if _, autoOpen := opcionesUI(cfg); autoOpen == "never" {
		return
	}
	if e.abrirPanel != nil {
		e.abrirPanel()
		return
	}
	// Sin aplicación no hay ventana que mostrar. La guarda no es defensa contra
	// un imposible de producción —ahí e.app está siempre— sino contra que una
	// prueba que ejercite esta lógica tenga que enterarse de que existe un
	// punto de sustitución sólo para no morir en InvokeAsync.
	if e.app == nil {
		return
	}
	application.InvokeAsync(e.mostrarPanel)
}

// emitirEvento publica en el bus del frontend. Pasa por el campo emitir para
// que las pruebas puedan observar lo que se publica sin arrancar la aplicación.
func (e *escritorio) emitirEvento(nombre string, datos any) {
	if e.emitir != nil {
		e.emitir(nombre, datos)
		return
	}
	e.app.Event.Emit(nombre, datos)
}

// cambiarDeProyecto pone al frente el contexto de otro repo ya conocido. No
// altera el estado de nadie: cada proyecto conserva su propio análisis.
//
// Sirve igual para un repo que el escritorio aún no ha visto nunca: publicarLocked
// relee el registro antes de buscarlo, así que un repo recién enrolado entra con
// su estado placeholder en vez de darse por desconocido.
func (e *escritorio) cambiarDeProyecto(raiz string) {
	e.mu.Lock()
	p := e.publicarLocked(raiz) // el contexto activo pasa a ser el elegido
	e.mu.Unlock()
	if p == nil {
		return
	}
	e.raizConfig.Store(p.RepoRoot)
	e.emitirEvento("analysis", p)
	e.tray.set(orbStateFor(p), tooltipDelOrbe(p))
}

// registrarAnalisis guarda el contexto de este proyecto y lo vuelve el activo.
// Devuelve la copia que se manda al panel y al orbe.
//
// El escritorio se queda con payload: quien lo construyó no vuelve a tocarlo,
// porque a partir de aquí sólo se lee y se escribe con e.mu tomado.
func (e *escritorio) registrarAnalisis(payload *panelPayload) *panelPayload {
	// cada proyecto guarda su contexto; el activo pasa a ser este
	e.mu.Lock()
	raiz := payload.RepoRoot
	e.porProyecto[raiz] = payload
	p := e.publicarLocked(raiz)
	if p == nil {
		// La lista acaba de dar de baja el repo porque su carpeta ya no
		// está. El análisis manda: acaba de correr sobre ese código.
		e.activo = payload
		p = paraPublicar(payload)
	}
	e.mu.Unlock()
	e.raizConfig.Store(raiz)
	return p
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
	// Copia: el contexto se lo lleva otra goroutine a leer y a serializar,
	// y el del mapa lo sigue reescribiendo el escritorio.
	c := contextoGrafo{raiz: raiz, payload: paraPublicar(e.porProyecto[raiz])}
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

// alPedirHistorial responde a la pestaña de historial del panel.
//
// Se sirve BAJO DEMANDA y no dentro del payload de cada análisis: la consulta
// abre la base y recorre corridas, y pagarlo en el camino del commit —que es el
// único momento en que el desarrollador está esperando— para un dato que casi
// nunca se mira sería cobrarle a todos por lo que usa uno.
func (e *escritorio) alPedirHistorial(raiz string) {
	if raiz == "" {
		if p := e.activoActual(); p != nil {
			raiz = p.RepoRoot
		}
	}
	h := struct {
		RepoRoot string          `json:"repo_root"`
		Error    string          `json:"error,omitempty"`
		Datos    store.Historial `json:"datos"`
	}{RepoRoot: raiz}

	// El error viaja hasta la pantalla en vez de morir en el log. Una pestaña
	// que se queda en blanco se lee como "no hay nada", que es justo la
	// confusión que este panel existe para deshacer.
	st, err := store.Open(store.DefaultPath())
	if err != nil || st == nil {
		h.Error = "no pude abrir la base de datos del agente"
		e.emitirEvento("historial", h)
		return
	}
	defer st.Close()
	datos, err := st.Historial(repoIDDe(raiz), 20)
	if err != nil {
		h.Error = "no pude leer el historial: " + err.Error()
	}
	h.Datos = datos
	e.emitirEvento("historial", h)
}

// repoIDDe calcula la misma clave con la que la CLI guardó las corridas. Si no
// coincidiera, el historial saldría vacío sobre una base llena.
func repoIDDe(raiz string) string {
	nativa := filepath.FromSlash(raiz)
	salida, err := gitCmdDaemon(nativa, "config", "--get", "remote.origin.url").Output()
	remoto := strings.TrimSpace(string(salida))
	if err != nil {
		remoto = ""
	}
	// La regla vive en store.RepoIDDe y no aquí: era una de las cinco copias
	// del mismo cálculo, y de las cinco sólo dos tenían el respaldo para los
	// repos sin remote. Que este archivo la tuviera bien no salvaba a los otros.
	return store.RepoIDDe(nativa, remoto)
}

// comandoDaemon arma CUALQUIER proceso hijo del daemon. Es el único sitio de
// cmd/daemon donde se llama a exec.Command, y TestNingunHijoDelDaemonSeArmaAMano
// es lo que lo mantiene así.
//
// Existe por la ventana de consola. El daemon se compila con -H windowsgui
// (dist/build-dist.ps1), o sea que no tiene consola propia; cuando un proceso
// sin consola lanza un ejecutable de consola, Windows le REGALA una nueva y
// visible. El desarrollador ve parpadear una ventana negra en la cara. Medido en
// esta máquina con un padre GUI y un hijo que reporta GetConsoleWindow: sin
// atributos, hwnd≠0 y IsWindowVisible=1; con ellos, ni siquiera hay ventana.
//
// Pasó exactamente eso al abrir la pestaña de historial, que llama a git para
// resolver el identificador del repo. Los motores nunca lo sufrieron porque van
// por proc.Correr, que ya oculta la ventana; el descuido fue construir un git al
// margen de ese camino. Por eso aquí se reusa proc.SinVentana y no se inventa
// otro apaño: el helper ya existía, sólo faltaba llamarlo.
//
// El entorno va acotado como el de cualquier otro hijo (ver proc.Entorno): el
// daemon tiene la clave del modelo en el suyo y ninguna utilidad que lance la
// necesita. Quien necesite las GIT_* pide gitCmdDaemon.
func comandoDaemon(nombre string, args ...string) *exec.Cmd {
	c := exec.Command(nombre, args...)
	proc.SinVentana(c)
	c.Env = proc.Entorno()
	return c
}

// gitCmdDaemon es comandoDaemon con el entorno que git necesita. Las GIT_* le
// dicen a git qué índice está mirando, y filtrarlas cambiaría en silencio qué se
// analiza; es la misma razón por la que la CLI tiene su gitCmd.
func gitCmdDaemon(dir string, args ...string) *exec.Cmd {
	c := comandoDaemon("git", append([]string{"-C", dir}, args...)...)
	c.Env = proc.EntornoGit()
	return c
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
		Shadow:     sombra,
		OnCommand:  e.alComandoDeLaCLI,
		OnRequest:  e.alEmpezarAnalisis,
		OnProgreso: e.alAvanzarAnalisis,
		OnResult:   e.alTerminarAnalisis,
	}
}

// alComandoDeLaCLI atiende las acciones de UI que pide la CLI: el explorador
// abre en la ventana del agente, nunca en un navegador.
func (e *escritorio) alComandoDeLaCLI(cmd string, req *ipc.Request) {
	if req == nil {
		return
	}
	root := req.RepoRoot
	switch cmd {
	// El desinstalador (y sólo él, en la práctica) pide el apagado por IPC en
	// vez de matar el proceso: un daemon fusilado deja su orbe pintado en la
	// bandeja como fantasma. La frontera de confianza no cambia: el pipe es
	// por-usuario, y quien puede hablarle al pipe ya podía hacer taskkill.
	case "apagar":
		if e.apagar != nil {
			e.apagar()
			return
		}
		// Vía el hilo de la UI, como toda operación que toca ventanas. El ack
		// del IPC ya salió: quien pidió el apagado no se queda esperando.
		application.InvokeAsync(func() { e.app.Quit() })
	case "open-graph":
		e.abrirGrafo(filepath.ToSlash(root))
	case "open-config":
		if root != "" {
			e.raizConfig.Store(filepath.ToSlash(root))
		}
		e.emitirEvento("open-config", nil)
	// `codeguard init` acaba de enrolar un repo. Se pone al frente igual que si
	// el usuario lo hubiera elegido en el panel: init promete que el proyecto
	// "aparece en el panel desde el momento del init", y sin este aviso la
	// promesa sólo se cumplía en un daemon que arrancara después —con el agente
	// ya corriendo y otro proyecto en pantalla, el repo no salía nunca.
	case "repo-enrolado":
		if root == "" {
			return
		}
		// Enrolar un repo es una acción del usuario que hasta ahora no producía
		// NINGUNA señal visible: `codeguard init` decía "LISTO" y el agente se
		// quedaba callado, así que no había forma de saber si había funcionado.
		//
		// Se abre el panel a propósito, y no sólo se cambia el contexto: es el
		// único momento en que el usuario acaba de pedir algo y espera verlo.
		// El resto del tiempo el panel se abre solo cuando hay un bloqueo
		// (ui.auto_open_panel: on_block), y eso no cambia.
		// Se abre con mostrarPanel y NO emitiendo "panel-show" a secas: el panel
		// nace Hidden y lo único que lo muestra es panel.Show(). Emitir el evento
		// suelto no sólo no abría nada — el JS de la burbuja pone
		// panelAbierto=true al recibirlo, y con esa bandera el susurro y el
		// tooltip del orbe dejan de responder: el agente se quedaba MUDO hasta
		// que el usuario abría y cerraba el panel a mano. Vía InvokeAsync porque
		// esto llega desde la goroutine del IPC y toca la ventana.
		raiz := filepath.ToSlash(root)
		e.cambiarDeProyecto(raiz)
		cfg, _ := config.Load(raiz)
		e.pedirPanel(cfg)
	// La etapa 1 frenó una credencial. Es el evento que justifica el producto y
	// era el ÚNICO que la interfaz no contaba: la compuerta de secretos corre
	// DENTRO del proceso del gancho —tiene que ser así, es fail-closed y no
	// puede depender de que el daemon esté vivo— y salía por os.Exit mucho antes
	// de la primera llamada al daemon. El commit quedaba bloqueado, la terminal
	// lo decía, y el orbe seguía en verde.
	//
	// Lo que llega es un NÚMERO, nunca los hallazgos: son ellos los que
	// contienen la credencial, y abrir un camino nuevo por el que salga sería lo
	// contrario de lo que este producto hace. El detalle está en la base —el
	// gancho lo persiste antes de salir— y se lee en la pestaña Historial.
	case "secreto-bloqueado":
		if root == "" || req.SecretosBloqueados <= 0 {
			return
		}
		raizSecreto := filepath.ToSlash(root)
		p := &panelPayload{
			Repo:     filepath.Base(raizSecreto),
			RepoRoot: raizSecreto,
			Branch:   req.Branch,
			Verdict:  "block",
			Blocking: req.SecretosBloqueados,
			Reason: plural(req.SecretosBloqueados,
				"se frenó 1 secreto antes de que entrara al repositorio",
				"se frenaron %d secretos antes de que entraran al repositorio") +
				" — rota la credencial primero: borrarla del historial no la invalida. " +
				"El detalle está en Historial y en la terminal donde commiteaste.",
			// CIParity en true: la paridad no se comprobó en este camino, y un
			// false pintaría el aviso de "puede pasar aquí y fallar allá", que
			// sería una acusación inventada encima del bloqueo real.
			CIParity:   true,
			SecretosEn: req.SecretosEn,
			Findings:   hallazgosDeSecreto(req.SecretosEn),
			MaxShow:    len(req.SecretosEn),
			At:         time.Now().Format("15:04"),
		}
		// Por el MISMO camino que un análisis terminado: registrar, pintar el
		// orbe y publicar. Un camino paralelo acabaría discrepando —el orbe
		// diciendo una cosa y la lista de proyectos otra— y eso es justo lo que
		// este archivo lleva todo el día arreglando.
		payload := e.registrarAnalisis(p)
		e.actualizarOrbe(payload)
		e.emitirEvento("analysis", payload)
		cfgSecreto, _ := config.Load(filepath.FromSlash(raizSecreto))
		e.pedirPanel(cfgSecreto)
	default:
		log.Println("comando desconocido desde la CLI:", cmd)
	}
}

// hallazgosDeSecreto convierte los sitios ("archivo:línea") en hallazgos que el
// panel pinta con SU tarjeta de siempre.
//
// Se construyen aquí y no se inventa una sección propia en el HTML porque el
// panel ya tiene un componente para esto —con su pilar, su severidad, su ruta
// copiable y su "cómo arreglarlo"—, y un bloque hecho a mano al lado se ve como
// lo que sería: un remiendo. La compuerta de secretos no pasa por el pipeline y
// por eso no traía hallazgos; el arreglo es dárselos, no pintarlos distinto.
//
// SIN Snippet, y es la línea que no se puede quitar: el fragmento se construye
// LEYENDO EL ARCHIVO, así que pintaría la credencial en una ventana que se
// comparte por pantalla. El sitio es lo que le falta al dev; el valor ya lo
// tiene abierto en su editor.
func hallazgosDeSecreto(sitios []string) []panelFinding {
	out := make([]panelFinding, 0, len(sitios))
	for _, sitio := range sitios {
		archivo, linea := sitio, 0
		if i := strings.LastIndex(sitio, ":"); i > 0 {
			if n, err := strconv.Atoi(sitio[i+1:]); err == nil {
				archivo, linea = sitio[:i], n
			}
		}
		out = append(out, panelFinding{
			Finding: finding.Finding{
				Engine:   "gitleaks",
				RuleKey:  "secreto-en-el-diff",
				Pillar:   finding.Security,
				Severity: finding.Error,
				Blocking: true,
				File:     archivo,
				Line:     linea,
				Message:  "Secreto detectado en el diff — nada salió a la red",
				Why: "Una credencial en el historial de git la tiene cualquiera con acceso al " +
					"repositorio, y sigue ahí aunque la borres en un commit posterior.",
				FixHint: "Rota la credencial en el proveedor PRIMERO. Borrarla del historial no " +
					"la invalida: quien ya la haya visto la sigue teniendo. Después sácala del " +
					"código y déjala en una variable de entorno o en la bóveda del equipo.",
				Verified: true,
			},
			IsFact: true, // determinista: es un hecho, no una observación del modelo
		})
	}
	return out
}

func (e *escritorio) alEmpezarAnalisis(req *ipc.Request) {
	// Re-anclar por si cambió la resolución o se movió la barra. La guarda no
	// defiende de un imposible de producción —ahí e.app está siempre— sino de
	// que una prueba del marcador del orbe tenga que arrancar Wails para no
	// morir en InvokeAsync. Mismo motivo que en pedirPanel.
	if e.app != nil {
		application.InvokeAsync(e.anclarBurbuja)
	}
	repo := filepath.Base(req.RepoRoot)
	// El marcador se abre ANTES de anunciar el estado: a partir de aquí pueden
	// entrar avances, y uno que llegara con el análisis todavía sin abrir se
	// descartaría por venir "de otro run".
	plazo := e.plazoVigilante
	if plazo <= 0 {
		plazo = plazoDelVigilante(req.DeadlineMs)
	}
	e.enCurso.empezar(req.RunID, repo, req.Branch, plazo, e.alMorirElAnalisis)
	e.tray.set("working", "revisando "+repo+" · rama "+req.Branch)
	e.emitirEvento("working", map[string]string{"repo": repo, "branch": req.Branch})
}

// alAvanzarAnalisis lleva al orbe UN paso del análisis, mientras corre.
//
// Corre en la goroutine de un motor, dentro del camino del commit: aquí no se
// puede bloquear. Por eso NO se toca la bandeja del sistema —sus setters son
// InvokeSync y esperan al hilo de la UI— y sólo se publica en el bus, que en
// Wails despacha en su propia goroutine. El ícono ya dice "working" desde que
// entró la petición y no cambia mientras dura: lo que cambia es lo que el orbe
// cuenta, y eso viaja por este evento.
func (e *escritorio) alAvanzarAnalisis(req *ipc.Request, av pipeline.Avance) {
	v, ok := e.enCurso.avanzar(req.RunID, av)
	if !ok {
		return // avance rezagado, o de otro análisis: pintarlo sería mentir
	}
	e.emitirEvento(eventoProgreso, cargaDeProgreso(v))
}

// alMorirElAnalisis corta el «revisando» que no vuelve.
//
// Se llega aquí cuando un análisis lleva callado más que su propio plazo con
// margen: el proceso se tragó un panic, un motor se colgó por encima del
// deadline, el pipe murió a media etapa. El orbe no puede quedarse afirmando que
// hay una revisión en marcha que ya no existe — es la misma mentira por omisión
// que el ✓ verde sobre un análisis omitido, sólo que sin caducidad.
//
// Va a "degraded" y no a reponerOrbe() —el estado real del último análisis
// completo— a propósito. Reponer sería honesto sobre el pasado y mudo sobre lo
// que acaba de pasar: el commit que el dev ACABA de hacer se quedaría enseñando
// el veredicto verde del anterior, que es exactamente lo que orbStateFor
// documenta como inaceptable ("la señal prudente es la que pide mirar, nunca la
// que tranquiliza"). Un análisis que no terminó es un agujero de cobertura del
// tamaño entero del commit, y "degraded" es justo eso: ve a mirar.
//
// No se toca porProyecto: ahí vive el último análisis que SÍ terminó, y el panel
// tiene que seguir pudiendo enseñarlo. Lo que se corrige es lo que el orbe
// afirma ahora mismo.
func (e *escritorio) alMorirElAnalisis(repo, rama string) {
	log.Printf("orbe: el análisis de %s (rama %s) no volvió; se corta el «revisando»", repo, rama)
	e.tray.set("degraded", fmt.Sprintf(
		"%s · rama %s · el análisis no terminó — no sé qué quedó sin revisar", repo, rama))
}

func (e *escritorio) alTerminarAnalisis(req *ipc.Request, resp *ipc.Response) {
	// Lo PRIMERO: cerrar el análisis en curso. Deja sin efecto al vigilante y
	// cierra la puerta a los avances rezagados, así que a partir de esta línea
	// nada puede volver a poner al orbe en "revisando".
	e.enCurso.terminar(req.RunID)
	cfg, _ := config.Load(req.RepoRoot)
	maxShow, autoOpen := opcionesUI(cfg)
	// El escritorio se queda con el payload; lo que sigue usa la copia que
	// publica, que es de este hilo y ya nadie va a reescribir por debajo.
	payload := e.registrarAnalisis(construirPayload(req, resp, cfg, maxShow))
	e.actualizarOrbe(payload)

	e.emitirEvento("analysis", payload)
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
//
// cfg entra porque la cabecera del panel no describe el ANÁLISIS sino el
// PROYECTO —su stack—, y eso no viaja en la respuesta. Puede ser nil: un repo
// cuyo config no se pudo leer no tiene "cero lenguajes", tiene un problema, y
// el panel no debe presentar lo segundo como lo primero.
func construirPayload(req *ipc.Request, resp *ipc.Response, cfg *config.Config, maxShow int) *panelPayload {
	var languages []string
	if cfg != nil {
		languages = cfg.Languages
	}
	payload := &panelPayload{
		Repo:        filepath.Base(req.RepoRoot),
		RepoRoot:    filepath.ToSlash(req.RepoRoot),
		Branch:      req.Branch,
		AIGenerated: req.AIGenerated,
		Suppressed:  resp.Suppressed,
		Languages:   languages,
		Capas:       resp.Capas,
		Verdict:     resp.Verdict,
		// El motivo del salto llegaba hasta aquí por el pipe y moría en esta
		// línea, que no existía: la UI se quedaba sin poder explicar por qué no
		// se revisó y acababa conjeturándolo.
		Reason:    resp.Reason,
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
	return payload
}

// actualizarOrbe pone el clima del orbe tras un análisis. El COLOR lo decide
// orbStateFor y sólo orbStateFor —aquí se elige el tooltip y si el estado es
// transitorio—, porque cuando cada ruta decidía el suyo acabaron discrepando.
//
// El orbe habla SOLO del proyecto que acabas de tocar.
func (e *escritorio) actualizarOrbe(p *panelPayload) {
	estado := orbStateFor(p)
	tooltip := tooltipDelOrbe(p)
	if estado == "degraded" && len(p.Degraded) > 0 {
		tooltip += " — no corrió: " + strings.Join(p.Degraded, ", ")
	}
	// Sólo el verde es transitorio: vuelve a idle a los 15 s porque "todo bien"
	// ya se dijo. Un bloqueo o un agujero de cobertura se quedan hasta que pase
	// otra cosa.
	if estado == "pass" {
		e.tray.setPass(tooltip)
		return
	}
	e.tray.set(estado, tooltip)
}

// reponerOrbe recalcula el orbe desde el estado REAL del proyecto activo.
//
// No restaura una foto guardada, y la diferencia importa: si mientras tanto
// entró un análisis de verdad, una foto vieja lo taparía —que es la forma de
// mentir que se acaba de quitar de todas las demás rutas—. Aquí se vuelve a
// derivar de `activoActual()` con las mismas dos funciones que usa el resto del
// archivo, así que el resultado es por construcción el que se vería si nadie
// hubiera tocado nada.
//
// Sin proyecto activo no se afirma nada: idle, y se dice por qué.
func (e *escritorio) reponerOrbe() {
	p := e.activoActual()
	if p == nil {
		e.tray.set("idle", "aún no has commiteado en un proyecto vigilado")
		return
	}
	e.actualizarOrbe(p)
}

// tooltipDelOrbe es la frase que se lee al pasar el ratón por encima.
//
// El caso omitido tiene la suya porque resumenHallazgos contaba hallazgos y
// devolvía "sin observaciones", que sobre un análisis que no miró nada es
// literalmente falso: no es que no hubiera observaciones, es que no se observó.
// Era la misma mentira que el hook ya dejó de contar, en la superficie de al
// lado, y con el agravante de que aquí no hacía falta adivinar nada — el motivo
// venía en el payload.
func tooltipDelOrbe(p *panelPayload) string {
	// Un repo que nunca se ha analizado no tiene "0 hallazgos": no tiene
	// ninguno porque nadie ha mirado, y decir "sin observaciones" ahí es la
	// misma mentira por omisión que el ✓ verde. El placeholder "—" lo pone el
	// registro cuando se enrola un repo o se cambia a uno que no ha commiteado.
	//
	// Va aquí y no en quien enrola, porque es una propiedad del payload: así lo
	// dicen igual el enrolamiento, el cambio de proyecto desde el panel y el
	// sembrado al arrancar, en vez de que cada camino escriba su propia frase.
	if p.Verdict == "—" || p.Verdict == "" {
		return fmt.Sprintf("%s · sin análisis todavía — haz un commit aquí", p.Repo)
	}
	if p.Verdict == "skipped" {
		motivo := p.Reason
		if motivo == "" {
			// Mejor decir que no se revisó sin el porqué que fingir que sí.
			motivo = "el motivo no llegó hasta aquí"
		}
		return fmt.Sprintf("%s · rama %s · sin revisar — %s", p.Repo, p.Branch, motivo)
	}
	// "3 bloqueantes, 1 avisos" es un contador, no una frase. Esto se
	// lee de un vistazo y en singular cuando toca.
	return fmt.Sprintf("%s · rama %s · %s%s", p.Repo, p.Branch,
		resumenHallazgos(p.Blocking, p.Advisory), coberturaDelOrbe(p.Capas))
}

// coberturaDelOrbe añade al tooltip CUÁNTO se miró, no sólo qué se encontró.
//
// Es la diferencia entre "sin observaciones" y "sin observaciones, y estas ocho
// capas lo miraron". El orbe era el único sitio que enseñaba el veredicto sin
// abrir nada, y decía el resultado sin decir el alcance: un ✓ tras un análisis
// con la mitad de los motores caídos se veía idéntico a uno completo.
func coberturaDelOrbe(cs []capas.Capa) string {
	if len(cs) == 0 {
		return ""
	}
	miraron, caidas := 0, 0
	for _, c := range cs {
		switch {
		case c.Cayo():
			caidas++
		case c.Estado == capas.Corrio:
			miraron++
		}
	}
	if caidas > 0 {
		return fmt.Sprintf(" · %d capas revisaron, %d no pudieron", miraron, caidas)
	}
	return fmt.Sprintf(" · %d capas revisaron", miraron)
}
