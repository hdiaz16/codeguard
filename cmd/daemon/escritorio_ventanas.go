package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// el JSON hasta que alguien lo añade aquí a propósito, y ese añadido se ve en la
// revisión.
type configLLMServida struct {
	Proveedores []proveedorUI `json:"proveedores"`
	Provider    string        `json:"provider"`
	Endpoint    string        `json:"endpoint"`
	APIKeyEnv   string        `json:"api_key_env"`
	Model       string        `json:"model"`
	ModelFast   string        `json:"model_fast"`
	TimeoutMs   int           `json:"timeout_ms"`
	EsLocal     bool          `json:"es_local"`
	HayKey      bool          `json:"hay_key"`
	RutaLocal   string        `json:"ruta_local"`
	DelEquipo   string        `json:"del_equipo"`
}

// configLLMParaServir serializa la configuración del modelo pasando por la lista
// blanca: lo que no esté en configLLMServida no sale por el endpoint.
func configLLMParaServir(e estadoConfigLLM) ([]byte, error) {
	// El literal campo a campo es LA lista blanca, no una torpeza: con la
	// conversión de tipo que sugiere S1016, un campo nuevo añadido a ambos
	// structs fluiría al endpoint sin que esta función lo delatara en la
	// revisión — que es exactamente lo que este archivo existe para impedir.
	//lint:ignore S1016 la copia explícita es una lista blanca deliberada
	return json.Marshal(configLLMServida{
		Proveedores: e.Proveedores,
		Provider:    e.Provider,
		Endpoint:    e.Endpoint,
		APIKeyEnv:   e.APIKeyEnv,
		Model:       e.Model,
		ModelFast:   e.ModelFast,
		TimeoutMs:   e.TimeoutMs,
		EsLocal:     e.EsLocal,
		HayKey:      e.HayKey,
		RutaLocal:   e.RutaLocal,
		DelEquipo:   e.DelEquipo,
	})
}

// ── Ventanas ─────────────────────────────────────────────────────────────────

func (e *escritorio) construirVentanas() {
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
	if e.panel == nil {
		return
	}
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
	if e.panel == nil {
		e.panel = e.construirPanel()
	}
	e.anclarPanel()
	e.panel.Show()
	e.app.Event.Emit("panel-show", nil)
}

// alternarPanel es lo que hacen el clic en la burbuja y el clic izquierdo en
// el ícono de la bandeja: si el panel está visible se cierra con animación de
// plegado; si no, emerge.
func (e *escritorio) alternarPanel() {
	if e.panel != nil && e.panel.IsVisible() {
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
	// Vía InvokeAsync como todo lo que toca ventanas: el callback del menú no
	// corre en el hilo de la UI, y mostrarPanel toca ultimoAnclaje y la
	// ventana. Los demás caminos (clic en el orbe, bandeja, IPC) ya lo hacen.
	menu.Add("Mostrar panel").OnClick(func(*application.Context) { application.InvokeAsync(e.mostrarPanel) })
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

