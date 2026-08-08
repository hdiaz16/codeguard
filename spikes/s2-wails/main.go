// Spike S2 — Wails v3: system tray con cambio de estado + ventana secundaria
// anclada al borde derecho, sin marco. Criterio: ambas cosas funcionan en Windows 11.
package main

import (
	"log"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

const panelHTML = `<!doctype html>
<html><head><meta charset="utf-8"><style>
  body { font-family: "Segoe UI", sans-serif; background:#1a232b; color:#dee6ec;
         margin:0; padding:1.5rem; }
  h1 { font-size:1rem; margin:0 0 .5rem; }
  .estado { color:#57bcb4; font-weight:600; }
  p { font-size:.85rem; color:#a6b4bf; }
</style></head>
<body>
  <h1>CodeGuard — spike S2</h1>
  <p>Panel lateral: ventana secundaria de Wails v3, sin marco, anclada a la derecha.</p>
  <p>Estado del tray: <span class="estado" id="st">ciclando…</span></p>
</body></html>`

func main() {
	app := application.New(application.Options{
		Name: "codeguard-spike-s2",
	})

	// Ventana principal mínima (Wails necesita al menos una; queda oculta).
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "principal (oculta)",
		Hidden: true,
		Width:  300,
		Height: 200,
	})

	// Panel lateral: sin marco, anclado al borde derecho, siempre visible.
	panel := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:         "CodeGuard",
		Frameless:     true,
		AlwaysOnTop:   true,
		Width:         360,
		Height:        520,
		HTML:          panelHTML,
		DisableResize: true,
	})

	tray := app.SystemTray.New()
	tray.SetLabel("CodeGuard: idle")
	tray.SetTooltip("CodeGuard — spike S2 (idle)")

	menu := application.NewMenu()
	menu.Add("Mostrar panel").OnClick(func(_ *application.Context) { panel.Show() })
	menu.Add("Salir").OnClick(func(_ *application.Context) { app.Quit() })
	tray.SetMenu(menu)

	// Ciclo de estados del tray: valida que el ícono/tooltip puede cambiar en caliente.
	go func() {
		states := []string{"idle", "working", "pass", "blocked", "degraded"}
		i := 0
		for range time.Tick(2 * time.Second) {
			s := states[i%len(states)]
			tray.SetLabel("CodeGuard: " + s)
			tray.SetTooltip("CodeGuard — spike S2 (" + s + ")")
			i++
		}
	}()

	// Anclar el panel al borde derecho de la pantalla primaria una vez arrancado.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(_ *application.ApplicationEvent) {
		if screen := app.Screen.GetPrimary(); screen != nil {
			w := screen.WorkArea
			panel.SetPosition(w.X+w.Width-360, w.Y)
			panel.SetSize(360, w.Height)
		}
		panel.Show()
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
