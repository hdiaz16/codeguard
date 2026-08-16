//go:build codeguard_demo

package main

import (
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// La demo de estados, sólo con `go build -tags codeguard_demo`.
//
// El porqué de la etiqueta está entero en demoestados.go. Aquí basta con esto:
// mientras corre, el orbe NO dice la verdad, y por eso no viaja en el producto
// instalado.
//
// Dos diferencias con la versión que estaba en producción, para que ni siquiera
// en depuración deje la bandeja mintiendo:
//
//   - Termina reponiendo el estado REAL en vez de forzar un idle. Y lo repone
//     recalculándolo del proyecto activo, no de una foto tomada al empezar: si
//     durante los 12 s entró un análisis de verdad, lo que queda a la vista es
//     ése y no el de antes.
//   - El aviso va en el propio tooltip. Quien mire el orbe a mitad de la demo
//     lee que está viendo una demo, no un veredicto.
func (e *escritorio) anadirDemoDeEstados(menu *application.Menu) {
	menu.AddSeparator()
	menu.Add("Demo de estados (12 s) — build de depuración").OnClick(func(*application.Context) {
		go func() {
			for _, s := range []string{"idle", "working", "pass", "blocked", "degraded", "offline"} {
				e.tray.set(s, "DEMO (no es el estado de tu repo): «"+s+"»")
				time.Sleep(2 * time.Second)
			}
			e.reponerOrbe()
		}()
	})
}

const demoDeEstadosCompilada = true
