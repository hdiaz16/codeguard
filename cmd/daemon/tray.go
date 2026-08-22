package main

import (
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

const retardoReset = 15 * time.Second

// trayState es la máquina de estados del orbe: ícono, etiqueta, tooltip y
// burbuja dicen lo mismo porque todos salen de aquí.
//
// La vuelta de «pass» a idle es una transición de esta máquina, no un efecto
// suelto que corra por su cuenta: la programa cambiar() y la invalida cualquier
// estado posterior. Cuando el timer vivía fuera de la máquina, un bloqueo que
// llegaba dentro de esos 15 s quedaba tapado por el «todo bien» del commit
// anterior — el orbe decía que no pasaba nada con un BLOQUEO activo.
type trayState struct {
	// Se fijan al construir la bandeja y ya no se tocan.
	tray *application.SystemTray
	emit func(state, tooltip string)
	// resetDelay lo acortan las pruebas; en cero rige retardoReset.
	resetDelay time.Duration

	// Lo mutable lo comparten las goroutines de IPC, del menú y del propio
	// timer, así que todo va bajo este candado.
	mu    sync.Mutex
	reset *time.Timer
	// gen numera las transiciones: cada estado nuevo abre la suya y con eso
	// deja sin efecto lo que programó el anterior.
	gen uint64
}

// retardo es lo que espera un pass antes de volver a idle.
func (t *trayState) retardo() time.Duration {
	if t.resetDelay > 0 {
		return t.resetDelay
	}
	return retardoReset
}

// set es el único punto de cambio de estado y, por lo mismo, el dueño del timer
// de reversión: entrar aquí cancela cualquier vuelta a idle pendiente.
func (t *trayState) set(state, tooltip string) {
	t.cambiar(state, tooltip, 0)
}

// setPass deja el verde a la vista un rato y luego vuelve a idle — salvo que
// para entonces ya haya pasado otra cosa, que es lo normal en una racha de
// commits.
func (t *trayState) setPass(tooltip string) {
	t.cambiar("pass", tooltip, t.retardo())
}

// cambiar aplica el estado y, si es transitorio, programa su reversión.
// revertirEn en cero significa que el estado se queda hasta nuevo aviso.
func (t *trayState) cambiar(state, tooltip string, revertirEn time.Duration) {
	t.mu.Lock()
	t.gen++
	gen := t.gen
	// Lo que programó la generación anterior ya no representa la realidad.
	if t.reset != nil {
		t.reset.Stop()
		t.reset = nil
	}
	if revertirEn > 0 {
		t.reset = time.AfterFunc(revertirEn, func() { t.revertirAIdle(gen, tooltip) })
	}
	t.mu.Unlock()
	// Fuera del candado a propósito: los setters de la bandeja son InvokeSync y
	// bloquean hasta que el hilo principal los atiende. Pintar con el candado
	// tomado colgaría la aplicación entera en cuanto algo del hilo principal
	// (un clic del menú) quisiera cambiar de estado.
	t.aplicar(state, tooltip)
}

// revertirAIdle corre en la goroutine del timer. Compara generaciones en vez de
// confiar en el Stop(): cuando el callback ya salió disparado, Stop() devuelve
// false y no alcanza a detenerlo — el contador sí lo deja sin efecto.
func (t *trayState) revertirAIdle(gen uint64, tooltip string) {
	t.mu.Lock()
	if t.gen != gen {
		t.mu.Unlock()
		return // otro estado tomó el relevo; esta reversión llegó tarde
	}
	t.gen++ // la reversión es una transición más, y no deja nada programado
	t.reset = nil
	t.mu.Unlock()
	t.aplicar("idle", tooltip)
}

// aplicar pinta el estado donde el usuario lo ve.
//
// Se auditó por qué corre fuera de mu (dos pintados concurrentes pueden llegar
// a la bandeja en orden distinto al de su generación) y se dejó COMO ESTÁ: el
// propio TestTrayCambiosConcurrentesNoSePierdenNiSeMezclan documenta ese orden
// como no cubierto a propósito —una ventana de microsegundos frente a los 15
// segundos del fallo que arregló H006— y el invariante que sí exige es que no se
// pierda ninguna emisión. Serializar aquí y descartar las generaciones
// superadas se probó: perdía 280 de 1600 emisiones y rompía ese invariante.
func (t *trayState) aplicar(state, tooltip string) {
	// Sin bandeja del sistema (pruebas) el estado se observa sólo por emit.
	if t.tray != nil {
		t.tray.SetIcon(trayIcon(state))
		t.tray.SetLabel("CodeGuard: " + state)
		t.tray.SetTooltip("CodeGuard — " + tooltip)
	}
	// La burbuja flotante escucha el mismo estado.
	if t.emit != nil {
		t.emit(state, tooltip)
	}
}

// version la inyecta build-dist con -X main.version desde setup.iss — una
// sola fuente de verdad. "dev" delata un binario compilado a mano.
