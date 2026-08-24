package main

import (
	"sync"
	"testing"
	"time"
)

// El orbe es la única salida visible del agente: lo que diga la bandeja ES lo
// que el desarrollador cree que pasó. Estas pruebas vigilan que ningún efecto
// programado de antes pueda contradecir al estado vigente.

type trayEmision struct {
	estado  string
	tooltip string
}

// trayGrabador hace de burbuja: anota cada estado emitido. El timer de
// reversión corre en su propia goroutine, así que la lista va bajo candado.
type trayGrabador struct {
	mu    sync.Mutex
	lista []trayEmision
	aviso chan trayEmision
}

func nuevoTrayGrabador() *trayGrabador {
	return &trayGrabador{aviso: make(chan trayEmision, 32)}
}

func (g *trayGrabador) anotar(estado, tooltip string) {
	e := trayEmision{estado, tooltip}
	g.mu.Lock()
	g.lista = append(g.lista, e)
	g.mu.Unlock()
	// Aviso sin bloquear: quien no esté esperando no debe frenar a la bandeja.
	select {
	case g.aviso <- e:
	default:
	}
}

func (g *trayGrabador) todas() []trayEmision {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]trayEmision(nil), g.lista...)
}

func (g *trayGrabador) ultima(t *testing.T) trayEmision {
	t.Helper()
	todas := g.todas()
	if len(todas) == 0 {
		t.Fatal("la bandeja no emitió ningún estado")
	}
	return todas[len(todas)-1]
}

// esperarEstado espera hasta ver el estado pedido, o falla al agotarse el plazo.
func (g *trayGrabador) esperarEstado(t *testing.T, estado string, plazo time.Duration) trayEmision {
	t.Helper()
	limite := time.After(plazo)
	for {
		select {
		case e := <-g.aviso:
			if e.estado == estado {
				return e
			}
		case <-limite:
			t.Fatalf("no llegó el estado %q en %s; emitidos: %v", estado, plazo, g.todas())
			return trayEmision{}
		}
	}
}

// bandejaDePrueba: sin bandeja del sistema real (tray nil) y con el retardo
// acortado para no esperar los 15 s de producción.
func bandejaDePrueba(retardo time.Duration) (*trayState, *trayGrabador) {
	g := nuevoTrayGrabador()
	return &trayState{emit: g.anotar, resetDelay: retardo}, g
}

const retardoDePrueba = 20 * time.Millisecond

// H006: un pass seguido de un bloqueo dentro de la ventana de reversión. El
// timer del pass no puede revivir el "todo bien" encima de un BLOQUEO activo:
// sería mentirle al usuario justo cuando más importa.
func TestTrayElPassNoRevierteUnEstadoPosterior(t *testing.T) {
	tray, g := bandejaDePrueba(retardoDePrueba)

	tray.setPass("codeguard · rama master · sin observaciones")
	tray.set("blocked", "codeguard · rama master · 1 problema por resolver")

	// De sobra para que el timer del pass haya disparado si nadie lo invalidó.
	time.Sleep(15 * retardoDePrueba)

	if u := g.ultima(t); u.estado != "blocked" {
		t.Errorf("la bandeja terminó en %q (tooltip %q); debía seguir en «blocked»\nemitidos: %v",
			u.estado, u.tooltip, g.todas())
	}
	// Y ni siquiera debió asomarse un idle: el bloqueo es el último estado.
	for _, e := range g.todas()[1:] {
		if e.estado == "idle" {
			t.Errorf("el pass programó una vuelta a idle que sobrevivió al bloqueo\nemitidos: %v", g.todas())
			break
		}
	}
}

// El mismo problema con el estado que abre el análisis siguiente: si el timer
// del pass anterior dispara, el orbe deja de decir que está trabajando.
func TestTrayElPassNoRevierteUnAnalisisEnCurso(t *testing.T) {
	tray, g := bandejaDePrueba(retardoDePrueba)

	tray.setPass("todo bien")
	tray.set("working", "revisando codeguard · rama master")

	time.Sleep(15 * retardoDePrueba)

	if u := g.ultima(t); u.estado != "working" {
		t.Errorf("la bandeja terminó en %q; debía seguir en «working»\nemitidos: %v", u.estado, g.todas())
	}
}

// La contraparte: sin nada que lo interrumpa, el pass SÍ debe volver a idle.
// Sin esta prueba, «quitar el timer» pasaría por arreglo.
func TestTrayElPassVuelveAIdleSiNadieLoInterrumpe(t *testing.T) {
	tray, g := bandejaDePrueba(retardoDePrueba)

	tray.setPass("todo bien")

	e := g.esperarEstado(t, "idle", 2*time.Second)
	if e.tooltip != "todo bien" {
		t.Errorf("la vuelta a idle conservó el tooltip %q; esperaba «todo bien»", e.tooltip)
	}
}

// El contador de generación existe por la reversión que YA salió disparada:
// llegada a ese punto, Stop() devuelve false y no la detiene. Aquí se llama al
// callback con la generación del pass ya caduca, que es justo lo que pasa
// cuando el timer vence a la vez que entra el bloqueo. Un Stop() a secas no
// cubre este caso; por eso no basta como arreglo.
func TestTrayLaReversionEnVueloNoPisaAlEstadoNuevo(t *testing.T) {
	tray, g := bandejaDePrueba(time.Hour) // ningún timer vence por su cuenta

	tray.setPass("todo bien")
	tray.mu.Lock()
	genDelPass := tray.gen
	tray.mu.Unlock()

	tray.set("blocked", "1 problema por resolver")
	tray.revertirAIdle(genDelPass, "todo bien")

	if u := g.ultima(t); u.estado != "blocked" {
		t.Errorf("una reversión en vuelo pisó el estado nuevo: la bandeja quedó en %q\nemitidos: %v",
			u.estado, g.todas())
	}
}

// Concurrencia: en esta máquina no se puede correr -race (no hay cgo), así que
// esta prueba tiene que ganarse la vida con aserciones y no con el detector.
//
// «¿emitió algo?» era lo único que comprobaba, y eso no es una red: pasaba
// habiendo perdido 1.599 de 1.600 emisiones. Ahora se exigen las dos
// propiedades que un mapa de estados con candado mal puesto rompe:
//
//   - NINGUNA emisión se pierde. Cada llamada tiene que llegar a la burbuja; un
//     `emit` fuera del candado o una lista sin proteger se comen anotaciones, y
//     al usuario eso le llega como un orbe que se queda en el estado anterior.
//   - El par (estado, tooltip) llega ENTERO. Los dos viajan juntos desde
//     aplicar(), así que una combinación que nadie escribió —«pass» con el
//     tooltip de «revisando»— sólo puede salir de una lectura partida.
//
// Lo que esta prueba NO cubre, y queda dicho para que nadie lo dé por cubierto:
// el ORDEN en que se pintan dos cambios simultáneos. cambiar() suelta el candado
// antes de llamar a aplicar() —y tiene que hacerlo, porque los setters de la
// bandeja son InvokeSync y pintar con el candado tomado colgaría la aplicación—,
// así que dos estados concurrentes pueden llegar a la bandeja en orden distinto
// al de su generación. Es una ventana de microsegundos, frente a los 15 segundos
// del fallo que arregló H006, pero existe.
func TestTrayCambiosConcurrentesNoSePierdenNiSeMezclan(t *testing.T) {
	// Ventana de reversión larguísima: ningún timer vence durante la prueba, así
	// que los idle no añaden emisiones y el recuento puede ser exacto. El timer
	// ya lo cubren las pruebas de arriba.
	tray, g := bandejaDePrueba(time.Hour)

	const goroutines, porGoroutine = 8, 200
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < porGoroutine; j++ {
				if (i+j)%2 == 0 {
					tray.setPass("commit limpio")
				} else {
					tray.set("working", "revisando")
				}
			}
		}(i)
	}
	wg.Wait()

	emitidas := g.todas()
	if quiero := goroutines * porGoroutine; len(emitidas) != quiero {
		t.Errorf("la bandeja emitió %d estados y se pidieron %d: se perdieron %d por el camino.\n"+
			"Al usuario eso le llega como un orbe congelado en el estado anterior.",
			len(emitidas), quiero, quiero-len(emitidas))
	}

	// Los únicos pares que este bucle puede producir. Cualquier otro es un
	// estado y un tooltip que nunca se escribieron juntos.
	validos := map[trayEmision]bool{
		{"pass", "commit limpio"}: true,
		{"working", "revisando"}:  true,
	}
	for i, e := range emitidas {
		if !validos[e] {
			t.Fatalf("emisión %d con un par que nadie escribió: estado %q con tooltip %q.\n"+
				"El estado y el tooltip salen juntos de aplicar(), así que verlos "+
				"descolocados es una lectura partida.", i, e.estado, e.tooltip)
		}
	}
}

// Dos pass seguidos: el timer del primero no puede acortar la ventana verde
// del segundo ni revertir con el tooltip viejo.
func TestTrayElSegundoPassRearmaSuPropiaVentana(t *testing.T) {
	tray, g := bandejaDePrueba(120 * time.Millisecond)

	tray.setPass("primer commit")
	time.Sleep(30 * time.Millisecond) // el primer timer aún no vence
	tray.setPass("segundo commit")

	e := g.esperarEstado(t, "idle", 3*time.Second)
	if e.tooltip != "segundo commit" {
		t.Errorf("volvió a idle con el tooltip %q; esperaba el del pass vigente «segundo commit»\nemitidos: %v",
			e.tooltip, g.todas())
	}
}
