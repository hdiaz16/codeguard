package pipeline

import (
	"log"
	"runtime/debug"
	"sync"

	"codeguard/internal/capas"
)

// El progreso EN VIVO del análisis, y por qué sale del pipeline por un callback
// y no por otra vía.
//
// El problema: el orbe pasaba de «revisando» al veredicto y entre medias —cuatro
// o cinco segundos, que es una eternidad mirando una pantalla— no decía nada. El
// dato existía: la etapa 2 ya cronometra cada motor y ya lo escribe en el log.
// Sólo que el log lo lee nadie.
//
// Por qué un callback opcional en Options y no un canal, ni una interfaz, ni que
// el pipeline emita por su cuenta:
//
//   - El pipeline es una LIBRERÍA y el mismo código corre en dos procesos: dentro
//     del daemon (que tiene el bus de Wails) y dentro del hook (que no tiene ni
//     ventana). Si el pipeline conociera Wails, el hook —que es el camino del
//     commit de todos los días— arrastraría la dependencia entera para no usarla.
//     Con el callback, el hook deja el campo en nil y no paga nada: ni una
//     goroutine, ni un canal, ni una asignación.
//   - Un canal obliga a decidir quién lo cierra y qué pasa si nadie lee. Un lector
//     lento congelaría la etapa 2, que corre en el camino del commit; un buffer que
//     se llena obliga a tirar avisos, y entonces los contadores mienten. El
//     callback deja esa decisión donde se puede tomar bien —en el consumidor— y
//     aquí no hay nada que cerrar.
//   - Una interfaz sería el mismo callback con más ceremonia: hay un solo método.
//
// EL CONTRATO, que es lo que hace utilizable esto desde ocho goroutines:
//
//  1. Los avisos llegan DE UNO EN UNO y en orden. Los motores corren en paralelo,
//     así que sin esto el consumidor tendría que poner su propio candado y llevar
//     su propia cuenta — y la cuenta saldría mal, porque «cuántas van» sólo se
//     puede contar donde se serializa.
//  2. Hechas es monótono: 1, 2, 3… hasta Total. Nunca retrocede ni se repite.
//  3. Todos los avisos de la etapa 2 ocurren ANTES de que Run devuelva. Lo
//     garantiza errgroup.Wait: cada aviso se emite dentro de la goroutine del
//     motor, antes de que termine. Quien reciba el resultado puede dar por
//     cerrada la cuenta de avisos de ese análisis.
//  4. El callback NO debe bloquear ni paniquear. Corre en la goroutine de un motor, en el
//     camino del commit, y con el candado del avisador tomado.
type Avance struct {
	// Capa es la que acaba de terminar, con el estado que tendrá en el Result.
	// Viene vacía en el aviso de apertura.
	Capa capas.Capa
	// Hechas es cuántas capas han terminado ya (esta incluida). Cero en la
	// apertura.
	Hechas int
	// Total es cuántas capas van a mirar este cambio. Sólo cuenta las que
	// APLICAN: prometer un denominador con motores que nunca iban a correr sería
	// exactamente la cobertura inventada que este producto no puede permitirse.
	Total int
}

// Abre distingue el aviso de apertura —«la etapa 2 arranca con N capas»— de los
// de cada capa terminada. La apertura existe para que la UI tenga denominador
// desde el primer instante en vez de deducirlo cuando ya no sirve de nada.
func (a Avance) Abre() bool { return a.Capa.Motor == "" }

// avisador entrega los avances de UN análisis cumpliendo el contrato de arriba:
// de uno en uno, en orden y con la cuenta llevada aquí.
type avisador struct {
	fn func(Avance)

	mu     sync.Mutex
	hechas int
	total  int
}

func (a *avisador) emitir(av Avance) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("codeguard: pánico en callback de progreso ignorado para no romper el análisis: %v\n%s", r, debug.Stack())
		}
	}()
	a.fn(av)
}

// abrir anuncia cuántas capas van a mirar. Se llama una sola vez y antes de que
// arranque ninguna, que es lo que le da sentido: un denominador que llega al
// final no es progreso, es un resumen.
func (a *avisador) abrir(total int) {
	if a == nil || a.fn == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total = total
	a.emitir(Avance{Total: total})
}

// capa anuncia que una capa terminó. La llaman las goroutines de los motores en
// paralelo; el candado es lo que convierte ese desorden en una secuencia.
func (a *avisador) capa(c capas.Capa) {
	if a == nil || a.fn == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hechas++
	a.emitir(Avance{Capa: c, Hechas: a.hechas, Total: a.total})
}
