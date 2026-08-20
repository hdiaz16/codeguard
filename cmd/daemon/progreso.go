package main

import (
	"fmt"
	"sync"
	"time"

	"codeguard/internal/capas"
	"codeguard/internal/pipeline"
)

// El orbe MIENTRAS dura el análisis.
//
// El orbe pasaba de «revisando» al veredicto y en medio —cuatro o cinco segundos
// mirando una pantalla— no decía absolutamente nada. Peor: si el análisis no
// volvía nunca (el proceso del daemon se traga un panic, un motor se cuelga por
// encima de su plazo), el orbe se quedaba en «revisando tu cambio» PARA SIEMPRE,
// afirmando que hay un análisis en marcha que ya no existe.
//
// Este archivo resuelve las dos cosas con el mismo estado, porque son el mismo
// invariante: hay como mucho UN análisis en curso, y o avanza o se declara
// muerto. Partirlo en «el contador del progreso» por un lado y «el temporizador
// de seguridad» por otro dejaría el hueco de siempre — un avance que llega
// después de la muerte, o una muerte que se pinta encima del veredicto.

// eventoProgreso es el nombre del evento que escucha widget.html. Es una
// constante porque el nombre es el cable: si se renombra aquí y no allí, el orbe
// se queda mudo sin que nada falle. La prueba de contrato ata los dos lados.
const eventoProgreso = "progreso"

// plazoMinimoDelAnalisis es el mismo suelo que aplica el daemon cuando el hook
// no manda plazo (ver Server.Analyze).
const plazoMinimoDelAnalisis = 5 * time.Second

// margenDelVigilante es lo que se le concede a un análisis POR ENCIMA de su
// propio plazo antes de darlo por muerto.
//
// Generoso a propósito, y en esta dirección: acusar de muerto a un análisis vivo
// pinta un naranja falso y encima se desmiente solo un segundo después, que es
// justo cómo se enseña a ignorar una señal. El plazo del hook sólo acota la
// etapa 2; leer la config, la baseline y el caché quedan fuera, así que el total
// real es siempre algo mayor que el plazo. Y el vigilante se rearma con cada
// avance: lo que mide no es cuánto tarda el análisis sino cuánto lleva CALLADO,
// que es lo único que de verdad distingue lento de muerto.
const margenDelVigilante = 10 * time.Second

// plazoDelVigilante: cuánto silencio se tolera antes de cortar el «revisando».
func plazoDelVigilante(deadlineMs int) time.Duration {
	plazo := time.Duration(deadlineMs) * time.Millisecond
	if plazo < plazoMinimoDelAnalisis {
		plazo = plazoMinimoDelAnalisis
	}
	return plazo + margenDelVigilante
}

// analisisEnCurso es lo que el orbe sabe del análisis que corre AHORA.
//
// Lo tocan tres orígenes distintos: la goroutine del IPC (empieza y termina), las
// goroutines de los motores (cada capa que acaba) y la del propio temporizador.
// Por eso todo va bajo mu, contador de generación incluido — el mismo patrón que
// trayState, y por la misma razón: un temporizador que ya salió disparado no se
// detiene con Stop(), sólo se deja sin efecto.
type analisisEnCurso struct {
	mu sync.Mutex
	// gen numera los análisis. Cada uno abre la suya y con eso invalida el
	// vigilante del anterior.
	gen   uint64
	timer *time.Timer
	vivo  bool

	// runID identifica el análisis. Dos repos pueden commitear a la vez —el
	// servidor atiende cada conexión en su goroutine—, y sin esto los avances
	// de uno se contarían en el marcador del otro.
	runID string
	repo  string
	rama  string

	plazo   time.Duration
	alMorir func(repo, rama string)

	// total es cuántas capas van a mirar. Empieza en -1 y no en 0 porque son
	// dos afirmaciones distintas: «todavía no sé cuántas» y «ninguna».
	total   int
	hechas  int
	miraron int
	caidas  int
}

// avanceVisible es la foto que se lleva quien va a pintar. Copia y no puntero:
// sale de una sección crítica hacia el bus de eventos, y el original lo siguen
// reescribiendo los motores que aún corren.
type avanceVisible struct {
	repo, rama string
	total      int
	hechas     int
	miraron    int
	caidas     int
	// ultima es la capa que acaba de terminar; vacía en la apertura.
	ultima capas.Capa
}

// empezar abre un análisis y arma el vigilante.
func (a *analisisEnCurso) empezar(runID, repo, rama string, plazo time.Duration, alMorir func(repo, rama string)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gen++
	a.detenerLocked()
	a.runID, a.repo, a.rama = runID, repo, rama
	a.plazo, a.alMorir = plazo, alMorir
	a.total, a.hechas, a.miraron, a.caidas = -1, 0, 0, 0
	a.vivo = true
	a.armarLocked()
}

// avanzar aplica un paso y devuelve qué pintar.
//
// Descarta lo que llega de otro análisis o de uno ya cerrado, y ese descarte es
// media funcionalidad: un avance rezagado pintado después del veredicto dejaría
// al orbe contando capas de un commit que ya se decidió. El bus de Wails no
// garantiza el orden entre emisiones (cada Emit despacha en su propia goroutine),
// así que hay que suponer que los rezagados existen.
func (a *analisisEnCurso) avanzar(runID string, av pipeline.Avance) (avanceVisible, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.vivo || runID != a.runID {
		return avanceVisible{}, false
	}
	// Las cifras sólo crecen. El bus no garantiza el orden entre emisiones —el
	// comentario de arriba ya avisa de que hay que suponer rezagados—, y un
	// avance atrasado trae un total o un hechas MENOR que el ya visto: pintarlo
	// haría retroceder el marcador y lo descuadraría con miraron y caidas, que
	// sí subieron con los avances que llegaron antes. Es el mismo invariante que
	// el guion del orbe ya defiende del lado del cliente. Como total empieza en
	// -1, el primer valor conocido entra aunque sea 0: se rechaza el paso atrás,
	// no el descubrimiento.
	if av.Total > a.total {
		a.total = av.Total
	}
	if !av.Abre() {
		if av.Hechas > a.hechas {
			a.hechas = av.Hechas
		}
		// Sólo se apunta como revisada la capa que REVISÓ. Una caída suma en su
		// propia cuenta: el marcador no puede sugerir cobertura que no hubo.
		switch {
		case av.Capa.Cayo():
			a.caidas++
		case av.Capa.Estado == capas.Corrio:
			a.miraron++
		}
	}
	a.armarLocked() // sigue vivo: se le renueva el plazo
	return avanceVisible{
		repo: a.repo, rama: a.rama,
		total: a.total, hechas: a.hechas, miraron: a.miraron, caidas: a.caidas,
		ultima: av.Capa,
	}, true
}

// terminar cierra SU análisis: apaga el vigilante y deja de aceptar avances.
//
// Cierra por runID y no a secas, y la diferencia se ve con dos repos
// commiteando a la vez: el servidor atiende cada conexión en su goroutine, así
// que el veredicto del primero puede llegar con el segundo ya en marcha. Un
// cierre ciego apagaría el vigilante del segundo y tiraría sus avances — o sea
// que el análisis vivo se quedaría sin marcador Y sin red de seguridad, que es
// justo la combinación que deja al orbe colgado.
//
// Devuelve si lo cerró él. En falso, o el vigilante ya lo había dado por muerto
// —y entonces ya terminó de pintar, porque pinta con el candado tomado, que es
// lo que garantiza que el veredicto de verdad se pinte DESPUÉS y gane— o el
// análisis en curso es otro y no hay nada que cerrar.
func (a *analisisEnCurso) terminar(runID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.vivo || runID != a.runID {
		return false
	}
	a.gen++
	a.vivo = false
	a.detenerLocked()
	return true
}

func (a *analisisEnCurso) detenerLocked() {
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
}

// armarLocked programa la muerte del análisis para dentro de a.plazo. Exige a.mu.
func (a *analisisEnCurso) armarLocked() {
	a.detenerLocked()
	if a.alMorir == nil || a.plazo <= 0 {
		return
	}
	gen, repo, rama, alMorir := a.gen, a.repo, a.rama, a.alMorir
	a.timer = time.AfterFunc(a.plazo, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.gen != gen || !a.vivo {
			return // otro análisis tomó el relevo, o este ya cerró
		}
		a.gen++ // la muerte es una transición más y no deja nada programado
		a.vivo = false
		a.timer = nil
		// Se pinta CON EL CANDADO TOMADO, y es deliberado. Es lo que ordena esta
		// muerte contra el veredicto que pueda estar llegando por el IPC: quien
		// llame a terminar() se queda esperando aquí, así que su pintada del
		// veredicto real ocurre después y tapa a esta. Sin eso, una carrera de
		// microsegundos podía dejar «el análisis no terminó» encima de un
		// resultado que sí llegó. El precio —el candado tomado durante una
		// pintada— sólo se paga cuando algo ya está roto.
		alMorir(repo, rama)
	})
}

// tooltip es lo que se lee al dejar el ratón sobre el orbe durante el análisis.
//
// Es el ÚNICO sitio donde se redacta el avance, igual que tooltipDelOrbe lo es
// para el análisis terminado. Y cuenta las tres cifras por separado —revisaron,
// no pudieron, faltan— en vez de un «3 de 9» a secas: ese numerador se lee como
// cobertura, y una capa que se cayó también termina. Sumarlas en el mismo número
// sería prometer una revisión que no ocurrió, en la superficie que existe
// precisamente para no hacer eso.
func (v avanceVisible) tooltip() string {
	cab := fmt.Sprintf("%s · rama %s", v.repo, v.rama)
	switch {
	case v.total < 0:
		// Todavía no se sabe cuántas capas aplican: no se inventa un total.
		return cab + " · revisando tu cambio"
	case v.total == 0:
		return cab + " · ninguna capa aplica a este cambio"
	case v.hechas == 0:
		return cab + " · " + plural(v.total, "1 capa va a mirar", "%d capas van a mirar")
	}
	detalle := plural(v.miraron, "1 revisó", "%d revisaron")
	if v.caidas > 0 {
		detalle += " · " + plural(v.caidas, "1 no pudo", "%d no pudieron")
	}
	if faltan := v.total - v.hechas; faltan > 0 {
		detalle += fmt.Sprintf(" · faltan %d", faltan)
	}
	return cab + " · " + detalle
}

// susurro es la línea corta que sale sobre el orbe con cada paso.
//
// Corta de verdad: la burbuja no envuelve el texto (white-space: nowrap sobre
// 230 px en widget.html), así que lo que no quepa se sale de la cápsula. Aquí
// caben unos treinta caracteres, y por eso el desglose honesto vive en el
// tooltip y aquí va el motor con lo que le pasó — que es lo que el dev quiere
// leer de reojo: «¿va avanzando y quién acaba de mirar?».
func (v avanceVisible) susurro() string {
	switch {
	case v.ultima.Motor == "": // apertura
		// -1 y 0 son dos afirmaciones distintas, como dice el campo total:
		// «todavía no sé cuántas» no puede pintarse como «ninguna aplica», que
		// promete una cobertura vacía que quizá no es cierta. Para el
		// desconocido se usa la misma frase neutra que el tooltip.
		if v.total < 0 {
			return "revisando tu cambio"
		}
		if v.total == 0 {
			return "ninguna capa aplica"
		}
		return plural(v.total, "1 capa mirando", "%d capas mirando")
	case v.ultima.Estado == capas.Ausente:
		return fmt.Sprintf("%d de %d · %s no está", v.hechas, v.total, v.ultima.Motor)
	case v.ultima.Cayo():
		return fmt.Sprintf("%d de %d · %s no pudo", v.hechas, v.total, v.ultima.Motor)
	}
	return fmt.Sprintf("%d de %d · %s listo", v.hechas, v.total, v.ultima.Motor)
}

// cargaDeProgreso es el payload que viaja a widget.html. Vive en una función y
// no en un literal suelto para que la prueba de contrato pueda comparar sus
// claves con lo que el JS lee.
func cargaDeProgreso(v avanceVisible) map[string]any {
	return map[string]any{
		"texto":   v.susurro(),
		"detalle": v.tooltip(),
		// hechas viaja aunque el texto ya lo diga: el orbe lo usa para descartar
		// un avance que llegue tarde y desordenado (el bus no garantiza orden),
		// y así el contador nunca retrocede a la vista del usuario.
		"hechas": v.hechas,
		"total":  v.total,
	}
}
