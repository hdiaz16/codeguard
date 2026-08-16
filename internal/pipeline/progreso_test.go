package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// El progreso en vivo existe porque el orbe pasaba de «revisando» al veredicto y
// entre medias —cuatro o cinco segundos— no decía nada. Estas pruebas defienden
// las tres cosas de las que cuelga que sirva para algo: que llegue MIENTRAS
// corre, que la cuenta sea de verdad, y que lo que diga de una capa sea lo mismo
// que dirá el resultado. Un progreso que miente es peor que no tener progreso.

// grabadorDeAvances anota lo que el pipeline publica. El candado propio es
// obligatorio: los avisos salen de las goroutines de los motores.
type grabadorDeAvances struct {
	mu    sync.Mutex
	lista []Avance
}

func (g *grabadorDeAvances) anotar(av Avance) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lista = append(g.lista, av)
}

func (g *grabadorDeAvances) todos() []Avance {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Avance(nil), g.lista...)
}

// correrConProgreso corre el embudo con el callback puesto y devuelve las dos
// mitades que estas pruebas comparan: lo que se dijo en vivo y lo que quedó.
func correrConProgreso(t *testing.T, motores []engines.Engine, fn func(Avance)) *Result {
	t.Helper()
	res, err := Run(context.Background(), Options{
		Config: &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000},
		Diff: &gitdiff.Diff{
			Files: []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}},
			Lines: 1,
		},
		Engines:  motores,
		Progreso: fn,
	})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	return res
}

// El denominador del orbe («3 de 9») sólo puede contar capas que de verdad van a
// mirar. Contando también las que no aplican, la barra se quedaría clavada a
// media revisión para siempre y, peor, el dev leería un total de cobertura que
// nunca existió — que es exactamente lo que este producto no puede hacer.
func TestElProgresoCuentaSoloLasCapasQueVanAMirar(t *testing.T) {
	var g grabadorDeAvances
	correrConProgreso(t, []engines.Engine{
		&motorControlado{nombre: "mira1", aplica: true},
		&motorControlado{nombre: "mira2", aplica: true},
		&motorControlado{nombre: "noaplica1", aplica: false},
		&motorControlado{nombre: "noaplica2", aplica: false},
	}, g.anotar)

	avisos := g.todos()
	if len(avisos) == 0 {
		t.Fatal("el análisis no publicó ni un avance: el orbe se queda mudo los segundos que dura")
	}
	if !avisos[0].Abre() {
		t.Fatalf("el primer aviso debe ser el de apertura (el denominador antes de arrancar), llegó %+v", avisos[0])
	}
	if avisos[0].Total != 2 {
		t.Errorf("la apertura anuncia %d capas y sólo 2 iban a mirar: el orbe prometería una "+
			"cobertura que nunca se pidió", avisos[0].Total)
	}
	// Y ninguna capa que no aplica puede aparecer como terminada.
	for _, av := range avisos[1:] {
		if av.Capa.Motor == "noaplica1" || av.Capa.Motor == "noaplica2" {
			t.Errorf("se anunció como terminada la capa %q, que ni siquiera aplicaba", av.Capa.Motor)
		}
		if av.Total != 2 {
			t.Errorf("el total cambió a mitad del análisis (%d): el marcador del orbe saltaría", av.Total)
		}
	}
	if hechas := len(avisos) - 1; hechas != 2 {
		t.Errorf("terminaron %d capas y se anunciaron %d", 2, hechas)
	}
}

// Lo que el orbe dice EN VIVO de una capa y lo que el panel dice de esa misma
// capa al terminar salen de la misma función a propósito (capaDe). Con la
// clasificación escrita dos veces, el orbe podía enseñar «gofmt listo» de una
// capa que el panel lista como caída medio segundo después, y el dev no tendría
// forma de saber cuál de las dos superficies le miente.
func TestElProgresoDiceDeCadaCapaLoMismoQueElResultado(t *testing.T) {
	var g grabadorDeAvances
	res := correrConProgreso(t, []engines.Engine{
		&motorControlado{nombre: "limpio", aplica: true},
		&motorControlado{nombre: "conhallazgos", aplica: true,
			hallazgos: []finding.Finding{mk("r1", "a.go", 1, false)}},
		&motorControlado{nombre: "ausente", aplica: true, err: fs.ErrNotExist},
		&motorControlado{nombre: "roto", aplica: true, err: errors.New("explotó")},
		&motorControlado{nombre: "sinplazo", aplica: true, err: context.DeadlineExceeded},
	}, g.anotar)

	enVivo := map[string]capas.Capa{}
	for _, av := range g.todos() {
		if !av.Abre() {
			enVivo[av.Capa.Motor] = av.Capa
		}
	}
	vistas := 0
	for _, c := range res.Capas {
		if c.Estado == capas.NoAplica {
			continue // esas no se anuncian: nunca arrancaron
		}
		vistas++
		vivo, hubo := enVivo[c.Motor]
		if !hubo {
			t.Errorf("la capa %s (%s) terminó y el orbe no se enteró", c.Motor, c.Estado)
			continue
		}
		if vivo.Estado != c.Estado {
			t.Errorf("%s: el orbe dijo en vivo %q y el resultado dice %q.\n"+
				"Dos superficies contando cosas distintas del mismo commit es peor "+
				"que cualquiera de las dos sola.", c.Motor, vivo.Estado, c.Estado)
		}
		if vivo.Hallazgos != c.Hallazgos {
			t.Errorf("%s: en vivo %d hallazgos, en el resultado %d", c.Motor, vivo.Hallazgos, c.Hallazgos)
		}
		if vivo.Detalle != c.Detalle {
			t.Errorf("%s: en vivo el detalle era %q y al final es %q", c.Motor, vivo.Detalle, c.Detalle)
		}
	}
	if vistas != 5 {
		t.Fatalf("esperaba comparar las 5 capas que arrancaron, comparé %d", vistas)
	}
	// Y la que importa: una capa caída jamás puede anunciarse como que revisó.
	for _, motor := range []string{"ausente", "roto", "sinplazo"} {
		if enVivo[motor].Estado == capas.Corrio {
			t.Errorf("%s no pudo correr y el orbe lo anunció como que revisó (%q): "+
				"cobertura prometida que no existe", motor, enVivo[motor].Estado)
		}
	}
}

// Los motores corren en paralelo, así que sin serializar aquí cada consumidor
// tendría que poner su propio candado y llevar su propia cuenta — y la cuenta
// saldría mal, porque «cuántas van» sólo se puede contar donde se serializa.
//
// En esta máquina no hay -race (no hay cgo), así que la prueba se gana la vida
// con dos aserciones y no con el detector: el callback duerme dentro, y dos
// callbacks dormidos a la vez son la prueba directa de que nadie los ordena.
func TestLosAvisosDeProgresoLleganDeUnoEnUnoYEnOrden(t *testing.T) {
	const motores = 24

	var dentro, solapes atomic.Int32
	var mu sync.Mutex
	var hechas []int

	fn := func(av Avance) {
		if dentro.Add(1) > 1 {
			solapes.Add(1)
		}
		// La ventana en la que un segundo callback sin candado entraría.
		time.Sleep(2 * time.Millisecond)
		mu.Lock()
		if !av.Abre() {
			hechas = append(hechas, av.Hechas)
		}
		mu.Unlock()
		dentro.Add(-1)
	}

	var lista []engines.Engine
	for i := 0; i < motores; i++ {
		lista = append(lista, &motorControlado{nombre: fmt.Sprintf("m%02d", i), aplica: true})
	}
	correrConProgreso(t, lista, fn)

	if n := solapes.Load(); n != 0 {
		t.Errorf("%d avisos entraron mientras otro seguía dentro: el consumidor recibe "+
			"llamadas en paralelo y la cuenta de capas no puede salir bien", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hechas) != motores {
		t.Fatalf("se anunciaron %d capas terminadas y eran %d: alguna se perdió", len(hechas), motores)
	}
	for i, h := range hechas {
		if h != i+1 {
			t.Fatalf("la cuenta llegó desordenada o repetida: aviso %d dijo «%d hechas» "+
				"(esperaba %d). Secuencia: %v", i, h, i+1, hechas)
		}
	}
}

// motorLento no devuelve hasta que alguien le avisa. Existe para probar lo único
// que hace útil a esta funcionalidad: que el avance llegue MIENTRAS el análisis
// corre. Publicarlo en un repaso al final compilaría, pasaría cualquier prueba
// de contenido y no serviría absolutamente para nada.
type motorLento struct {
	nombre string
	espera <-chan struct{}
	plazo  time.Duration
}

func (m *motorLento) Name() string               { return m.nombre }
func (m *motorLento) Applies(engines.Input) bool { return true }
func (m *motorLento) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	select {
	case <-m.espera:
		return nil, nil
	case <-time.After(m.plazo):
		return nil, errors.New("no llegó ningún avance mientras el análisis corría")
	}
}

func TestElProgresoLlegaMientrasElAnalisisCorre(t *testing.T) {
	visto := make(chan struct{})
	var una sync.Once
	fn := func(av Avance) {
		if !av.Abre() && av.Capa.Motor == "rapido" {
			una.Do(func() { close(visto) })
		}
	}

	lento := &motorLento{nombre: "lento", espera: visto, plazo: 5 * time.Second}
	res := correrConProgreso(t, []engines.Engine{
		&motorControlado{nombre: "rapido", aplica: true},
		lento,
	}, fn)

	for _, c := range res.Capas {
		if c.Motor != "lento" {
			continue
		}
		if c.Estado != capas.Corrio {
			t.Fatalf("el motor lento acabó %q (%s): nadie le avisó de que otra capa había "+
				"terminado, o sea que el progreso se publica cuando ya terminó todo. "+
				"Un progreso que llega al final no es progreso.", c.Estado, c.Detalle)
		}
	}
}

// El hook corre el MISMO pipeline sin ventana ni bus de eventos: deja el
// callback en nil. Es el camino del commit de todos los días y no puede pagar
// nada por una funcionalidad del daemon, ni mucho menos reventar por ella.
func TestSinCallbackElPipelineCorreIgual(t *testing.T) {
	res := correrConProgreso(t, []engines.Engine{
		&motorControlado{nombre: "uno", aplica: true},
		&motorControlado{nombre: "dos", aplica: true, err: errors.New("explotó")},
	}, nil)
	if len(res.Capas) != 2 {
		t.Fatalf("sin callback el resultado tiene que ser el de siempre: %+v", res.Capas)
	}
}

// Un cambio tan grande que sólo se revisan secretos: NINGUNA capa determinista
// corre. El orbe tiene que enterarse igual — un total que nunca llega deja la
// cuenta abierta, y una cuenta abierta es el estado colgado que esto viene a
// quitar.
func TestElProgresoAvisaTambienCuandoNingunaCapaVaAMirar(t *testing.T) {
	var g grabadorDeAvances
	res, err := Run(context.Background(), Options{
		Config: &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 10},
		Diff: &gitdiff.Diff{
			Files: []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}},
			Lines: 5000, // por encima de MaxDiffLines: degrada a sólo-secretos
		},
		Engines:  []engines.Engine{&motorControlado{nombre: "nunca", aplica: true}},
		Progreso: g.anotar,
	})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if len(res.Degraded) == 0 {
		t.Fatal("el montaje no llegó a degradar a sólo-secretos: la prueba no prueba nada")
	}

	avisos := g.todos()
	if len(avisos) != 1 {
		t.Fatalf("esperaba sólo el aviso de apertura, llegaron %d: %+v", len(avisos), avisos)
	}
	if !avisos[0].Abre() || avisos[0].Total != 0 {
		t.Errorf("con ninguna capa corriendo la apertura debe decir 0, dijo %+v", avisos[0])
	}
}
