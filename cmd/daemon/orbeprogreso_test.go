package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"codeguard/internal/capas"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
)

// El orbe pasaba de «revisando» al veredicto sin decir nada en medio, y si el
// análisis no volvía se quedaba en «revisando» PARA SIEMPRE. Estas pruebas
// defienden lo segundo con la misma dureza que lo primero: un indicador de
// seguridad que afirma un análisis en marcha que ya no existe miente igual que
// el ✓ verde sobre un análisis omitido, sólo que sin caducidad.

// grabadorDeEventos anota lo que el escritorio publica en el bus. Los avances
// llegan desde las goroutines de los motores, así que va bajo candado.
type grabadorDeEventos struct {
	mu    sync.Mutex
	lista []eventoEmitido
}

type eventoEmitido struct {
	nombre string
	datos  any
}

func (g *grabadorDeEventos) anotar(nombre string, datos any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lista = append(g.lista, eventoEmitido{nombre, datos})
}

// progresos son los payloads del evento del orbe, en orden.
func (g *grabadorDeEventos) progresos() []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []map[string]any
	for _, e := range g.lista {
		if e.nombre != eventoProgreso {
			continue
		}
		if m, ok := e.datos.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// escritorioConOrbe arma un escritorio con bandeja simulada y bus observable,
// sin aplicación de Wails. plazo es lo que se le concede al análisis antes de
// darlo por muerto.
func escritorioConOrbe(plazo time.Duration) (*escritorio, *trayGrabador, *grabadorDeEventos) {
	tray, bandeja := bandejaDePrueba(time.Hour) // ninguna reversión a idle interfiere
	var bus grabadorDeEventos
	e, _ := escritorioDePrueba(nil)
	e.tray = tray
	e.emitir = bus.anotar
	e.plazoVigilante = plazo
	return e, bandeja, &bus
}

// temporizadorDelVigilante devuelve el temporizador que el vigilante tiene armado
// AHORA, con el candado tomado. Es la forma de comprobar el rearme —cada avance
// detiene el anterior y arma uno nuevo— y el apagado tras el veredicto SIN reloj
// de pared: el mecanismo se mira, no se espera.
func temporizadorDelVigilante(a *analisisEnCurso) *time.Timer {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.timer
}

func peticion(runID, raiz, rama string) *ipc.Request {
	return &ipc.Request{RunID: runID, RepoRoot: raiz, Branch: rama, DeadlineMs: 5000}
}

func avanceDeCapa(motor, estado string, hechas, total int) pipeline.Avance {
	return pipeline.Avance{
		Capa:   capas.Capa{Motor: motor, Estado: estado},
		Hechas: hechas, Total: total,
	}
}

// ── que se vea avanzar ───────────────────────────────────────────────────────

func TestElOrbeCuentaElAnalisisMientrasCorre(t *testing.T) {
	e, _, bus := escritorioConOrbe(time.Hour)

	e.alEmpezarAnalisis(peticion("r1", "C:/repos/demo", "master"))
	e.alAvanzarAnalisis(peticion("r1", "C:/repos/demo", "master"), pipeline.Avance{Total: 3})
	e.alAvanzarAnalisis(peticion("r1", "C:/repos/demo", "master"), avanceDeCapa("gofmt", capas.Corrio, 1, 3))
	e.alAvanzarAnalisis(peticion("r1", "C:/repos/demo", "master"), avanceDeCapa("semgrep", capas.Corrio, 2, 3))

	av := bus.progresos()
	if len(av) != 3 {
		t.Fatalf("el orbe recibió %d avances de 3: si no publica cada paso, el dev sigue "+
			"mirando cuatro segundos de nada", len(av))
	}
	quiero := []struct{ texto, detalle string }{
		{"3 capas mirando", "demo · rama master · 3 capas van a mirar"},
		{"1 de 3 · gofmt listo", "demo · rama master · 1 revisó · faltan 2"},
		{"2 de 3 · semgrep listo", "demo · rama master · 2 revisaron · faltan 1"},
	}
	for i, q := range quiero {
		if av[i]["texto"] != q.texto {
			t.Errorf("avance %d: el orbe susurra %q, esperaba %q", i, av[i]["texto"], q.texto)
		}
		if av[i]["detalle"] != q.detalle {
			t.Errorf("avance %d: el tooltip dice %q, esperaba %q", i, av[i]["detalle"], q.detalle)
		}
	}
}

// El marcador no puede sumar como revisada una capa que se cayó. Es el mismo ✓
// falso de siempre, en pequeño y en vivo: «2 revisaron» sobre un gofmt que no
// pudo correr es cobertura prometida que no existe.
func TestElMarcadorNoCuentaComoRevisadaUnaCapaQueSeCayo(t *testing.T) {
	e, _, bus := escritorioConOrbe(time.Hour)
	req := peticion("r1", "C:/repos/demo", "master")

	e.alEmpezarAnalisis(req)
	e.alAvanzarAnalisis(req, pipeline.Avance{Total: 4})
	e.alAvanzarAnalisis(req, avanceDeCapa("semgrep", capas.Corrio, 1, 4))
	e.alAvanzarAnalisis(req, avanceDeCapa("gofmt", capas.Degradada, 2, 4))
	e.alAvanzarAnalisis(req, avanceDeCapa("trivy", capas.Ausente, 3, 4))

	av := bus.progresos()
	// Sin esta guarda, un orbe mudo panica por índice —aquí y en el bucle de
	// abajo— en vez de decir qué avance faltó, y el panic entierra el mensaje
	// que explica el porqué.
	if len(av) != 4 {
		t.Fatalf("el orbe publicó %d avances de 4 (arranque + 3 capas): %v", len(av), av)
	}
	ultimo := av[len(av)-1]
	quiero := "demo · rama master · 1 revisó · 2 no pudieron · faltan 1"
	if ultimo["detalle"] != quiero {
		t.Errorf("el tooltip dice %q\nesperaba          %q\n"+
			"Una capa que se cayó también termina: contarla en el numerador de la "+
			"cobertura es prometer una revisión que no ocurrió.", ultimo["detalle"], quiero)
	}
	// Y el susurro de cada una dice lo que le pasó, no un «listo» genérico.
	for i, q := range []string{"1 de 4 · semgrep listo", "2 de 4 · gofmt no pudo", "3 de 4 · trivy no está"} {
		if av[i+1]["texto"] != q {
			t.Errorf("susurro %d: %q, esperaba %q", i, av[i+1]["texto"], q)
		}
	}
}

// ── que nunca se quede colgado ───────────────────────────────────────────────

// El caso que no tenía red: el análisis entra, el orbe se pone a «revisando» y
// nadie vuelve nunca (el proceso se traga un panic, un motor se cuelga, el pipe
// muere a media etapa). Sin vigilante, el orbe afirma indefinidamente que hay
// una revisión en marcha que ya no existe.
func TestElOrbeNoSeQuedaColgadoSiElAnalisisNoVuelve(t *testing.T) {
	e, bandeja, _ := escritorioConOrbe(40 * time.Millisecond)

	e.alEmpezarAnalisis(peticion("r1", "C:/repos/demo", "master"))
	if u := bandeja.ultima(t); u.estado != "working" {
		t.Fatalf("el análisis empieza y el orbe debía ponerse a «working», se puso a %q", u.estado)
	}

	// Nadie llama a alTerminarAnalisis: el análisis se murió.
	sale := bandeja.esperarEstado(t, "degraded", 3*time.Second)

	if u := bandeja.ultima(t); u.estado == "working" {
		t.Errorf("el orbe volvió a «working» después de darse el análisis por muerto: %v", bandeja.todas())
	}
	if !strings.Contains(sale.tooltip, "no terminó") {
		t.Errorf("el orbe salió de «revisando» sin decir por qué (tooltip %q): un cambio de "+
			"color sin explicación se lee como un veredicto, y aquí no hubo ninguno", sale.tooltip)
	}
	// Y no puede inventarse un estado que el orbe no sepa pintar: setState cae a
	// «idle» ante cualquier desconocido, así que la señal se perdería en silencio.
	html, err := os.ReadFile("frontend/widget.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), sale.estado+":") {
		t.Errorf("el vigilante deja el orbe en %q y widget.html no conoce ese estado: "+
			"el orbe lo pintaría como «idle», o sea que no diría nada", sale.estado)
	}
}

// La contraparte, para que «quitar el vigilante» no pase por arreglo al revés:
// un análisis que SÍ termina no puede acabar acusado de muerto.
func TestElVeredictoApagaAlVigilante(t *testing.T) {
	// Plazo largo a propósito: la prueba ya no necesita que el vigilante PUDIERA
	// disparar por reloj —mira el mecanismo, no una ventana de tiempo— y así
	// ningún retraso del planificador puede hacerlo disparar de verdad a mitad.
	e, bandeja, _ := escritorioConOrbe(time.Hour)
	req := peticion("r1", t.TempDir(), "master")

	e.alEmpezarAnalisis(req)
	// Sin vigilante armado al empezar, el resto de la prueba pasaría en vacío: no
	// habría nada que apagar. Que el arma dispara cuando nadie termina el análisis
	// lo fija TestElOrbeNoSeQuedaColgadoSiElAnalisisNoVuelve.
	if temporizadorDelVigilante(&e.enCurso) == nil {
		t.Fatal("el análisis empezó sin vigilante armado: la prueba no tendría nada que apagar")
	}

	e.alTerminarAnalisis(req, &ipc.Response{RunID: "r1", Verdict: "pass", CIParity: true})

	// Aserción negativa SIN reloj de pared. Lo que se comprueba es que el
	// vigilante NO PUEDE disparar después del veredicto, y eso se mira en el
	// mecanismo: terminar() vuelve con el análisis cerrado y el temporizador
	// detenido. Si el callback estuviera pintando justo ahora, pinta con el
	// candado tomado, así que terminar() se habría quedado esperando y la pintada
	// sería ANTERIOR a este punto: ya estaría en la lista de la bandeja y la vería
	// el bucle de abajo. Antes se dormía 1 s contra un plazo de 40 ms, y en un CI
	// cargado un retraso del planificador por encima del margen producía un
	// «degraded» falso intermitente.
	e.enCurso.mu.Lock()
	vivo, armado := e.enCurso.vivo, e.enCurso.timer != nil
	e.enCurso.mu.Unlock()
	if vivo || armado {
		t.Fatalf("el veredicto no apagó al vigilante (vivo=%v, temporizador armado=%v): "+
			"acabará acusando de muerto a un análisis que terminó en «pass»", vivo, armado)
	}

	for _, em := range bandeja.todas() {
		if em.estado == "degraded" {
			t.Fatalf("el análisis terminó en «pass» y el vigilante lo dio por muerto igual: %v",
				bandeja.todas())
		}
	}
	if u := bandeja.ultima(t); u.estado != "pass" {
		t.Errorf("el orbe terminó en %q y el veredicto era «pass»: %v", u.estado, bandeja.todas())
	}
}

// Un avance rezagado —el bus de Wails no garantiza el orden entre emisiones—
// no puede volver a poner al orbe a contar capas de un commit ya decidido.
func TestUnAvanceRezagadoNoRevivelElAnalisisTerminado(t *testing.T) {
	e, _, bus := escritorioConOrbe(time.Hour)
	req := peticion("r1", t.TempDir(), "master")

	e.alEmpezarAnalisis(req)
	e.alAvanzarAnalisis(req, pipeline.Avance{Total: 2})
	e.alTerminarAnalisis(req, &ipc.Response{RunID: "r1", Verdict: "pass", CIParity: true})
	e.alAvanzarAnalisis(req, avanceDeCapa("gofmt", capas.Corrio, 1, 2))

	if n := len(bus.progresos()); n != 1 {
		t.Errorf("se publicaron %d avances y sólo uno llegó antes del veredicto: "+
			"el orbe volvería a contar capas de un commit ya decidido", n)
	}
}

// Dos repos pueden commitear a la vez: el servidor atiende cada conexión en su
// propia goroutine. Los avances de uno no pueden entrar en el marcador del otro.
func TestUnAvanceDeOtroAnalisisNoEntraEnElMarcador(t *testing.T) {
	e, _, bus := escritorioConOrbe(time.Hour)

	e.alEmpezarAnalisis(peticion("r1", "C:/repos/uno", "master"))
	e.alAvanzarAnalisis(peticion("r1", "C:/repos/uno", "master"), pipeline.Avance{Total: 2})
	// Llega el avance de OTRO análisis, con su propio run.
	e.alAvanzarAnalisis(peticion("r2", "C:/repos/otro", "dev"), avanceDeCapa("gofmt", capas.Corrio, 1, 9))

	av := bus.progresos()
	if len(av) != 1 {
		t.Fatalf("el marcador aceptó el avance de otro análisis: %v", av)
	}
	if !strings.HasPrefix(av[0]["detalle"].(string), "uno · rama master") {
		t.Errorf("el orbe habla del proyecto equivocado: %q", av[0]["detalle"])
	}
}

// Dos repos commiteando a la vez: el veredicto del primero llega con el segundo
// ya en marcha. Cerrar «el análisis en curso» a secas apagaría el vigilante del
// segundo y tiraría sus avances — el análisis vivo se quedaría sin marcador Y
// sin red de seguridad, que es justo la combinación que deja al orbe colgado.
func TestElVeredictoDeUnAnalisisNoCierraElDeOtro(t *testing.T) {
	e, bandeja, bus := escritorioConOrbe(60 * time.Millisecond)
	uno := peticion("r1", t.TempDir(), "master")
	dos := peticion("r2", "C:/repos/otro", "dev")

	e.alEmpezarAnalisis(uno)
	e.alEmpezarAnalisis(dos) // entra el segundo commit
	e.alTerminarAnalisis(uno, &ipc.Response{RunID: "r1", Verdict: "pass", CIParity: true})

	// El segundo sigue vivo: sus avances entran…
	e.alAvanzarAnalisis(dos, pipeline.Avance{Total: 2})
	if n := len(bus.progresos()); n != 1 {
		t.Errorf("el veredicto del primer análisis tiró los avances del segundo (%d publicados)", n)
	}
	// …y su vigilante sigue armado.
	bandeja.esperarEstado(t, "degraded", 3*time.Second)
}

// Si el daemon se cae a mitad de un análisis, al arrancar de nuevo no puede
// resucitar el «revisando»: para eso, el análisis en curso NO se guarda en
// ninguna parte del estado que sobrevive. Esta prueba fija ese invariante — es
// lo único que hace honesto el arranque, y se rompería solo el día que alguien
// decida "sembrar" el proyecto en cuanto entra la petición.
func TestElAnalisisEnCursoNoTocaElEstadoQueSobrevive(t *testing.T) {
	e, _, _ := escritorioConOrbe(time.Hour)
	raiz := "C:/repos/demo"
	e.porProyecto[raiz] = &panelPayload{Repo: "demo", RepoRoot: raiz, Verdict: "pass", At: "11:00"}
	e.activo = e.porProyecto[raiz]

	req := peticion("r1", raiz, "master")
	e.alEmpezarAnalisis(req)
	e.alAvanzarAnalisis(req, pipeline.Avance{Total: 3})
	e.alAvanzarAnalisis(req, avanceDeCapa("gofmt", capas.Corrio, 1, 3))

	p := e.activoActual()
	if p == nil || p.Verdict != "pass" {
		t.Fatalf("el análisis en curso pisó el último veredicto guardado: %+v", p)
	}
	for raiz, p := range e.porProyecto {
		if p.Verdict == "working" || p.Verdict == "" {
			t.Errorf("%s quedó guardado con un veredicto de análisis en curso (%q): "+
				"al reiniciar el daemon, el panel y el orbe lo resucitarían", raiz, p.Verdict)
		}
	}
}

// La carrera fea: el vigilante decide que el análisis murió en el mismo instante
// en que el veredicto real está llegando por el IPC. Si la muerte se pintara
// después, el orbe se quedaría diciendo «el análisis no terminó» encima de un
// resultado que sí llegó — y ahí se queda hasta el commit siguiente.
//
// Lo que lo ordena es que la muerte se pinta con el candado tomado: quien cierra
// el análisis espera a que termine, así que su pintada va después y gana.
func TestLaMuerteDelAnalisisNuncaSePintaDespuesDelVeredicto(t *testing.T) {
	var a analisisEnCurso
	var mu sync.Mutex
	var orden []string
	pintando := make(chan struct{})

	a.empezar("r1", "demo", "master", 5*time.Millisecond, func(repo, rama string) {
		close(pintando)
		mu.Lock()
		orden = append(orden, "muerte")
		mu.Unlock()
	})

	// Nada de reloj de pared: terminar se llama cuando el vigilante YA está
	// pintando, que es el instante exacto de la carrera que se quiere fijar.
	// Antes se dormía 50 ms suponiendo que para entonces habría disparado.
	select {
	case <-pintando:
	case <-time.After(3 * time.Second):
		t.Fatal("el vigilante no disparó en 3 s: sin muerte pintada no hay orden que comprobar")
	}
	a.terminar("r1")
	mu.Lock()
	orden = append(orden, "veredicto")
	got := strings.Join(orden, ",")
	mu.Unlock()

	if got != "muerte,veredicto" {
		t.Errorf("el orden de pintado fue %q y tenía que ser «muerte,veredicto».\n"+
			"Con la muerte pintándose después, el orbe se queda acusando de muerto a un "+
			"análisis que sí volvió, y ahí se queda hasta el commit siguiente.", got)
	}
}

// ── el cable con el orbe ─────────────────────────────────────────────────────

// El nombre del evento y los campos del payload son el cable entre Go y el
// orbe. Renombrar cualquiera de los dos no rompe nada visible: el orbe
// simplemente se queda mudo, que es indistinguible de que no haya pasado nada —
// ya ocurrió en este proyecto con el aviso del panel al enrolar un repo.
func TestElOrbeEscuchaElProgresoQueElDaemonEmite(t *testing.T) {
	html, err := os.ReadFile("frontend/widget.html")
	if err != nil {
		t.Fatal(err)
	}
	texto := string(html)

	if !strings.Contains(texto, `Events.On("`+eventoProgreso+`"`) {
		t.Fatalf("el daemon emite %q y widget.html no lo escucha: el orbe se queda mudo "+
			"durante todo el análisis y nada falla", eventoProgreso)
	}

	raw, err := json.Marshal(cargaDeProgreso(avanceVisible{
		repo: "demo", rama: "master", total: 3, hechas: 1, miraron: 1,
		ultima: capas.Capa{Motor: "gofmt", Estado: capas.Corrio},
	}))
	if err != nil {
		t.Fatal(err)
	}
	var carga map[string]any
	if err := json.Unmarshal(raw, &carga); err != nil {
		t.Fatal(err)
	}

	leidos := regexp.MustCompile(`\bpr\.([a-z_][a-z_0-9]*)`).FindAllStringSubmatch(texto, -1)
	if len(leidos) == 0 {
		t.Fatal("no se encontró ninguna lectura del avance en widget.html: o cambió el " +
			"nombre de la variable y esta prueba dejó de mirar nada")
	}
	for _, m := range leidos {
		if _, ok := carga[m[1]]; !ok {
			t.Errorf("widget.html lee pr.%s y ese campo NO viaja en el JSON del avance.\n"+
				"  El orbe pintaría «undefined», o se quedaría callado, que es peor.\n"+
				"  campos que sí manda Go: %v", m[1], claves(carga))
		}
	}
}

// Las dos reglas que impiden que el orbe se quede colgado viven en el JS de
// widget.html y en ningún otro sitio: no se pinta un avance si el análisis ya
// terminó, y el contador no retrocede. La prueba de contrato de arriba ata los
// NOMBRES del cable y no puede decir nada de la lógica — borrar cualquiera de
// las dos guardas la deja verde.
//
// Así que el guion se ejecuta de verdad, sacado del propio HTML, contra un DOM
// de mentira (testdata/orbe_harness.mjs). Node hace falta: sin él no hay forma
// de correr JS, y se dice en voz alta en vez de dar la casilla por buena.
func TestElGuionDelOrbeCumpleSusReglas(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("SIN PROBAR: no hay node en esta máquina, así que la lógica del orbe " +
			"(widget.html) se queda sin ejercitar — sólo se comprobó el contrato de nombres")
	}
	salida, err := exec.Command("node", "testdata/orbe_harness.mjs", "frontend/widget.html").CombinedOutput()
	if err != nil {
		t.Fatalf("el guion del orbe no cumple sus reglas:\n%s", salida)
	}
	t.Log(strings.TrimSpace(string(salida)))
}

// ── el plazo del vigilante ───────────────────────────────────────────────────

// Lo que el vigilante mide es SILENCIO, no duración: por eso cada avance lo
// rearma. Un análisis lento que va avisando está vivo, y acusarlo de muerto
// pinta un naranja falso que además se desmiente solo — que es justo cómo se
// enseña a ignorar una señal.
func TestUnAnalisisQueAvisaNoSeDaPorMuerto(t *testing.T) {
	e, bandeja, _ := escritorioConOrbe(200 * time.Millisecond)
	req := peticion("r1", "C:/repos/demo", "master")

	e.alEmpezarAnalisis(req)

	// El rearme se comprueba en el MECANISMO y no con el reloj de pared: cada
	// avance detiene el temporizador anterior y arma otro con el plazo completo,
	// así que tras cada avance el temporizador tiene que ser uno nuevo. Antes
	// había sleeps de 60 ms contra un plazo de 200 ms, y un retraso del
	// planificador por encima del margen pintaba un «degraded» que no tocaba:
	// intermitente, y en un CI cargado.
	anterior := temporizadorDelVigilante(&e.enCurso)
	if anterior == nil {
		t.Fatal("el análisis empezó sin vigilante armado: sin él, un «revisando» que no " +
			"vuelve se queda pintado para siempre")
	}
	for i := 1; i <= 6; i++ {
		e.alAvanzarAnalisis(req, avanceDeCapa("m", capas.Corrio, i, 9))
		actual := temporizadorDelVigilante(&e.enCurso)
		if actual == nil {
			t.Fatalf("el avance %d dejó al análisis sin vigilante: si ahora se calla, el "+
				"orbe se queda en «revisando» para siempre", i)
		}
		if actual == anterior {
			t.Fatalf("el avance %d no rearmó al vigilante: el temporizador sigue contando "+
				"desde el avance anterior y dará por muerto a un análisis que está avisando", i)
		}
		anterior = actual
	}
	for _, em := range bandeja.todas() {
		if em.estado == "degraded" {
			t.Fatalf("el análisis avisó seis veces y el vigilante lo dio por muerto igual: %v",
				bandeja.todas())
		}
	}

	// La otra mitad, y es la que la versión con sleeps NO tenía: que el
	// temporizador rearmado sea de VERDAD. Al callarse, el vigilante tiene que
	// disparar; si el rearme lo armara con un plazo roto —uno que no vence
	// nunca— la comprobación de identidad de arriba pasaría igual y el orbe se
	// quedaría colgado en «revisando». Espera POSITIVA con 15× de margen, el
	// patrón del archivo: aquí lo que falla es que la muerte NO llegue.
	sale := bandeja.esperarEstado(t, "degraded", 3*time.Second)
	if !strings.Contains(sale.tooltip, "no terminó") {
		t.Errorf("el orbe salió de «revisando» sin decir por qué (tooltip %q)", sale.tooltip)
	}
}

// El plazo sale del que manda el hook, con margen. Un hook que pide más tiempo
// tiene que ganar más tiempo, o el vigilante cortaría análisis vivos en los
// repos grandes — que son justo donde el análisis tarda.
func TestElPlazoDelVigilanteSigueAlDelHook(t *testing.T) {
	corto := plazoDelVigilante(5000)
	largo := plazoDelVigilante(30000)
	if largo <= corto {
		t.Errorf("un hook con 30 s de plazo recibe %v de vigilancia y uno con 5 s recibe %v: "+
			"el vigilante no sigue al plazo real y cortaría análisis vivos", largo, corto)
	}
	if corto <= 5*time.Second {
		t.Errorf("el plazo de vigilancia (%v) no supera al del propio análisis (5s): "+
			"cortaría siempre, justo antes de que llegue el veredicto", corto)
	}
	// Sin plazo del hook rige el suelo, no cero: un cero daría por muerto el
	// análisis en el instante de empezarlo.
	if plazoDelVigilante(0) < plazoMinimoDelAnalisis {
		t.Errorf("sin plazo del hook la vigilancia queda en %v", plazoDelVigilante(0))
	}
}
