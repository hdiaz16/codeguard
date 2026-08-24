package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/registry"
)

// Estas pruebas existen porque dos fallos del daemon llegaron a producción sin
// que nada los atrapara: el panel salía vacío tras reiniciar y la lista de
// proyectos no se refrescaba. Todo lo que se prueba aquí vive fuera de Wails a
// propósito — ninguna prueba abre una ventana ni arranca la aplicación.

// escritorioDePrueba arma un escritorio sin aplicación: sólo el estado y el
// registro simulado. El campo app queda nil y ningún método de aquí lo toca.
func escritorioDePrueba(repos []registry.Repo) (*escritorio, *[]string) {
	var olvidados []string
	e := &escritorio{
		porProyecto: map[string]*panelPayload{},
		cargarRepos: func() []registry.Repo { return repos },
	}
	// En producción es `go registry.Remove(raiz)`; aquí, síncrono, para poder
	// afirmar sobre lo que se olvidó sin carreras.
	e.olvidarRepo = func(raiz string) { olvidados = append(olvidados, raiz) }
	return e, &olvidados
}

// repoEnDisco crea una carpeta de verdad: listaProyectos comprueba con os.Stat
// que el proyecto siga existiendo, y esa comprobación es parte de lo probado.
func repoEnDisco(t *testing.T, nombre string) registry.Repo {
	t.Helper()
	dir := filepath.Join(t.TempDir(), nombre)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return registry.Repo{Root: filepath.ToSlash(dir), Nombre: nombre}
}

func TestListaProyectosSiembraLosEnroladosAunqueNoHayanCommiteado(t *testing.T) {
	// La lección de portal-cliente: `codeguard init` escribe en repos.json, pero
	// el daemon ya estaba corriendo con su copia en memoria. El registro se
	// relee en cada lista, no sólo al arrancar.
	nuevo := repoEnDisco(t, "portal-cliente")
	e, _ := escritorioDePrueba(nil)
	if lista := e.listaProyectos(""); len(lista) != 0 {
		t.Fatalf("sin proyectos la lista debe venir vacía, llegó %v", lista)
	}

	e.cargarRepos = func() []registry.Repo { return []registry.Repo{nuevo} }
	lista := e.listaProyectos("")
	if len(lista) != 1 {
		t.Fatalf("el proyecto recién enrolado debe aparecer sin esperar al primer commit: %v", lista)
	}
	if p := lista[0]; p.Marca != "○" || p.Nombre != "portal-cliente" || p.Activo {
		t.Errorf("un proyecto sin análisis va con marca ○ y sin activar: %+v", p)
	}
	if p := e.porProyecto[nuevo.Root]; p == nil || p.Verdict != "—" || p.At != "sin análisis" {
		t.Errorf("el proyecto sembrado debe quedar con su estado placeholder: %+v", p)
	}
}

func TestListaProyectosMarcaElEstadoDeCadaUnoYOrdenaPorNombre(t *testing.T) {
	// El orbe habla del proyecto activo, pero el panel muestra a todos con su
	// propio estado: un bloqueo en uno no secuestra el verde de los demás.
	uno := repoEnDisco(t, "alfa")
	dos := repoEnDisco(t, "beta")
	tres := repoEnDisco(t, "gama")
	e, _ := escritorioDePrueba([]registry.Repo{tres, uno, dos})
	e.porProyecto[uno.Root] = &panelPayload{Repo: "alfa", RepoRoot: uno.Root, Verdict: "block"}
	e.porProyecto[dos.Root] = &panelPayload{Repo: "beta", RepoRoot: dos.Root, Verdict: "pass"}

	lista := e.listaProyectos(dos.Root)
	if len(lista) != 3 {
		t.Fatalf("deben salir los tres proyectos: %v", lista)
	}
	quiero := []struct {
		marca, nombre string
		activo        bool
	}{
		{"⛔", "alfa", false},
		{"✓", "beta", true},
		{"○", "gama", false},
	}
	for i, q := range quiero {
		p := lista[i]
		if p.Marca != q.marca || p.Nombre != q.nombre || p.Activo != q.activo {
			t.Errorf("entrada %d: quería %v, llegó %+v", i, q, p)
		}
	}
}

func TestListaProyectosOlvidaElProyectoBorradoDelDisco(t *testing.T) {
	// Un proyecto cuya carpeta ya no existe no es un proyecto: antes seguía
	// en el panel hasta reiniciar el agente.
	vivo := repoEnDisco(t, "vivo")
	muerto := filepath.ToSlash(filepath.Join(t.TempDir(), "borrado")) // nunca se crea
	e, olvidados := escritorioDePrueba([]registry.Repo{vivo})
	e.porProyecto[muerto] = &panelPayload{Repo: "borrado", RepoRoot: muerto, Verdict: "pass"}

	lista := e.listaProyectos("")
	if len(lista) != 1 || lista[0].Nombre != "vivo" {
		t.Fatalf("sólo debe quedar el proyecto vivo: %v", lista)
	}
	if _, sigue := e.porProyecto[muerto]; sigue {
		t.Error("el proyecto borrado debe salir también del estado en memoria")
	}
	if len(*olvidados) != 1 || (*olvidados)[0] != muerto {
		t.Errorf("debe olvidarse también del registro, se olvidó %v", *olvidados)
	}
}

func TestSembrarDesdeRegistroLlenaElPanelTrasReiniciarElDaemon(t *testing.T) {
	// El fallo de la 1.2.0: daemon recién arrancado, sin análisis en memoria.
	// El panel salía vacío y se leía como "se perdieron mis repos".
	uno := repoEnDisco(t, "alfa")
	dos := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{uno, dos})

	e.sembrarDesdeRegistro()

	if e.activo == nil {
		t.Fatal("con proyectos enrolados el panel nunca debe quedarse sin contexto")
	}
	if e.activo.Repo != "alfa" || e.activo.RepoRoot != uno.Root {
		t.Errorf("se muestra el primero del registro, llegó %+v", e.activo)
	}
	if e.activo.Verdict != "—" || e.activo.At != "sin análisis" {
		t.Errorf("sin análisis todavía, el estado es placeholder: %+v", e.activo)
	}
	if len(e.activo.OtrosRepos) != 2 {
		t.Fatalf("el panel debe listar los dos proyectos: %v", e.activo.OtrosRepos)
	}
	if p := e.activo.OtrosRepos[0]; !p.Activo {
		t.Errorf("el sembrado debe quedar marcado como activo: %+v", p)
	}
}

func TestSembrarDesdeRegistroNoPisaElAnalisisEnCurso(t *testing.T) {
	// Sembrar es sólo para el arranque en frío: si ya hubo un análisis, el
	// contexto activo manda.
	uno := repoEnDisco(t, "alfa")
	e, _ := escritorioDePrueba([]registry.Repo{uno})
	analizado := &panelPayload{Repo: "beta", RepoRoot: "c:/repos/beta", Verdict: "block"}
	e.activo = analizado

	e.sembrarDesdeRegistro()

	if e.activo != analizado {
		t.Errorf("el contexto activo no se toca, quedó %+v", e.activo)
	}
}

func TestSembrarDesdeRegistroSinProyectosEnrolados(t *testing.T) {
	// Máquina sin ningún repo enrolado: no hay nada que mostrar y tampoco
	// nada que reventar.
	e, _ := escritorioDePrueba(nil)

	e.sembrarDesdeRegistro()

	if e.activo != nil {
		t.Errorf("sin proyectos no debe inventarse un contexto: %+v", e.activo)
	}
}

func TestRegistrarAnalisisGuardaElContextoYLoVuelveActivo(t *testing.T) {
	uno := repoEnDisco(t, "alfa")
	dos := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{uno, dos})
	e.sembrarDesdeRegistro() // arranque en frío: el activo es alfa

	analisis := &panelPayload{Repo: "beta", RepoRoot: dos.Root, Verdict: "block", Blocking: 2}
	e.registrarAnalisis(analisis)

	if e.activo != analisis {
		t.Fatalf("el proyecto recién analizado pasa a ser el activo: %+v", e.activo)
	}
	if e.porProyecto[dos.Root] != analisis {
		t.Error("el análisis debe quedar guardado en el contexto de su proyecto")
	}
	if raiz, _ := e.raizConfig.Load().(string); raiz != dos.Root {
		t.Errorf("la config del modelo se lee desde el último proyecto analizado, quedó %q", raiz)
	}
	// El otro proyecto conserva su estado: cambiar de contexto no altera a nadie.
	if p := e.porProyecto[uno.Root]; p == nil || p.Verdict != "—" {
		t.Errorf("alfa no debe verse afectado por un bloqueo en beta: %+v", p)
	}
	if len(analisis.OtrosRepos) != 2 {
		t.Fatalf("el panel viaja con la lista completa: %v", analisis.OtrosRepos)
	}
	if p := analisis.OtrosRepos[1]; p.Nombre != "beta" || p.Marca != "⛔" || !p.Activo {
		t.Errorf("beta debe salir bloqueado y activo: %+v", p)
	}
}

// ── Estado compartido entre goroutines ───────────────────────────────────────
//
// El contexto por proyecto lo tocan al menos tres hilos distintos: los
// manejadores de eventos de Wails (el panel se abre, se cambia de repo, se
// pide el explorador), el servidor IPC —que atiende CADA conexión en su
// propia goroutine— y las goroutines que el propio escritorio lanza para
// serializar el grafo. Las pruebas de aquí abajo defienden ese estado.
//
// AVISO SOBRE LA EVIDENCIA: esta máquina no puede correr `go test -race`
// (necesita cgo y no hay compilador de C instalado), así que ninguna de estas
// pruebas se apoya en que el detector de carreras salte. Todas afirman una
// INCONSISTENCIA OBSERVABLE del estado —un análisis que se pierde, un objeto
// ya entregado que cambia bajo su lector—, que es un fallo real por sí mismo y
// se reproduce sin instrumentación. Lo que NO queda certificado aquí es la
// ausencia de carreras de memoria a nivel del modelo de memoria de Go; para
// eso hace falta -race en una máquina con cgo.

// El panel se abre (panel-ready → sembrarDesdeRegistro) justo cuando termina
// un análisis que entra por el IPC. Sembrar mira si hay contexto activo y, si
// no lo hay, lo pone; entre esas dos cosas cabe un análisis entero, y sembrar
// lo pisa con el placeholder "sin análisis" del primer repo del registro. El
// usuario acaba de commitear y el panel le dice que nunca ha analizado nada.
//
// El resultado no depende del orden en que corran los dos hilos: si siembra
// primero, el análisis llega después y manda; si llega primero el análisis,
// sembrar debe ver que ya hay contexto y no tocar nada. En los dos casos el
// contexto activo al final es el análisis.
func TestSembrarDesdeRegistroNoDescartaElAnalisisQueLlegoALaVez(t *testing.T) {
	alfa := repoEnDisco(t, "alfa")
	beta := repoEnDisco(t, "beta")

	const intentos = 300
	perdidos := 0
	for i := 0; i < intentos; i++ {
		e, _ := escritorioDePrueba([]registry.Repo{alfa, beta})
		analisis := &panelPayload{Repo: "beta", RepoRoot: beta.Root, Verdict: "block", Blocking: 2}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); e.sembrarDesdeRegistro() }() // el panel se abre
		go func() { defer wg.Done(); e.registrarAnalisis(analisis) }()
		wg.Wait()

		if e.activo == nil || e.activo.RepoRoot != beta.Root || e.activo.Verdict != "block" {
			perdidos++
		}
	}
	if perdidos > 0 {
		t.Errorf("el análisis recién terminado desapareció del panel en %d de %d intentos: "+
			"sembrar comprueba e.activo y lo escribe sin candado, así que pisa lo que llegó en medio",
			perdidos, intentos)
	}
}

// abrirGrafo saca el contexto del proyecto y se lo lleva a OTRA goroutine
// (`go func(){ e.prepararGrafo(c) }`) que lo lee y lo serializa dentro del
// JSON del explorador. Si lo que se lleva es el puntero que vive en el mapa,
// cualquier publicación posterior le reescribe los campos por debajo mientras
// lo serializa.
//
// Aquí la publicación posterior es la del panel al abrirse. Va sin goroutines
// a propósito: el fallo no necesita concurrencia para verse, la concurrencia
// sólo lo vuelve además una carrera de memoria.
func TestElContextoDelGrafoNoSeMutaDespuesDeEntregarse(t *testing.T) {
	alfa := repoEnDisco(t, "alfa")
	beta := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{alfa, beta})
	e.listaProyectos("") // alta de los enrolados, como al arrancar el daemon

	// El usuario pide el explorador de alfa: el contexto se entrega y viaja.
	c := e.contextoDelGrafo(alfa.Root)
	if c.payload == nil {
		t.Fatal("el contexto del grafo debía traer el payload del proyecto")
	}
	antes, err := json.Marshal(c.payload)
	if err != nil {
		t.Fatal(err)
	}

	// Y mientras tanto se abre el panel, que siembra el contexto activo.
	e.sembrarDesdeRegistro()

	despues, err := json.Marshal(c.payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(antes, despues) {
		t.Errorf("el payload entregado al explorador cambió bajo la goroutine que lo serializa:\n"+
			"  antes:   %s\n  después: %s", antes, despues)
	}
}

// Corolario estructural del anterior: mientras contextoDelGrafo devuelva el
// mismo objeto que vive en el mapa, no hay forma de que el invariante «un
// payload ya entregado no se muta jamás» se sostenga.
func TestContextoDelGrafoNoEntregaElObjetoDelMapa(t *testing.T) {
	beta := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{beta})
	e.listaProyectos("")

	c := e.contextoDelGrafo(beta.Root)
	if c.payload == nil {
		t.Fatal("el contexto del grafo debía traer el payload del proyecto")
	}
	if e.porProyecto[beta.Root] == c.payload {
		t.Error("contextoDelGrafo entrega el objeto que el escritorio sigue mutando; " +
			"debe entregar una copia de la que la otra goroutine sea dueña")
	}
}

// Las tres puertas de entrada al contexto compartido corriendo a la vez, como
// en producción: el IPC registrando análisis, el panel pidiendo su contexto y
// el explorador llevándose el suyo a serializar.
//
// Sin -race esto NO certifica ausencia de carreras de memoria. Lo que sí
// comprueba es que ningún payload publicado cambia mientras su lector lo tiene
// en la mano, y que ninguno llega al bus con la lista de proyectos a medias
// —dos inconsistencias observables que el estado sin candado sí produce.
func TestElContextoCompartidoAguantaLasTresPuertasALaVez(t *testing.T) {
	alfa := repoEnDisco(t, "alfa")
	beta := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{alfa, beta})

	const vueltas = 400
	var mutados int64
	var wg sync.WaitGroup

	// Servidor IPC: cada análisis llega en su propia goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < vueltas; i++ {
			veredicto := "pass"
			if i%2 == 0 {
				veredicto = "block"
			}
			e.registrarAnalisis(&panelPayload{Repo: "beta", RepoRoot: beta.Root, Verdict: veredicto})
		}
	}()

	// El panel abriéndose una y otra vez.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < vueltas; i++ {
			e.sembrarDesdeRegistro()
		}
	}()

	// Explorador: se lleva el contexto a otra goroutine y lo serializa allí,
	// que es lo que hace `go func(){ e.prepararGrafo(c) }`.
	for _, raiz := range []string{alfa.Root, beta.Root} {
		wg.Add(1)
		go func(raiz string) {
			defer wg.Done()
			for i := 0; i < vueltas; i++ {
				c := e.contextoDelGrafo(raiz)
				if c.payload == nil {
					continue
				}
				antes, err1 := json.Marshal(c.payload)
				despues, err2 := json.Marshal(c.payload)
				if err1 != nil || err2 != nil {
					t.Errorf("el contexto del grafo no se pudo serializar: %v %v", err1, err2)
					return
				}
				if !bytes.Equal(antes, despues) {
					atomic.AddInt64(&mutados, 1)
				}
			}
		}(raiz)
	}

	wg.Wait()
	if n := atomic.LoadInt64(&mutados); n > 0 {
		t.Errorf("%d payloads cambiaron mientras su lector los serializaba", n)
	}
	// Con el temporal ya en calma: lo que quede activo debe llevar la lista
	// completa. Un contexto publicado a medias deja al panel sin selector.
	if e.activo == nil {
		t.Fatal("tras 400 análisis debía quedar un contexto activo")
	}
	if len(e.activo.OtrosRepos) != 2 {
		t.Errorf("el contexto activo quedó con la lista a medias: %v", e.activo.OtrosRepos)
	}
}

func TestOrbStateFor(t *testing.T) {
	// El clima del orbe: un bloqueo manda sobre todo lo demás, y una
	// sugerencia no es motivo para pintar de verde ni de rojo.
	casos := []struct {
		nombre  string
		payload *panelPayload
		quiero  string
	}{
		// Con el Outcome derivado a bordo, como los deja construirPayload.
		{"bloqueado", &panelPayload{Verdict: "block", Outcome: "blocked"}, "blocked"},
		{"bloqueado con avisos", &panelPayload{Verdict: "block", Outcome: "blocked", Advisory: 3}, "blocked"},
		{"limpio", &panelPayload{Verdict: "pass", Outcome: "clean"}, "pass"},
		{"sólo sugerencias", &panelPayload{Verdict: "pass", Outcome: "findings", Advisory: 1}, "idle"},
		// Un análisis que corrió con la garantía rota pide que se mire: es el
		// MISMO criterio (SinGarantia, derivado en el productor) que rompe el
		// job del CI y pinta PARCIAL en el hook — el orbe ya no tiene el suyo.
		{"garantía rota", &panelPayload{Verdict: "pass", Outcome: "degraded",
			GarantiaRota: []string{"falta:trivy"}}, "degraded"},
		// Un fallo del análisis no es un salto: la cobertura tiene un agujero.
		{"el análisis falló", &panelPayload{Verdict: "skipped", Outcome: "failed"}, "degraded"},
		// Este caso decía "pass" y era un ✓ falso de los que este archivo
		// persigue: un proyecto enrolado que nadie ha analizado todavía no puede
		// afirmar una revisión limpia. Se llega aquí al abrir el panel con el
		// daemon recién reiniciado. Ahora no afirma nada.
		{"sin análisis", &panelPayload{Verdict: "—"}, "idle"},
		// Y un outcome que este binario no sepa clasificar cae del lado que
		// pide mirar, jamás del que tranquiliza.
		{"outcome desconocido", &panelPayload{Verdict: "pass", Outcome: "estupendo"}, "degraded"},
	}
	for _, c := range casos {
		if got := orbStateFor(c.payload); got != c.quiero {
			t.Errorf("%s: quería %q, llegó %q", c.nombre, c.quiero, got)
		}
	}
}

func TestResumenHallazgos(t *testing.T) {
	// "0 bloqueantes, 1 avisos" obliga a descifrar dos números y encima está
	// mal escrito. Los plurales son el punto de esta función.
	casos := []struct {
		bloqueantes, avisos int
		quiero              string
	}{
		{0, 0, "sin observaciones"},
		{0, 1, "1 sugerencia"},
		{0, 4, "4 sugerencias"},
		{1, 0, "1 problema por resolver"},
		{3, 0, "3 problemas por resolver"},
		{1, 1, "1 problema por resolver y 1 sugerencia"},
		{2, 3, "2 problemas por resolver y 3 sugerencias"},
	}
	for _, c := range casos {
		if got := resumenHallazgos(c.bloqueantes, c.avisos); got != c.quiero {
			t.Errorf("(%d,%d): quería %q, llegó %q", c.bloqueantes, c.avisos, c.quiero, got)
		}
	}
}

func TestMarcaProyecto(t *testing.T) {
	casos := map[string]string{
		"block": "⛔",
		"pass":  "✓",
		// "skipped" daba "✓", y el panel rotula ese ✓ como «limpio — el último
		// commit pasó todas las compuertas». En un análisis omitido no pasó
		// ninguna: el embudo se paró en la etapa 0.
		"skipped": "○",
		"—":       "○",
		"":        "○",
	}
	for veredicto, quiero := range casos {
		if got := marcaProyecto(&panelPayload{Verdict: veredicto}); got != quiero {
			t.Errorf("veredicto %q: quería %q, llegó %q", veredicto, quiero, got)
		}
	}
}

func TestOpcionesUI(t *testing.T) {
	maxShow, autoOpen := opcionesUI(nil)
	if maxShow != 7 || autoOpen != "on_block" {
		t.Errorf("sin configuración legible mandan los valores de §12: %d %q", maxShow, autoOpen)
	}

	cfg := &config.Config{}
	cfg.UI.MaxVisibleFindings = 3
	cfg.UI.AutoOpenPanel = "never"
	if maxShow, autoOpen = opcionesUI(cfg); maxShow != 3 || autoOpen != "never" {
		t.Errorf("el proyecto manda sobre el default: %d %q", maxShow, autoOpen)
	}

	// Un cero o un vacío no son una elección: se quedan los defaults.
	if maxShow, autoOpen = opcionesUI(&config.Config{}); maxShow != 7 || autoOpen != "on_block" {
		t.Errorf("los campos sin poner conservan el default: %d %q", maxShow, autoOpen)
	}
}

func TestConstruirPayloadLlevaElCodigoSenalado(t *testing.T) {
	repo := t.TempDir()
	archivo := filepath.Join(repo, "main.go")
	if err := os.WriteFile(archivo, []byte("uno\ndos\ntres\ncuatro\ncinco\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := &ipc.Request{RepoRoot: repo, Branch: "main", AIGenerated: true}
	resp := &ipc.Response{
		Verdict: "block", BlockingFindings: 1, AdvisoryFindings: 2, ElapsedMs: 42,
		Findings: []finding.Finding{
			{File: "main.go", Line: 3, Source: finding.Deterministic},
		},
	}

	payload := construirPayload(req, resp, nil, 5)

	if payload.Repo != filepath.Base(repo) || payload.Branch != "main" || !payload.AIGenerated {
		t.Errorf("el encabezado del panel sale de la petición: %+v", payload)
	}
	if payload.RepoRoot != filepath.ToSlash(repo) {
		t.Errorf("la raíz viaja con separadores / (es la llave del contexto): %q", payload.RepoRoot)
	}
	if payload.MaxShow != 5 || payload.Verdict != "block" || payload.Blocking != 1 || payload.Advisory != 2 {
		t.Errorf("el veredicto y los contadores salen de la respuesta: %+v", payload)
	}
	if len(payload.Findings) != 1 {
		t.Fatalf("debe viajar el hallazgo: %+v", payload.Findings)
	}
	f := payload.Findings[0]
	if !f.IsFact {
		t.Error("un hallazgo determinista se enuncia como hecho (§12.2)")
	}
	if len(f.Snippet) != 5 {
		t.Fatalf("el snippet lleva la línea señalada y tres a cada lado: %+v", f.Snippet)
	}
	if f.Snippet[2].Text != "tres" || !f.Snippet[2].Culprit {
		t.Errorf("la línea culpable debe venir marcada: %+v", f.Snippet[2])
	}
}

// Un proyecto sembrado del registro NO puede afirmar que la paridad con el CI
// está rota: nadie la ha comprobado todavía.
//
// El panel enseña el aviso amarillo cuando ci_parity es false, y false es el
// cero de Go. Al sembrar el placeholder sin fijar el campo, portal-cliente —un repo
// sano, con su rulepack instalado y resuelto— aparecía acusando "tu rulepack no
// coincide, no puedo garantizar que pase el CI". El arreglo del panel vacío
// (1.3.0) trajo puesto este otro fallo.
func TestElProyectoSembradoNoAcusaFaltaDeParidad(t *testing.T) {
	uno := repoEnDisco(t, "portal")
	e, _ := escritorioDePrueba([]registry.Repo{uno})

	e.sembrarDesdeRegistro()

	if e.activo == nil {
		t.Fatal("el sembrado debia dejar un contexto activo")
	}
	if !e.activo.CIParity {
		t.Error("sin analisis no hay paridad rota que reportar: el panel ensenaria un aviso inventado")
	}
	if e.activo.Verdict != "—" || e.activo.At != "sin analisis" && e.activo.At != "sin análisis" {
		t.Errorf("el placeholder debe verse como lo que es: %+v", e.activo)
	}
}
