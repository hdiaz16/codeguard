package main

import (
	"encoding/json"
	"log"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/codegraph"
	"codeguard/internal/config"
	"codeguard/internal/store"
)

// "sin análisis" justo después de commitear.
func (e *escritorio) sembrarDesdeRegistro() *panelPayload {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.activo != nil {
		// Se RECALCULA la lista, no se devuelve la foto guardada.
		//
		// Aquí había un `return paraPublicar(e.activo)` con el argumento de que
		// "ya hay contexto: sembrar no pisa nada". Cierto para el contexto, y
		// falso para la lista: publicarLocked es lo único que da de alta a los
		// repos recién enrolados y da de baja a los que ya no están en disco,
		// y por este atajo abrir el panel no hacía ninguna de las dos cosas.
		// La limpieza sólo corría al analizar o al cambiar de proyecto, así que
		// un repo borrado seguía listado durante toda la vida del agente y la
		// única salida era reiniciarlo a mano — que es justo lo que un
		// desarrollador no va a hacer, ni tiene por qué saber que existe.
		// Se anota ANTES de republicar: publicarLocked da de alta los enrolados,
		// así que después ya no se puede distinguir quién estaba.
		_, estabaEnElMapa := e.porProyecto[e.activo.RepoRoot]
		if p := e.publicarLocked(e.activo.RepoRoot); p != nil {
			return p
		}
		if !estabaEnElMapa {
			// Contexto activo que nunca estuvo en el mapa de proyectos. No es un
			// repo dado de baja: es un análisis recién llegado, y sembrar no
			// puede pisarlo — es el invariante que defiende
			// TestSembrarDesdeRegistroNoPisaElAnalisisEnCurso.
			return paraPublicar(e.activo)
		}
		// Sí estaba y ya no: su carpeta desapareció y la lista acaba de darlo de
		// baja. Se suelta y se busca otro abajo, porque enseñar el estado de una
		// carpeta que ya no existe es peor que no enseñar nada.
		e.activo = nil
	}
	// El primero del registro que siga existiendo. No vale quedarse con
	// repos[0] a ciegas: el registro puede tener carpetas borradas —su baja es
	// asíncrona— y ese camino devolvía nil dejando el panel vacío, que se lee
	// como "se perdieron mis repos".
	for _, r := range e.cargarRepos() {
		if p := e.publicarLocked(filepath.ToSlash(r.Root)); p != nil {
			return p
		}
	}
	return nil
}

// mostrarContextoActivo responde al panel cuando se abre: le manda el contexto
// activo, sembrándolo del registro si el daemon acaba de arrancar.
func (e *escritorio) mostrarContextoActivo() {
	if p := e.sembrarDesdeRegistro(); p != nil {
		e.app.Event.Emit("analysis", p)
	}
}

// pedirPanel abre el panel respetando la voluntad del usuario.
//
// No basta con emitir "panel-show": el panel nace oculto y sólo lo muestra
// panel.Show(). Y emitir ese evento a secas hace daño — el JS de la burbuja
// marca panelAbierto y con esa bandera el susurro y el tooltip del orbe dejan
// de responder, así que el agente se quedaba MUDO hasta que el usuario abría y
// cerraba el panel a mano.
//
// Se respeta `ui.auto_open_panel: never`: quien lo pone está diciendo que el
// panel no se abre solo, y enrolar un repo no es excusa para desobedecerlo.
func (e *escritorio) pedirPanel(cfg *config.Config) {
	if _, autoOpen := opcionesUI(cfg); autoOpen == "never" {
		return
	}
	if e.abrirPanel != nil {
		e.abrirPanel()
		return
	}
	// Sin aplicación no hay ventana que mostrar. La guarda no es defensa contra
	// un imposible de producción —ahí e.app está siempre— sino contra que una
	// prueba que ejercite esta lógica tenga que enterarse de que existe un
	// punto de sustitución sólo para no morir en InvokeAsync.
	if e.app == nil {
		return
	}
	application.InvokeAsync(e.mostrarPanel)
}

// emitirEvento publica en el bus del frontend. Pasa por el campo emitir para
// que las pruebas puedan observar lo que se publica sin arrancar la aplicación.
func (e *escritorio) emitirEvento(nombre string, datos any) {
	if e.emitir != nil {
		e.emitir(nombre, datos)
		return
	}
	e.app.Event.Emit(nombre, datos)
}

// cambiarDeProyecto pone al frente el contexto de otro repo ya conocido. No
// altera el estado de nadie: cada proyecto conserva su propio análisis.
//
// Sirve igual para un repo que el escritorio aún no ha visto nunca: publicarLocked
// relee el registro antes de buscarlo, así que un repo recién enrolado entra con
// su estado placeholder en vez de darse por desconocido.
func (e *escritorio) cambiarDeProyecto(raiz string) {
	e.mu.Lock()
	p := e.publicarLocked(raiz) // el contexto activo pasa a ser el elegido
	e.mu.Unlock()
	if p == nil {
		return
	}
	e.raizConfig.Store(p.RepoRoot)
	e.emitirEvento("analysis", p)
	e.tray.set(orbStateFor(p), tooltipDelOrbe(p))
}

// registrarAnalisis guarda el contexto de este proyecto y lo vuelve el activo.
// Devuelve la copia que se manda al panel y al orbe.
//
// El escritorio se queda con payload: quien lo construyó no vuelve a tocarlo,
// porque a partir de aquí sólo se lee y se escribe con e.mu tomado.
func (e *escritorio) registrarAnalisis(payload *panelPayload) *panelPayload {
	// cada proyecto guarda su contexto; el activo pasa a ser este
	e.mu.Lock()
	raiz := payload.RepoRoot
	e.porProyecto[raiz] = payload
	p := e.publicarLocked(raiz)
	if p == nil {
		// La lista acaba de dar de baja el repo porque su carpeta ya no
		// está. El análisis manda: acaba de correr sobre ese código.
		e.activo = payload
		p = paraPublicar(payload)
	}
	e.mu.Unlock()
	e.raizConfig.Store(raiz)
	return p
}

// ── Explorador de código ─────────────────────────────────────────────────────

// contextoGrafo es lo que abrirGrafo saca del estado compartido antes de
// soltar el candado: leer el código y serializarlo es lento y no se hace con
// el mutex tomado.
type contextoGrafo struct {
	raiz      string
	repoRoot  string
	nombre    string
	payload   *panelPayload
	proyectos []codegraph.Proyecto
}

// abrirGrafo construye el explorador de UN proyecto (nunca mezcla sistemas)
// e incluye la lista de los demás para poder cambiar de contexto.
func (e *escritorio) abrirGrafo(raiz string) {
	c := e.contextoDelGrafo(raiz)
	go func() {
		// Store y apertura bajo el mismo candado: quien sale último de aquí
		// deja SU grafo servido y SU apertura encolada la última, así que la
		// ventana que sobrevive lee los datos de su propio pedido.
		e.grafoMu.Lock()
		defer e.grafoMu.Unlock()
		e.prepararGrafo(c)
		application.InvokeAsync(e.abrirVentanaExplorador)
	}()
}

func (e *escritorio) contextoDelGrafo(raiz string) contextoGrafo {
	e.mu.Lock()
	// Copia: el contexto se lo lleva otra goroutine a leer y a serializar,
	// y el del mapa lo sigue reescribiendo el escritorio.
	c := contextoGrafo{raiz: raiz, payload: paraPublicar(e.porProyecto[raiz])}
	for r, p := range e.porProyecto {
		c.proyectos = append(c.proyectos, codegraph.Proyecto{
			Nombre: p.Repo, Root: r, Activo: r == raiz, Estado: p.Verdict,
		})
	}
	e.mu.Unlock()
	sort.Slice(c.proyectos, func(i, j int) bool { return c.proyectos[i].Nombre < c.proyectos[j].Nombre })
	c.repoRoot = filepath.FromSlash(raiz)
	c.nombre = filepath.Base(c.repoRoot)
	if c.payload != nil {
		c.nombre = c.payload.Repo
	}
	return c
}

// prepararGrafo deja el grafo servido en /graph.json. La ventana se abre
// SIEMPRE, pase lo que pase aquí: antes, cualquiera de estos fallos hacía que
// el botón no hiciera absolutamente nada — sin ventana, sin mensaje, sólo una
// línea en un log que nadie mira.
func (e *escritorio) prepararGrafo(c contextoGrafo) {
	cg, err := codegraph.Build(c.repoRoot)
	var motivo string
	switch {
	case err != nil:
		motivo = "No pude leer el código de este proyecto: " + err.Error()
	case cg == nil || len(cg.Nodes) == 0:
		motivo = "No encontré funciones que mapear en " + c.nombre + ".\n\n" +
			"El explorador entiende Go y TypeScript/JavaScript, estén donde estén " +
			"en el repo. Si este proyecto usa otro lenguaje, todavía no está cubierto."
	}
	if motivo != "" {
		log.Printf("grafo de %s no disponible: %s", c.nombre, strings.SplitN(motivo, "\n", 2)[0])
		cg = &codegraph.Graph{Root: c.raiz, Error: motivo}
	} else if c.payload != nil {
		// Sin análisis previo no hay hallazgos que superponer, pero el
		// mapa del código se puede ver igual.
		cg.Overlay = buildOverlay(cg, c.payload)
	}
	cg.Proyectos = c.proyectos
	data, err := json.Marshal(cg)
	if err != nil {
		log.Println("grafo: no se pudo serializar:", err)
		data = []byte(`{"nodes":[],"edges":[],"error":"no se pudo preparar el grafo"}`)
	}
	e.grafoJSON.Store(data)
	if motivo == "" {
		log.Printf("grafo de %s: %d nodos, %d aristas (%d KB servidos en /graph.json)",
			c.nombre, len(cg.Nodes), len(cg.Edges), len(data)/1024)
	}
}

func (e *escritorio) abrirVentanaExplorador() {
	if e.explorador != nil {
		e.explorador.Close()
		e.explorador = nil
	}
	w, h := e.tamanoQueQuepa(1280, 820)
	e.explorador = e.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "CodeGuard — explorador de código",
		Width:            w,
		Height:           h,
		URL:              "/explorer.html",
		BackgroundColour: application.RGBA{Red: 11, Green: 14, Blue: 17, Alpha: 255},
	})
	e.explorador.Center()
	e.explorador.Show()
}

// alPedirHistorial responde a la pestaña de historial del panel.
//
// Se sirve BAJO DEMANDA y no dentro del payload de cada análisis: la consulta
// abre la base y recorre corridas, y pagarlo en el camino del commit —que es el
// único momento en que el desarrollador está esperando— para un dato que casi
// nunca se mira sería cobrarle a todos por lo que usa uno.
func (e *escritorio) alPedirHistorial(raiz string) {
	if raiz == "" {
		if p := e.activoActual(); p != nil {
			raiz = p.RepoRoot
		}
	}
	h := struct {
		RepoRoot string          `json:"repo_root"`
		Error    string          `json:"error,omitempty"`
		Datos    store.Historial `json:"datos"`
	}{RepoRoot: raiz}

	// El error viaja hasta la pantalla en vez de morir en el log. Una pestaña
	// que se queda en blanco se lee como "no hay nada", que es justo la
	// confusión que este panel existe para deshacer.
	st, err := store.Open(store.DefaultPath())
	if err != nil || st == nil {
		h.Error = "no pude abrir la base de datos del agente"
		e.emitirEvento("historial", h)
		return
	}
	defer st.Close()
	datos, err := st.Historial(repoIDDe(raiz), 20)
	if err != nil {
		h.Error = "no pude leer el historial: " + err.Error()
	}
	h.Datos = datos
	e.emitirEvento("historial", h)
}

// repoIDDe calcula la misma clave con la que la CLI guardó las corridas. Si no
// coincidiera, el historial saldría vacío sobre una base llena.
