package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/store"
)

// registrarEventos conecta el bus de la aplicación con el escritorio. Son
// catorce manejadores y todos son cableado: cada uno delega en un método.
func (e *escritorio) registrarEventos() {
	e.registrarEventosPanel()
	e.registrarEventosVentanas()
	e.registrarEventosModelo()
}

// zonaDelEvento traduce lo que manda la página —su caja en píxeles CSS más el
// factor de escala— a píxeles físicos, que es en lo que habla SetWindowRgn.
//
// La escala la manda la página (devicePixelRatio) en vez de preguntarla aquí:
// es la misma que usó para medirse, así que no puede desincronizarse. En un
// monitor al 150% eso es la diferencia entre recortar donde está el orbe y
// recortar a dos tercios de camino.
func zonaDelEvento(ev *application.CustomEvent) (string, []Rect) {
	if ev == nil || ev.Data == nil {
		return "", nil
	}
	raw, err := json.Marshal(ev.Data)
	if err != nil {
		return "", nil
	}
	var msg struct {
		Ventana string  `json:"ventana"`
		Escala  float64 `json:"escala"`
		Zonas   []struct {
			X, Y, W, H, Radio float64
		} `json:"zonas"`
	}
	if json.Unmarshal(raw, &msg) != nil || msg.Ventana == "" {
		return "", nil
	}
	if msg.Escala <= 0 {
		msg.Escala = 1
	}
	px := func(v float64) int { return int(v*msg.Escala + 0.5) }
	zonas := make([]Rect, 0, len(msg.Zonas))
	for _, z := range msg.Zonas {
		zonas = append(zonas, Rect{
			X: px(z.X), Y: px(z.Y), W: px(z.W), H: px(z.H), Radio: px(z.Radio),
		})
	}
	return msg.Ventana, zonas
}

func (e *escritorio) registrarEventosPanel() {
	// Clic en la burbuja: alterna el panel (cierre con animación de plegado).
	e.app.Event.On("widget-click", func(*application.CustomEvent) {
		application.InvokeAsync(e.alternarPanel)
	})
	// La burbuja pide su estado al cargar.
	e.app.Event.On("widget-ready", func(*application.CustomEvent) {})
	// Cada ventana transparente dice dónde acabó su contenido, y la ventana se
	// recorta a esa forma. Sin esto, el aire que rodea al orbe y la mitad vacía
	// del panel se comen los clics de esa zona de la pantalla.
	e.app.Event.On("zona-activa", func(ev *application.CustomEvent) {
		titulo, zonas := zonaDelEvento(ev)
		if titulo == "" {
			return
		}
		application.InvokeAsync(func() { RecortarA(titulo, zonas) })
	})
	e.app.Event.On("panel-close", func(*application.CustomEvent) {
		application.InvokeAsync(func() {
			if e.panel != nil {
				e.panel.Hide()
			}
		})
	})
	// Feedback del panel → tabla feedback (etapa 9). En su propia goroutine,
	// por el mismo motivo que pedir-historial: abre la base y escribe, y el
	// hilo del bus de eventos no puede quedarse esperando a un disco.
	e.app.Event.On("feedback", func(ev *application.CustomEvent) {
		go guardarFeedback(ev)
	})
	// La pestaña de historial pide sus datos al abrirse. Va en su propia
	// goroutine: abre la base y consulta, y el hilo de la UI no puede quedarse
	// esperando a un disco.
	e.app.Event.On("pedir-historial", func(ev *application.CustomEvent) {
		var raiz string
		if rs := rootsDelEvento(ev); len(rs) > 0 {
			raiz = rs[0]
		}
		go e.alPedirHistorial(raiz)
	})
	// El panel pide el contexto activo al abrirse.
	e.app.Event.On("panel-ready", func(*application.CustomEvent) {
		e.mostrarContextoActivo()
	})
	// Cambio de contexto: el panel pide ver otro proyecto. Cada uno conserva
	// su propio análisis; cambiar de contexto no altera el estado de nadie.
	e.app.Event.On("switch-repo", func(ev *application.CustomEvent) {
		raw, _ := json.Marshal(ev.Data)
		var roots []string
		if json.Unmarshal(raw, &roots) != nil || len(roots) == 0 {
			var one string
			if json.Unmarshal(raw, &one) == nil {
				roots = []string{one}
			}
		}
		if len(roots) == 0 {
			return
		}
		e.cambiarDeProyecto(roots[0])
	})
}

func (e *escritorio) registrarEventosVentanas() {
	// La página avisa cuando cargó; recién entonces se le manda el grafo.
	e.app.Event.On("explorer-ready", func(*application.CustomEvent) {
		if e.grafoPendiente != nil {
			e.app.Event.Emit("graph-data", e.grafoPendiente)
		}
	})
	// Botón 🕸: el explorador de código en su PROPIA ventana del agente
	// (nada de navegador) con el análisis proyectado encima.
	e.app.Event.On("open-graph", func(ev *application.CustomEvent) {
		// El panel manda la raíz del proyecto que se está viendo. Sin ella
		// —p.ej. desde el menú de la bandeja— se cae al último analizado.
		if roots := rootsDelEvento(ev); len(roots) > 0 && roots[0] != "" {
			e.abrirGrafo(roots[0])
			return
		}
		p := e.activoActual()
		if p == nil {
			log.Println("grafo: aún no hay proyecto activo")
			return
		}
		e.abrirGrafo(p.RepoRoot)
	})
	// El explorador pide cambiar al grafo de otro proyecto.
	e.app.Event.On("graph-switch", func(ev *application.CustomEvent) {
		if roots := rootsDelEvento(ev); len(roots) > 0 {
			e.abrirGrafo(roots[0])
		}
	})
	e.app.Event.On("open-config", func(*application.CustomEvent) {
		application.InvokeAsync(e.abrirConfig)
	})
	e.app.Event.On("open-guide", func(*application.CustomEvent) {
		application.InvokeAsync(e.abrirGuia)
	})
}

func (e *escritorio) registrarEventosModelo() {
	e.app.Event.On("llm-probar", func(ev *application.CustomEvent) {
		g, err := decodificarConfigLLM(ev)
		if err != nil {
			e.responderConfig(false, "no entendí el formulario: "+err.Error(), false)
			return
		}
		go func() {
			detalle, err := probarConfigLLM(g)
			if err != nil {
				e.responderConfig(false, "<b>No respondió.</b><br><code>"+escaparHTML(err.Error())+"</code>", false)
				return
			}
			e.responderConfig(true, "<b>Conexión correcta.</b> "+escaparHTML(detalle), false)
		}()
	})
	e.app.Event.On("llm-guardar", func(ev *application.CustomEvent) {
		g, err := decodificarConfigLLM(ev)
		if err != nil {
			e.responderConfig(false, "no entendí el formulario: "+err.Error(), false)
			return
		}
		if err := guardarLLMLocal(g); err != nil {
			e.responderConfig(false, "<b>No se pudo guardar.</b><br><code>"+escaparHTML(err.Error())+"</code>", false)
			return
		}
		if g.Restaurar {
			log.Println("configuración del modelo: se restauró la del equipo")
			e.responderConfig(true, "<b>Listo.</b> Vuelves a usar la configuración del equipo.", true)
			return
		}
		log.Printf("configuración del modelo: %s · %s (local)", g.Provider, g.Model)
		e.responderConfig(true, "<b>Guardado.</b> Se aplica desde el próximo commit.", true)
	})
}

func (e *escritorio) responderConfig(bien bool, mensaje string, recargar bool) {
	e.app.Event.Emit("llm-resultado", map[string]any{
		"bien": bien, "mensaje": mensaje, "recargar": recargar,
	})
}

// guardarFeedback lleva el pulgar arriba/abajo del panel a la tabla feedback.
func guardarFeedback(ev *application.CustomEvent) {
	raw, _ := json.Marshal(ev.Data)
	var items []struct {
		FindingID string `json:"finding_id"`
		Verdict   string `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		log.Println("feedback ilegible:", err)
		return
	}
	st, err := store.Open(store.DefaultPath())
	if err != nil {
		log.Println("feedback: no se pudo abrir la BD:", err)
		return
	}
	defer st.Close()
	for _, it := range items {
		if err := st.SaveFeedback(it.FindingID, it.Verdict, ""); err != nil {
			log.Println("feedback:", err)
		}
	}
}

// ── Contexto de los proyectos ────────────────────────────────────────────────

// altaDeProyectosEnroladosLocked añade al mapa los proyectos del registro que
// aún no estén, con su estado placeholder. Exige e.mu tomado.
func (e *escritorio) altaDeProyectosEnroladosLocked() {
	for _, r := range e.cargarRepos() {
		root := filepath.ToSlash(r.Root)
		if _, ya := e.porProyecto[root]; !ya {
			// El stack y las capas se saben SIN analizar nada: el stack está
			// escrito en el config desde el `init` y las capas salen de
			// preguntarle a cada motor por el árbol. Sin esto, la ficha nacía
			// con la cabecera vacía y el dev que acababa de instalar veía un
			// producto que no sabía nada de su repo, justo después de que
			// `init` le hubiera dicho por pantalla qué stack había detectado.
			// Es lo primero que se mira y era lo último que se rellenaba.
			//
			// config.Load devolviendo error no es un fallo: es el repo de quien
			// corrió `install` y todavía no `init`. Ahí no hay stack que
			// enseñar y no se inventa ninguno.
			var langs, capasDelRepo []string
			if cfg, err := config.Load(filepath.FromSlash(root)); err == nil && cfg != nil {
				langs = cfg.Languages
				capasDelRepo = daemon.CapasDelRepoEn(cfg, filepath.FromSlash(root))
			}
			e.porProyecto[root] = &panelPayload{
				Repo: r.Nombre, RepoRoot: root, Verdict: "—", At: "sin análisis",
				Languages: langs, CapasRepo: capasDelRepo,
				// CIParity en true a propósito: el panel enseña el aviso de
				// paridad cuando es false, y el cero de Go es false. Sin esta
				// línea, un proyecto que NUNCA se ha analizado aparecía
				// afirmando "tu rulepack no coincide — no puedo garantizar que
				// pase el CI", que es una acusación inventada sobre un repo
				// perfectamente sano. Pasó con portal-cliente en cuanto se sembró
				// el panel desde el registro (1.3.0). La paridad sólo se puede
				// romper cuando un análisis la comprueba; mientras no lo haya,
				// no hay nada que avisar.
				CIParity: true,
			}
		}
	}
}

// listaProyectos: TODOS los proyectos con su estado (incluido el activo),
// para que de un vistazo se vea cuál está en verde y cuál bloqueado.
func (e *escritorio) listaProyectos(raizActiva string) []proyectoEnLista {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.listaProyectosLocked(raizActiva)
}

// listaProyectosLocked es la lista de verdad, y exige e.mu tomado.
//
// Existe separada de listaProyectos porque sync.Mutex no es reentrante: quien
// necesitaba la lista dentro de su propia sección crítica no podía llamar a la
// versión que toma el candado, así que soltaba el suyo antes y publicaba
// después. En ese hueco es donde se colaban las dos carreras que este archivo
// tenía. Con las dos capas separadas, toda publicación cabe en un solo Lock.
func (e *escritorio) listaProyectosLocked(raizActiva string) []proyectoEnLista {
	// El registro se relee AQUÍ, no sólo al arrancar. `codeguard init`
	// escribe en repos.json el proyecto recién enrolado, pero el daemon ya
	// estaba corriendo con su copia en memoria: el repo no aparecía en el
	// panel hasta el primer commit, contradiciendo lo que init promete al
	// terminar ("aparece en el panel sin esperar al primer commit"). Pasó
	// al enrolar portal-cliente.
	e.altaDeProyectosEnroladosLocked()
	var out []proyectoEnLista
	for root, p := range e.porProyecto {
		// Un proyecto cuya carpeta ya no existe no es un proyecto. El
		// daemon añade a porProyecto cada repo que analiza y antes no lo
		// quitaba nunca: un repo borrado seguía en el panel hasta
		// reiniciar el agente. Se olvida aquí y también del registro.
		if _, err := os.Stat(filepath.FromSlash(root)); err != nil {
			delete(e.porProyecto, root)
			e.olvidarRepo(root)
			continue
		}
		out = append(out, proyectoEnLista{
			Marca:    marcaProyecto(p),
			Nombre:   p.Repo,
			Ruta:     root,
			Activo:   root == raizActiva,
			Verdict:  p.Verdict,
			Blocking: p.Blocking,
			Advisory: p.Advisory,
			Cuando:   p.At,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nombre < out[j].Nombre })
	return out
}

// marcaProyecto es el semáforo que el panel pinta junto al nombre del repo.
//
// El ✓ no es un adorno: el panel lo rotula «limpio — el último commit pasó todas
// las compuertas». Sobre un análisis OMITIDO no pasó ninguna, así que el salto se
// va al ○, que es la marca que no afirma nada. Es el mismo ✓ falso del orbe en
// pequeño, y llegaba al sitio donde se mira de reojo el estado de los demás
// proyectos.
//
// Una degradación real SÍ conserva su ✓ y es a propósito: ahí el análisis corrió
// y lo que corrió pasó. El agujero de cobertura se cuenta donde hay sitio para
// decirlo con precisión —el orbe se pone en piedra y el panel escribe «No se
// revisó: …» a partir de p.degraded—, no apretándolo en un glifo que el panel
// rotula «sin analizar todavía» y que sería una inexactitud nueva.
//
// Las tres marcas son las que el panel sabe nombrar con palabras (index.html);
