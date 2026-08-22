package main

import (
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/codegraph"
	"codeguard/internal/registry"
)

// 300x180 aloja el orbe de 84 px anclado abajo-derecha más la burbuja, que
// crece hacia arriba y a la izquierda. Si cambia el tamaño del orbe en
// widget.html, esto no necesita cambiar: el orbe se ancla solo.
const widgetW, widgetH = 300, 180

// escritorio agrupa lo que antes vivía suelto dentro de main(): las ventanas,
// el contexto de cada proyecto y lo que el orbe muestra. Todo ese estado
// estaba atrapado en cierres de una sola función de 744 líneas, y por eso no
// había forma de probar nada —ni el sembrado del panel al reiniciar— sin
// arrancar Wails y mirar la pantalla. Aquí es estado con nombre y con métodos.
type escritorio struct {
	app *application.App
	// Sin ventana principal: el panel y la burbuja son las únicas ventanas
	// permanentes. Una ventana oculta extra costaba un renderer de WebView2
	// (~60 MB). Las otras tres nacen y mueren con su botón.
	panel         *application.WebviewWindow
	widget        *application.WebviewWindow
	explorador    *application.WebviewWindow
	ventanaConfig *application.WebviewWindow
	guia          *application.WebviewWindow
	tray          *trayState

	// ── Contexto POR PROYECTO ──────────────────────────────────────────────
	// Cada repo mantiene su propio estado y su propia historia. El orbe
	// refleja SIEMPRE el proyecto del último análisis — un bloqueo en el
	// repo A jamás secuestra el verde del repo B. Los demás proyectos se
	// listan en el panel para poder cambiar de contexto, nada más.
	//
	// Los tres campos de abajo son UN SOLO invariante, no tres cosas sueltas,
	// y lo tocan a la vez el servidor IPC —que atiende cada conexión en su
	// propia goroutine—, los manejadores de eventos de Wails y las goroutines
	// que este mismo archivo lanza para serializar el grafo. Dos reglas, y
	// las dos son de las que si se rompen no avisan:
	//
	//  1. e.mu cubre el invariante COMPLETO, no un campo. Antes cubría sólo
	//     porProyecto y activo quedaba al aire: un análisis recién terminado
	//     podía perderse entero porque sembrarDesdeRegistro comprobaba activo
	//     y lo escribía después, con todo el cálculo de la lista en medio.
	//  2. Un payload PUBLICADO no se muta jamás. Lo que sale de aquí hacia el
	//     bus de eventos o hacia otra goroutine es una copia de la que el
	//     receptor es dueño; los objetos de porProyecto y activo son del
	//     escritorio y sólo cambian con e.mu tomado. Antes se entregaba el
	//     puntero del mapa y luego se le reescribía OtrosRepos por debajo,
	//     mientras Wails o el explorador lo estaban serializando.
	//
	// Y cada operación es UNA sola sección crítica. Partirla en dos deja al
	// mapa y al activo contándose historias distintas en el hueco.
	mu          sync.Mutex
	porProyecto map[string]*panelPayload // contexto de cada proyecto
	activo      *panelPayload            // contexto activo (el último analizado)

	// raizConfig es la raíz desde la que se lee la configuración del modelo.
	// Se actualiza con cada análisis; sin ninguno todavía, sirve cualquier
	// repo enrolado —la configuración del modelo suele ser la misma para todos.
	raizConfig atomic.Value // string
	// El grafo puede pesar cientos de KB: viaja por HTTP interno, no por el
	// bus de eventos (ahí llegaba vacío). El explorador hace fetch("/graph.json").
	grafoJSON atomic.Value // []byte
	// grafoMu hace indivisible el par "servir el grafo + abrir la ventana".
	// Sin él, dos peticiones casi a la vez (panel y CLI, p.ej.) cruzaban el
	// Store de /graph.json con la apertura: la ventana del pedido A podía
	// acabar pintando el grafo del pedido B sin ningún aviso. Como sólo hay
	// UNA ventana de explorador, la regla es "el último pedido gana entero":
	// su grafo y su ventana, nunca la mezcla.
	grafoMu sync.Mutex
	// grafoPendiente es el grafo que el explorador recibiría por el bus en
	// cuanto avisa que cargó. Desde que el grafo viaja por HTTP nadie lo
	// llena, y el manejador de explorer-ready no encuentra nada que mandar.
	grafoPendiente *codegraph.Graph

	// Redimensionar un WebView en cada apertura causa lag: el panel solo se
	// acomoda cuando el área de trabajo cambió (otro monitor, taskbar movida).
	ultimoAnclaje struct{ w, h int }

	// cargarRepos y olvidarRepo son la puerta al registro de proyectos de la
	// máquina. Son campos y no llamadas directas a registry porque el sembrado
	// del panel es justo la lógica que se rompió en producción y hay que poder
	// ejercitarla en una prueba sin tocar el registro real del usuario.
	cargarRepos func() []registry.Repo
	olvidarRepo func(raiz string)

	// emitir manda un evento al frontend. Es un campo por la misma razón que
	// los dos de arriba: publicar el contexto activo es la lógica que se rompió
	// al enrolar un repo con el agente ya corriendo, y ejercitarla exigía
	// arrancar Wails entero. En producción se queda en nil y emitirEvento pasa
	// por el bus de la aplicación; sólo las pruebas lo llenan.
	emitir func(nombre string, datos any)

	// enCurso es el análisis que corre AHORA: el marcador que el orbe enseña en
	// vivo y el vigilante que corta un «revisando» que no vuelve. Ver progreso.go.
	enCurso analisisEnCurso
	// plazoVigilante lo acortan las pruebas para no esperar los segundos de
	// producción; en cero se calcula del plazo que manda el hook.
	plazoVigilante time.Duration

	// abrirPanel muestra la ventana. Mismo motivo que emitir: tocar la ventana
	// exige el hilo de la UI de Wails (application.InvokeAsync), y eso panica
	// sin una aplicación viva — así que la lógica de CUÁNDO abrir no se podía
	// probar sin arrancar Wails entero. En producción se queda en nil.
	abrirPanel func()

	// apagar termina la aplicación POR EL CAMINO BUENO — el mismo que el botón
	// «Salir de CodeGuard» del menú. Mismo patrón inyectable que los de arriba.
	//
	// Existe porque el desinstalador no tenía forma de pedirlo: mataba el
	// proceso con Stop-Process -Force, y un proceso fusilado no llega a quitar
	// su icono de la bandeja. Windows deja el icono pintado —el famoso orbe
	// fantasma— hasta que algo refresca el área de notificación, y en la
	// bandeja nueva de Windows 11 no hay forma programática decente de
	// refrescarla sin reiniciar Explorer. La única salida limpia es no matar:
	// pedir. app.Quit() desmonta la bandeja antes de morir.
	apagar func()
}

// nuevoEscritorio deja el estado listo ANTES de que exista la aplicación: el
// manejador HTTP se construye desde aquí y Wails lo pide al crearse.
func nuevoEscritorio() *escritorio {
	e := &escritorio{
		porProyecto: map[string]*panelPayload{},
		cargarRepos: registry.Load,
		olvidarRepo: func(raiz string) { go registry.Remove(raiz) },
	}
	e.grafoJSON.Store([]byte(`{"nodes":[],"edges":[]}`))
	// Proyectos enrolados en la máquina (desde `codeguard init`), aunque aún
	// no hayan commiteado: aparecen en la lista desde el primer día.
	e.mu.Lock()
	e.altaDeProyectosEnroladosLocked()
	e.mu.Unlock()
	return e
}

// ── Servidor interno ─────────────────────────────────────────────────────────

// manejadorHTTP monta lo que sirve la aplicación: los assets embebidos y las
// dos rutas propias.
func (e *escritorio) manejadorHTTP() http.Handler {
	frontend, err := fs.Sub(assets, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	assetsFS := application.BundledAssetFileServer(frontend)
	handler := http.NewServeMux()
	handler.HandleFunc("/graph.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(e.grafoJSON.Load().([]byte))
	})
	// Igual que el grafo: la configuración se sirve por HTTP y no por eventos.
	// Pero NO tal cual: sale sólo la lista blanca de configLLMServida —la ventana
	// necesita saber QUE hay clave, no su valor, que no sale del Administrador de
	// credenciales— y si no se puede serializar, no se sirve: fail-closed.
	//
	// Y NO es «cualquier proceso local con un GET», como decía aquí antes: este mux
	// se monta como AssetOptions.Handler de Wails (main.go:517), o sea que lo sirve
	// el canal de assets de la WebView2 y no un socket. MEDIDO: el daemon no tiene
	// ningún puerto TCP en escucha, así que desde fuera no hay GET posible. Quien lo
	// lee es lo que corra DENTRO de la webview, y por eso la lista blanca sigue
	// valiendo: el día que el panel cargue algo de terceros, o que un asset se
	// cuele, el JSON no puede llevar más de lo que se decidió exponer.
	handler.HandleFunc("/config-llm.json", func(w http.ResponseWriter, r *http.Request) {
		raiz, _ := e.raizConfig.Load().(string)
		if raiz == "" {
			if repos := e.cargarRepos(); len(repos) > 0 {
				raiz = repos[0].Root
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		data, err := configLLMParaServir(leerConfigLLM(filepath.FromSlash(raiz)))
		if err != nil {
			log.Println("config-llm: no se pudo enmascarar la configuración:", err)
			http.Error(w, "no se pudo servir la configuración", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})
	handler.Handle("/", assetsFS)
	return handler
}

// claveEnmascarada es el centinela que el camino de guardado reconoce como «la
// clave no se tocó» (ver guardarLLMLocal). /config-llm.json ya no sirve ningún
// campo de credencial —ni tapado—, así que la constante queda por dos motivos: un
// formulario ya abierto que la devuelva no debe pisar la clave guardada, y el
// contrato de guardarLLMLocal no se toca.
const claveEnmascarada = "__codeguard_guardada__"

// configLLMServida es la lista BLANCA de lo que /config-llm.json expone: sólo
// estos campos, copiados a mano desde estadoConfigLLM.
//
// Sustituye a la lista NEGRA anterior, que tapaba todo campo cuyo nombre oliera a
// credencial ("key", "token", "secret"...). Esa lista protegía al revés de como se
// rompe: el día que estadoConfigLLM gane un campo sensible con un nombre fuera de
// la lista —"cabecera", "firma", "certificado"— saldría en claro sin que nadie lo
// notara.
//
// Y ADEMÁS la lista negra tenía un daño ya activo: "api_key_env" contiene "key",
// así que el NOMBRE de la variable de entorno se servía tapado. config.html:184
// llena con él el campo del formulario y lo devuelve al guardar (línea 209), de
// modo que guardarLLMLocal acababa guardando la clave bajo la variable
// "__codeguard_guardada__" y la capa de consejo se quedaba buscando una variable
// que no existe. El nombre de una variable no es una credencial; el valor, que sí
// lo es, nunca ha estado en este struct — vive en el Administrador de credenciales
// y aquí sólo viaja QUE existe (HayKey).
//
// Con la lista blanca el modo de fallo se invierte: un campo nuevo NO aparece en
