package main

import (
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/shadow"
	"codeguard/internal/store"
)

func repoIDDe(raiz string) string {
	nativa := filepath.FromSlash(raiz)
	salida, err := gitCmdDaemon(nativa, "config", "--get", "remote.origin.url").Output()
	remoto := strings.TrimSpace(string(salida))
	if err != nil {
		remoto = ""
	}
	// La regla vive en store.RepoIDDe y no aquí: era una de las cinco copias
	// del mismo cálculo, y de las cinco sólo dos tenían el respaldo para los
	// repos sin remote. Que este archivo la tuviera bien no salvaba a los otros.
	return store.RepoIDDe(nativa, remoto)
}

// comandoDaemon arma CUALQUIER proceso hijo del daemon. Es el único sitio de
// cmd/daemon donde se llama a exec.Command, y TestNingunHijoDelDaemonSeArmaAMano
// es lo que lo mantiene así.
//
// Existe por la ventana de consola. El daemon se compila con -H windowsgui
// (dist/build-dist.ps1), o sea que no tiene consola propia; cuando un proceso
// sin consola lanza un ejecutable de consola, Windows le REGALA una nueva y
// visible. El desarrollador ve parpadear una ventana negra en la cara. Medido en
// esta máquina con un padre GUI y un hijo que reporta GetConsoleWindow: sin
// atributos, hwnd≠0 y IsWindowVisible=1; con ellos, ni siquiera hay ventana.
//
// Pasó exactamente eso al abrir la pestaña de historial, que llama a git para
// resolver el identificador del repo. Los motores nunca lo sufrieron porque van
// por proc.Correr, que ya oculta la ventana; el descuido fue construir un git al
// margen de ese camino. Por eso aquí se reusa proc.SinVentana y no se inventa
// otro apaño: el helper ya existía, sólo faltaba llamarlo.
//
// El entorno va acotado como el de cualquier otro hijo (ver proc.Entorno): el
// daemon tiene la clave del modelo en el suyo y ninguna utilidad que lance la
// necesita. Quien necesite las GIT_* pide gitCmdDaemon.
func comandoDaemon(nombre string, args ...string) *exec.Cmd {
	c := exec.Command(nombre, args...)
	proc.SinVentana(c)
	c.Env = proc.Entorno()
	return c
}

// gitCmdDaemon es comandoDaemon con el entorno que git necesita. Las GIT_* le
// dicen a git qué índice está mirando, y filtrarlas cambiaría en silencio qué se
// analiza; es la misma razón por la que la CLI tiene su gitCmd.
func gitCmdDaemon(dir string, args ...string) *exec.Cmd {
	c := comandoDaemon("git", append([]string{"-C", dir}, args...)...)
	c.Env = proc.EntornoGit()
	return c
}

// ── Sombra y servidor IPC ────────────────────────────────────────────────────

// arrancarSombra prepara el corredor de la sombra. Sin BD no hay sombra, pero
// el daemon sigue: el análisis determinista no depende de ella.
func (e *escritorio) arrancarSombra() *shadow.Runner {
	shadowStore, err := store.Open(store.DefaultPath())
	if err != nil {
		log.Println("sombra desactivada — no se pudo abrir la BD:", err)
	}
	if shadowStore == nil {
		return nil
	}
	// El razonamiento del modelo se transmite al panel, con acelerador:
	// muchos deltas pequeños → una emisión cada ~350 ms con la cola.
	var thinkMu sync.Mutex
	var thinkBuf string
	var lastEmit time.Time
	return &shadow.Runner{
		Store: shadowStore,
		OnThinking: func(pillar, text string) {
			if pillar == "" && text == "" {
				e.app.Event.Emit("thinking", map[string]string{"pillar": "", "text": ""})
				return
			}
			thinkMu.Lock()
			defer thinkMu.Unlock()
			thinkBuf += text
			if len(thinkBuf) > 140 {
				thinkBuf = thinkBuf[len(thinkBuf)-140:]
			}
			if time.Since(lastEmit) < 350*time.Millisecond {
				return
			}
			lastEmit = time.Now()
			e.app.Event.Emit("thinking", map[string]string{"pillar": pillar, "text": thinkBuf})
		},
	}
}

func (e *escritorio) construirServidorIPC(sombra *shadow.Runner) *daemon.Server {
	return &daemon.Server{
		Shadow:     sombra,
		OnCommand:  e.alComandoDeLaCLI,
		OnRequest:  e.alEmpezarAnalisis,
		OnProgreso: e.alAvanzarAnalisis,
		OnResult:   e.alTerminarAnalisis,
	}
}

// alComandoDeLaCLI atiende las acciones de UI que pide la CLI: el explorador
// abre en la ventana del agente, nunca en un navegador.
func (e *escritorio) alComandoDeLaCLI(cmd string, req *ipc.Request) {
	if req == nil {
		return
	}
	root := req.RepoRoot
	switch cmd {
	// El desinstalador (y sólo él, en la práctica) pide el apagado por IPC en
	// vez de matar el proceso: un daemon fusilado deja su orbe pintado en la
	// bandeja como fantasma. La frontera de confianza no cambia: el pipe es
	// por-usuario, y quien puede hablarle al pipe ya podía hacer taskkill.
	case "apagar":
		if e.apagar != nil {
			e.apagar()
			return
		}
		// Vía el hilo de la UI, como toda operación que toca ventanas. El ack
		// del IPC ya salió: quien pidió el apagado no se queda esperando.
		application.InvokeAsync(func() { e.app.Quit() })
	case "open-graph":
		e.abrirGrafo(filepath.ToSlash(root))
	case "open-config":
		if root != "" {
			e.raizConfig.Store(filepath.ToSlash(root))
		}
		e.emitirEvento("open-config", nil)
	// `codeguard init` acaba de enrolar un repo. Se pone al frente igual que si
	// el usuario lo hubiera elegido en el panel: init promete que el proyecto
	// "aparece en el panel desde el momento del init", y sin este aviso la
	// promesa sólo se cumplía en un daemon que arrancara después —con el agente
	// ya corriendo y otro proyecto en pantalla, el repo no salía nunca.
	case "repo-enrolado":
		if root == "" {
			return
		}
		// Enrolar un repo es una acción del usuario que hasta ahora no producía
		// NINGUNA señal visible: `codeguard init` decía "LISTO" y el agente se
		// quedaba callado, así que no había forma de saber si había funcionado.
		//
		// Se abre el panel a propósito, y no sólo se cambia el contexto: es el
		// único momento en que el usuario acaba de pedir algo y espera verlo.
		// El resto del tiempo el panel se abre solo cuando hay un bloqueo
		// (ui.auto_open_panel: on_block), y eso no cambia.
		// Se abre con mostrarPanel y NO emitiendo "panel-show" a secas: el panel
		// nace Hidden y lo único que lo muestra es panel.Show(). Emitir el evento
		// suelto no sólo no abría nada — el JS de la burbuja pone
		// panelAbierto=true al recibirlo, y con esa bandera el susurro y el
		// tooltip del orbe dejan de responder: el agente se quedaba MUDO hasta
		// que el usuario abría y cerraba el panel a mano. Vía InvokeAsync porque
		// esto llega desde la goroutine del IPC y toca la ventana.
		raiz := filepath.ToSlash(root)
		e.cambiarDeProyecto(raiz)
		cfg, _ := config.Load(raiz)
		e.pedirPanel(cfg)
	// La etapa 1 frenó una credencial. Es el evento que justifica el producto y
	// era el ÚNICO que la interfaz no contaba: la compuerta de secretos corre
	// DENTRO del proceso del gancho —tiene que ser así, es fail-closed y no
	// puede depender de que el daemon esté vivo— y salía por os.Exit mucho antes
	// de la primera llamada al daemon. El commit quedaba bloqueado, la terminal
	// lo decía, y el orbe seguía en verde.
	//
	// Lo que llega es un NÚMERO, nunca los hallazgos: son ellos los que
	// contienen la credencial, y abrir un camino nuevo por el que salga sería lo
	// contrario de lo que este producto hace. El detalle está en la base —el
	// gancho lo persiste antes de salir— y se lee en la pestaña Historial.
	case "secreto-bloqueado":
		if root == "" || req.SecretosBloqueados <= 0 {
			return
		}
		raizSecreto := filepath.ToSlash(root)
		p := &panelPayload{
			Repo:     filepath.Base(raizSecreto),
			RepoRoot: raizSecreto,
			Branch:   req.Branch,
			Verdict:  "block",
			// El bloqueo por secreto es un Bloqueado de libro: la etapa 1 miró
			// y frenó. Se dice en el vocabulario tipado como en el legacy.
			Outcome:  string(pipeline.Bloqueado),
			Blocking: req.SecretosBloqueados,
			Reason: plural(req.SecretosBloqueados,
				"se frenó 1 secreto antes de que entrara al repositorio",
				"se frenaron %d secretos antes de que entraran al repositorio") +
				" — rota la credencial primero: borrarla del historial no la invalida. " +
				"El detalle está en Historial y en la terminal donde commiteaste.",
			// CIParity en true: la paridad no se comprobó en este camino, y un
			// false pintaría el aviso de "puede pasar aquí y fallar allá", que
			// sería una acusación inventada encima del bloqueo real.
			CIParity:   true,
			SecretosEn: req.SecretosEn,
			Findings:   hallazgosDeSecreto(req.SecretosEn),
			MaxShow:    len(req.SecretosEn),
			At:         time.Now().Format("15:04"),
		}
		// Por el MISMO camino que un análisis terminado: registrar, pintar el
		// orbe y publicar. Un camino paralelo acabaría discrepando —el orbe
		// diciendo una cosa y la lista de proyectos otra— y eso es justo lo que
		// este archivo lleva todo el día arreglando.
		payload := e.registrarAnalisis(p)
		e.actualizarOrbe(payload)
		e.emitirEvento("analysis", payload)
		cfgSecreto, _ := config.Load(filepath.FromSlash(raizSecreto))
		e.pedirPanel(cfgSecreto)
	default:
		log.Println("comando desconocido desde la CLI:", cmd)
	}
}

// hallazgosDeSecreto convierte los sitios ("archivo:línea") en hallazgos que el
// panel pinta con SU tarjeta de siempre.
//
// Se construyen aquí y no se inventa una sección propia en el HTML porque el
// panel ya tiene un componente para esto —con su pilar, su severidad, su ruta
// copiable y su "cómo arreglarlo"—, y un bloque hecho a mano al lado se ve como
// lo que sería: un remiendo. La compuerta de secretos no pasa por el pipeline y
// por eso no traía hallazgos; el arreglo es dárselos, no pintarlos distinto.
//
// SIN Snippet, y es la línea que no se puede quitar: el fragmento se construye
// LEYENDO EL ARCHIVO, así que pintaría la credencial en una ventana que se
// comparte por pantalla. El sitio es lo que le falta al dev; el valor ya lo
// tiene abierto en su editor.
func hallazgosDeSecreto(sitios []string) []panelFinding {
	out := make([]panelFinding, 0, len(sitios))
	for _, sitio := range sitios {
		archivo, linea := sitio, 0
		if i := strings.LastIndex(sitio, ":"); i > 0 {
			if n, err := strconv.Atoi(sitio[i+1:]); err == nil {
				archivo, linea = sitio[:i], n
			}
		}
		out = append(out, panelFinding{
			Finding: finding.Finding{
				Engine:   "gitleaks",
				RuleKey:  "secreto-en-el-diff",
				Pillar:   finding.Security,
				Severity: finding.Error,
				Blocking: true,
				File:     archivo,
				Line:     linea,
				Message:  "Secreto detectado en el diff — nada salió a la red",
				Why: "Una credencial en el historial de git la tiene cualquiera con acceso al " +
					"repositorio, y sigue ahí aunque la borres en un commit posterior.",
				FixHint: "Rota la credencial en el proveedor PRIMERO. Borrarla del historial no " +
					"la invalida: quien ya la haya visto la sigue teniendo. Después sácala del " +
					"código y déjala en una variable de entorno o en la bóveda del equipo.",
				Verified: true,
			},
			IsFact: true, // determinista: es un hecho, no una observación del modelo
		})
	}
	return out
}
