// codeguard-daemon — el compañero (§12): daemon con tray y panel lateral.
// Compilar con -ldflags "-H windowsgui" para no abrir consola.
package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"codeguard/internal/capas"
	"codeguard/internal/daemon"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

//go:embed all:frontend
var assets embed.FS

// panelWidth: 660 y no los 480 de antes porque el panel dejó de ser una
// columna. Con la lista de proyectos a la izquierda, mantener 480 habría
// robado ese ancho a las tarjetas de hallazgo —que llevan el código señalado y
// son lo que de verdad se lee—, así que la lista se paga aparte: 170 para el
// carril y los mismos ~490 de contenido que había.
const panelWidth = 660

// panelFinding es lo que pinta el panel: el hallazgo + su código señalado.
type panelFinding struct {
	finding.Finding
	Snippet []snippetLine `json:"snippet"`
	// Tono §12.2: determinista se enuncia como hecho; el LLM (fase 3+) como observación.
	IsFact bool `json:"is_fact"`
}

type snippetLine struct {
	No      int    `json:"no"`
	Text    string `json:"text"`
	Culprit bool   `json:"culprit"`
}

// rootsDelEvento saca las rutas de un evento del frontend. Wails entrega el
// dato como llegó de JavaScript, y las dos formas de Emit del runtime lo
// mandan distinto: una como arreglo, otra como valor suelto.
func rootsDelEvento(e *application.CustomEvent) []string {
	if e == nil || e.Data == nil {
		return nil
	}
	raw, err := json.Marshal(e.Data)
	if err != nil {
		return nil
	}
	var roots []string
	if json.Unmarshal(raw, &roots) == nil && len(roots) > 0 {
		return roots
	}
	var uno string
	if json.Unmarshal(raw, &uno) == nil && uno != "" {
		return []string{uno}
	}
	return nil
}

type panelPayload struct {
	Repo        string `json:"repo"`
	RepoRoot    string `json:"repo_root"`
	Branch      string `json:"branch"`
	AIGenerated bool   `json:"ai_generated"`
	Suppressed  int    `json:"suppressed"`
	// Languages es el stack que CodeGuard detectó en este repo (`languages:`
	// del config). Estaba escrito desde el `init` y el panel no lo enseñaba:
	// el dev no tenía forma de ver qué cree la herramienta que es su proyecto,
	// y de eso cuelga qué motores corren.
	Languages []string `json:"languages,omitempty"`
	// Capas: qué hizo cada motor en el ÚLTIMO ANÁLISIS. Incluye los que NO
	// corrieron, que son los que importa no perder — una lista de sólo los que
	// corrieron afirma que el resto no existe. Ver internal/capas.
	Capas []capas.Capa `json:"capas,omitempty"`
	// CapasRepo son las capas que vigilan ESTE REPO, que es una pregunta
	// distinta de la anterior y no existía.
	//
	// Capas habla del commit; CapasRepo habla del repo. Confundirlas es lo que
	// hacía que un commit que tocaba un README se leyera como "1 capa revisó tu
	// repo" y pareciera que el producto estaba apagado. Se sabe sin analizar
	// nada —basta el árbol y el config— así que está desde el momento en que se
	// enrola, antes del primer commit. Sale de daemon.CapasDelRepo.
	CapasRepo []string `json:"capas_repo,omitempty"`
	// SecretosEn: dónde estaba cada secreto que frenó el commit,
	// "archivo:línea". Sólo se llena en el bloqueo de la etapa 1, que no pasa
	// por el pipeline y por tanto no tiene Findings que enseñar.
	//
	// Llevar el sitio y NO el hallazgo es deliberado: el hallazgo arrastra la
	// línea de código —o sea la credencial— y el panel es una superficie que se
	// comparte por pantalla. Con el archivo y la línea, quien lo lee sabe adónde
	// ir; el valor ya lo tiene delante en su editor.
	SecretosEn []string `json:"secretos_en,omitempty"`
	// TODOS los proyectos enrolados con su estado. Cambiar de contexto desde
	// el panel no altera el estado de nadie.
	//
	// Era una lista de cadenas "marca|nombre|ruta|activo", y el panel las
	// partía por el separador para pintar un botón por repo. Con seis
	// proyectos esos botones se amontonaban y lo único que decían era el
	// semáforo: cuántos problemas tiene cada uno, o si alguno lleva sin
	// analizarse, había que ir repo por repo a averiguarlo.
	OtrosRepos []proyectoEnLista `json:"otros_repos,omitempty"`
	Verdict    string            `json:"verdict"`
	// Reason es POR QUÉ no se analizó, cuando Verdict es "skipped".
	//
	// Ya venía en ipc.Response —el daemon lo rellena y el hook lo imprime— y
	// aquí se tiraba. Sin él las tres superficies de la UI tenían que adivinar:
	// el panel llegó a enumerar de memoria "fue un merge, un revert, o todos los
	// archivos están excluidos", una conjetura escrita a mano sobre un dato que
	// ya estaba cruzando el pipe. Y el orbe no podía distinguir la decisión del
	// equipo de la avería, que es la diferencia entre no alarmar y avisar.
	Reason   string         `json:"reason,omitempty"`
	Blocking int            `json:"blocking"`
	Advisory int            `json:"advisory"`
	CIParity bool           `json:"ci_parity"`
	Degraded []string       `json:"degraded"`
	Findings []panelFinding `json:"findings"`
	// ChangedFiles son las rutas que tocó el commit, tal como llegan en
	// ipc.Request.StagedFiles. Sin ellas el overlay del explorador sólo podía
	// iluminar los archivos CON hallazgos, y un archivo del diff que salió
	// limpio no marcaba su zona: el dato cruzaba el pipe y se tiraba aquí.
	//
	// Viajan SÓLO rutas —ni contenido, ni líneas, ni hashes—: es lo que el
	// overlay necesita y nada de lo que la regla del canal prohíbe. Va vacío en
	// el aviso de secreto bloqueado, que no trae staged (hook.go:384); el
	// overlay lo cubre uniendo los archivos con hallazgos.
	ChangedFiles []string `json:"changed_files,omitempty"`
	MaxShow      int      `json:"max_show"`
	ElapsedMs    int64    `json:"elapsed_ms"`
	At           string   `json:"at"`
}

// proyectoEnLista es una fila de la lista de proyectos del panel.
//
// Lleva el veredicto y los conteos además del semáforo porque la lista existe
// para responder "¿dónde tengo un problema?" de un vistazo, y una marca sola
// no distingue un repo con un bloqueante de uno con nueve.
type proyectoEnLista struct {
	Marca  string `json:"marca"` // ⛔ ✓ ○ — el semáforo que ya rotulaba el panel
	Nombre string `json:"nombre"`
	Ruta   string `json:"ruta"`
	Activo bool   `json:"activo"`
	// Verdict va crudo además de la marca: la marca agrupa (un salto y un repo
	// sin estrenar comparten ○) y el panel necesita poder decirlos distinto.
	Verdict  string `json:"verdict"`
	Blocking int    `json:"blocking"`
	Advisory int    `json:"advisory"`
	// Cuando es la hora del último análisis, o "sin análisis". Un repo que
	// lleva semanas sin revisarse se ve igual de verde que el de hace un
	// minuto si nadie dice cuándo fue.
	Cuando string `json:"cuando"`
}

func snippet(repoRoot, rel string, line int) []snippetLine {
	if line < 1 {
		return nil
	}
	// Confinado al repo: una ruta manipulada en la salida de un escáner no
	// debe poder mostrar archivos de fuera (gosec G304/G703).
	full := filepath.Clean(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	raiz := filepath.Clean(repoRoot)
	if !strings.HasPrefix(full, raiz+string(filepath.Separator)) {
		return nil
	}
	// El prefijo valida la ruta LÉXICA, no su destino, y lo que se acaba
	// abriendo es el destino: un symlink o junction dentro del repo que apunte
	// fuera atraviesa el filtro sin cambiar la ruta, y el fragmento acabaría
	// pintado en un panel que se comparte por pantalla. Se resuelven los dos
	// lados y se repite el chequeo sobre las rutas reales —que además
	// canonicaliza las formas cortas 8.3 de Windows, la misma trampa que ya
	// costó los hallazgos perdidos de mypy—. Si no se pueden resolver, no se
	// abre nada.
	realFull, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil
	}
	realRaiz, err := filepath.EvalSymlinks(raiz)
	if err != nil {
		return nil
	}
	if !strings.HasPrefix(realFull, realRaiz+string(filepath.Separator)) {
		return nil
	}
	f, err := os.Open(realFull)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []snippetLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	no := 0
	for sc.Scan() {
		no++
		if no < line-3 {
			continue
		}
		if no > line+3 {
			break
		}
		out = append(out, snippetLine{No: no, Text: sc.Text(), Culprit: no == line})
	}
	return out
}

// resumenHallazgos describe el resultado en una frase, con los plurales bien.
// Un "0 bloqueantes, 1 avisos" obliga a descifrar dos números y encima está
// mal escrito; esto se entiende sin pensarlo.
func resumenHallazgos(bloqueantes, avisos int) string {
	switch {
	case bloqueantes == 0 && avisos == 0:
		return "sin observaciones"
	case bloqueantes == 0:
		return plural(avisos, "1 sugerencia", "%d sugerencias")
	case avisos == 0:
		return plural(bloqueantes, "1 problema por resolver", "%d problemas por resolver")
	}
	return fmt.Sprintf("%s y %s",
		plural(bloqueantes, "1 problema por resolver", "%d problemas por resolver"),
		plural(avisos, "1 sugerencia", "%d sugerencias"))
}

func plural(n int, uno, varios string) string {
	if n == 1 {
		return uno
	}
	return fmt.Sprintf(varios, n)
}

// orbStateFor traduce el veredicto de UN proyecto al clima del orbe. Es el
// ÚNICO sitio donde se decide ese color: actualizarOrbe también pasa por aquí.
//
// Antes había dos caminos y no coincidían. actualizarOrbe (tras un análisis) sí
// miraba las capas degradadas; esta función (al cambiar de proyecto en el panel)
// no las miraba en absoluto. El mismo commit se veía naranja al terminar y VERDE
// al volver a ese proyecto un minuto después. Un semáforo que cambia de color
// según por dónde lo mires no es un semáforo, así que ahora hay uno solo.
//
// QUÉ SIGNIFICA CADA COLOR, que es de donde sale todo lo de abajo:
//
//	pass (verde)      "lo revisé y está limpio" — la única afirmación fuerte
//	blocked (rojo)    "hay algo que resolver antes de commitear"
//	degraded (piedra) "tu cobertura tiene un agujero: ve a mirar"
//	idle (niebla)     "no tengo nada que reportar" — no afirma nada
//
// Y POR QUÉ UN ANÁLISIS OMITIDO NO ES NINGUNO DE LOS DOS PRIMEROS. Verde es
// falso: el embudo se paró en la etapa 0 y ninguna compuerta llegó a mirar nada,
// que es el mismo ✓ falso que ya se corrigió en el hook. Rojo también sería
// falso: no hay nada que resolver y el commit pasó.
//
// Entre los dos que quedan, la línea NO es "cuánto se revisó" sino DE QUIÉN ES
// LA DECISIÓN, el mismo matiz que el hook ya aplica:
//
//   - Un merge, un revert o unos archivos excluidos en la config son un acuerdo
//     del equipo. Pasan todos los días. Pintarlos de naranja convertiría el
//     naranja en ruido, y entonces no serviría el día que haya una degradación
//     de verdad — este repo ya se ha comido esa lección dos veces (el trivy
//     ausente que pintaba cada commit, el aviso de paridad sin motivo). Van a
//     idle: no se afirma nada, y el tooltip dice qué pasó.
//   - Una config ilegible o un repo sin enrolar es una avería: el análisis no
//     corrió porque NO PUDO, y el usuario tiene que ir a arreglarlo
//     (`codeguard init`, o el YAML roto). Van a degraded, que es exactamente
//     "tu cobertura tiene un agujero".
//
// No se inventa un quinto estado a propósito. La mentira nunca fue el color a
// solas: era el color MÁS el tooltip "sin observaciones". Con idle y un tooltip
// que dice "sin revisar — <motivo>", el significado llega completo; un estado
// nuevo costaría ícono, paleta, CSS del panel y todos los consumidores para
// codificar una distinción que el tooltip ya hace con palabras.
func orbStateFor(p *panelPayload) string {
	switch {
	case p.Verdict == "block":
		return "blocked"
	case p.Verdict == "skipped":
		// Quién decidió el salto lo dice pipeline.EsDecisionDelEquipo, que vive
		// junto a las constantes del motivo y es la MISMA que consulta el hook
		// para elegir el tono de su mensaje. Aquí había una copia del criterio, y
		// el día que se añadiera un motivo nuevo tocando sólo una de las dos, el
		// mismo commit habría salido en tono neutro en la terminal y en naranja de
		// avería en el orbe: un producto contradiciéndose sobre un solo commit es
		// peor que cualquiera de los dos comportamientos por separado. Es la misma
		// razón por la que el color se decide sólo en esta función.
		//
		// Las capas degradadas se comprueban AQUÍ y no allí porque son un dato del
		// payload y no del motivo: el daemon marca "config:unreadable" cuando no
		// puede leer la config, así que un salto que llega con capas caídas es una
		// avería aunque su texto pareciera de los rutinarios.
		//
		// Y ante un motivo que este binario no sepa clasificar —un daemon de otra
		// versión, una etapa 0 nueva— la respuesta es "degraded". La dirección en
		// la que se falla importa: la señal prudente es la que pide mirar, nunca la
		// que tranquiliza.
		if !hayDegradacionReal(p.Degraded) && pipeline.EsDecisionDelEquipo(p.Reason) {
			return "idle"
		}
		return "degraded"
	// Enrolado pero sin analizar todavía (el placeholder del registro, con el
	// daemon recién reiniciado). No hay revisión que enseñar, así que no se
	// afirma ninguna: antes esto caía en el default y pintaba verde un proyecto
	// que nadie había mirado nunca.
	case p.Verdict == "—" || p.Verdict == "":
		return "idle"
	// Una capa que no corrió gana a una sugerencia: la sugerencia es algo que sí
	// se vio, y la capa caída es justo lo que no se pudo ver.
	case hayDegradacionReal(p.Degraded):
		return "degraded"
	case p.Advisory > 0:
		return "idle"
	default:
		return "pass"
	}
}

// hayDegradacionReal separa "una compuerta no pudo mirar" de "una herramienta no
// está instalada". Un motor ausente es un asunto de configuración, no una
// degradación del análisis: un trivy sin instalar no debe pintar de naranja cada
// commit del día.
func hayDegradacionReal(degraded []string) bool {
	return len(degraded) > 0 && !pipeline.SoloFaltantes(degraded)
}

// retardoReset: pass vuelve a idle a los 15 s — con 10 el verde pasaba
// desapercibido.
const retardoReset = 15 * time.Second

// trayState es la máquina de estados del orbe: ícono, etiqueta, tooltip y
// burbuja dicen lo mismo porque todos salen de aquí.
//
// La vuelta de «pass» a idle es una transición de esta máquina, no un efecto
// suelto que corra por su cuenta: la programa cambiar() y la invalida cualquier
// estado posterior. Cuando el timer vivía fuera de la máquina, un bloqueo que
// llegaba dentro de esos 15 s quedaba tapado por el «todo bien» del commit
// anterior — el orbe decía que no pasaba nada con un BLOQUEO activo.
type trayState struct {
	// Se fijan al construir la bandeja y ya no se tocan.
	tray *application.SystemTray
	emit func(state, tooltip string)
	// resetDelay lo acortan las pruebas; en cero rige retardoReset.
	resetDelay time.Duration

	// Lo mutable lo comparten las goroutines de IPC, del menú y del propio
	// timer, así que todo va bajo este candado.
	mu    sync.Mutex
	reset *time.Timer
	// gen numera las transiciones: cada estado nuevo abre la suya y con eso
	// deja sin efecto lo que programó el anterior.
	gen uint64
}

// retardo es lo que espera un pass antes de volver a idle.
func (t *trayState) retardo() time.Duration {
	if t.resetDelay > 0 {
		return t.resetDelay
	}
	return retardoReset
}

// set es el único punto de cambio de estado y, por lo mismo, el dueño del timer
// de reversión: entrar aquí cancela cualquier vuelta a idle pendiente.
func (t *trayState) set(state, tooltip string) {
	t.cambiar(state, tooltip, 0)
}

// setPass deja el verde a la vista un rato y luego vuelve a idle — salvo que
// para entonces ya haya pasado otra cosa, que es lo normal en una racha de
// commits.
func (t *trayState) setPass(tooltip string) {
	t.cambiar("pass", tooltip, t.retardo())
}

// cambiar aplica el estado y, si es transitorio, programa su reversión.
// revertirEn en cero significa que el estado se queda hasta nuevo aviso.
func (t *trayState) cambiar(state, tooltip string, revertirEn time.Duration) {
	t.mu.Lock()
	t.gen++
	gen := t.gen
	// Lo que programó la generación anterior ya no representa la realidad.
	if t.reset != nil {
		t.reset.Stop()
		t.reset = nil
	}
	if revertirEn > 0 {
		t.reset = time.AfterFunc(revertirEn, func() { t.revertirAIdle(gen, tooltip) })
	}
	t.mu.Unlock()
	// Fuera del candado a propósito: los setters de la bandeja son InvokeSync y
	// bloquean hasta que el hilo principal los atiende. Pintar con el candado
	// tomado colgaría la aplicación entera en cuanto algo del hilo principal
	// (un clic del menú) quisiera cambiar de estado.
	t.aplicar(state, tooltip)
}

// revertirAIdle corre en la goroutine del timer. Compara generaciones en vez de
// confiar en el Stop(): cuando el callback ya salió disparado, Stop() devuelve
// false y no alcanza a detenerlo — el contador sí lo deja sin efecto.
func (t *trayState) revertirAIdle(gen uint64, tooltip string) {
	t.mu.Lock()
	if t.gen != gen {
		t.mu.Unlock()
		return // otro estado tomó el relevo; esta reversión llegó tarde
	}
	t.gen++ // la reversión es una transición más, y no deja nada programado
	t.reset = nil
	t.mu.Unlock()
	t.aplicar("idle", tooltip)
}

// aplicar pinta el estado donde el usuario lo ve.
//
// Se auditó por qué corre fuera de mu (dos pintados concurrentes pueden llegar
// a la bandeja en orden distinto al de su generación) y se dejó COMO ESTÁ: el
// propio TestTrayCambiosConcurrentesNoSePierdenNiSeMezclan documenta ese orden
// como no cubierto a propósito —una ventana de microsegundos frente a los 15
// segundos del fallo que arregló H006— y el invariante que sí exige es que no se
// pierda ninguna emisión. Serializar aquí y descartar las generaciones
// superadas se probó: perdía 280 de 1600 emisiones y rompía ese invariante.
func (t *trayState) aplicar(state, tooltip string) {
	// Sin bandeja del sistema (pruebas) el estado se observa sólo por emit.
	if t.tray != nil {
		t.tray.SetIcon(trayIcon(state))
		t.tray.SetLabel("CodeGuard: " + state)
		t.tray.SetTooltip("CodeGuard — " + tooltip)
	}
	// La burbuja flotante escucha el mismo estado.
	if t.emit != nil {
		t.emit(state, tooltip)
	}
}

// version la inyecta build-dist con -X main.version desde setup.iss — una
// sola fuente de verdad. "dev" delata un binario compilado a mano.
var version = "dev"

// abrirLog manda el registro al archivo del usuario. El daemon corre sin
// consola (-H windowsgui): sin este log, cualquier fallo es invisible. Vive
// junto a la BD del usuario.
func abrirLog(refrescadas int) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return
	}
	dir := filepath.Join(base, "codeguard")
	_ = os.MkdirAll(dir, 0o755) // best-effort: el OpenFile del log de abajo reportaría el fallo
	f, err := os.OpenFile(filepath.Join(dir, "daemon.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.Printf("=== daemon %s arrancado ===", version)
	if refrescadas > 0 {
		log.Printf("entorno: %d variable(s) del usuario incorporadas del registro", refrescadas)
	}
}

// main es la raíz de composición y nada más: cablea las piezas en el orden en
// que dependen unas de otras. Lo que cada pieza HACE vive en escritorio.go —
// aquí sólo se ve el arranque completo de un vistazo.
func main() {
	// El PATH del registro antes que nada: el daemon lo lanza la clave Run al
	// iniciar sesión, y si el agente se instaló DURANTE la sesión en curso su
	// entorno no tiene los motores. Sin esto, la compuerta de secretos bloquea
	// commits pidiendo un gitleaks que está instalado.
	proc.RefrescarPATH()
	// Y las demás variables del usuario, que es donde vive la clave del modelo:
	// sin esto, cada reinicio del daemon apagaba la capa LLM en silencio.
	refrescadas := proc.RefrescarVariables()
	// El caché de resultados lleva la versión en su clave: al actualizar el
	// agente, lo que analizó el binario viejo deja de darse por bueno.
	daemon.Version = version
	abrirLog(refrescadas)

	// El sandbox (token restringido) que no se puede crear degrada a
	// privilegios completos sin decirlo en ningún sitio que se lea solo
	// (prepararSandbox): la línea de `codeguard engines` existe, pero nadie
	// corre el diagnóstico espontáneamente. Una línea aquí lo deja dicho en
	// cada arranque. Solo con err: fuera de Windows SandboxActivo devuelve
	// (false, nil) por diseño. La palabra t*ken no puede ir en el mensaje:
	// log-dato-sensible liga el texto de CADA argumento del logger.
	if activo, err := proc.SandboxActivo(); !activo && err != nil {
		log.Printf("sandbox: la contencion NO esta disponible (%v): los motores corren con los privilegios completos de la sesion", err)
	}

	// Y ya con el log abierto, se mueve a la bóveda la clave que las versiones
	// anteriores dejaron en HKCU\Environment en texto plano. Va aquí porque es
	// el único sitio por el que pasa toda instalación existente al actualizar:
	// esperar a que el usuario abra la pantalla de configuración dejaría la
	// copia vieja expuesta indefinidamente en las máquinas de quien no la
	// vuelva a tocar, que son la mayoría.
	migrarClaveSiHaceFalta()

	// El escritorio nace antes que la aplicación: Wails pide el manejador HTTP
	// al construirse y ese manejador sirve el estado que vive en el escritorio.
	e := nuevoEscritorio()
	e.app = application.New(application.Options{
		Name:        "CodeGuard",
		Description: "Agente de análisis pre-commit con paridad hacia CI",
		// La identidad del agente es el mismo orbe que el desarrollador ve en
		// la esquina de su pantalla, no un ícono genérico.
		Icon: iconoOficial(),
		Assets: application.AssetOptions{
			// BundledAssetFileServer sirve también /wails/runtime.js,
			// que el panel importa para los eventos.
			Handler: e.manejadorHTTP(),
		},
	})
	e.construirVentanas()
	e.construirBandeja()
	e.registrarEventos()

	srv := e.construirServidorIPC(e.arrancarSombra())

	// Anclar el orbe en su esquina al arrancar (con reintentos).
	e.app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		e.anclarBurbujaSeguro()
	})

	ctx, cancel := context.WithCancel(context.Background())
	e.app.OnShutdown(cancel)
	go func() {
		// El tray refleja "working" mientras el server atiende: el propio
		// handler emite el estado al entrar la petición (ver ipc hook abajo).
		if err := srv.Serve(ctx); err != nil {
			log.Println("servidor IPC:", err)
		}
	}()

	if err := e.app.Run(); err != nil {
		log.Fatal(err)
	}
}
