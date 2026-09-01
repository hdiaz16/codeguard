package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
)

func (e *escritorio) alEmpezarAnalisis(req *ipc.Request) {
	// Re-anclar por si cambió la resolución o se movió la barra. La guarda no
	// defiende de un imposible de producción —ahí e.app está siempre— sino de
	// que una prueba del marcador del orbe tenga que arrancar Wails para no
	// morir en InvokeAsync. Mismo motivo que en pedirPanel.
	if e.app != nil {
		application.InvokeAsync(e.anclarBurbuja)
	}
	repo := filepath.Base(req.RepoRoot)
	// El marcador se abre ANTES de anunciar el estado: a partir de aquí pueden
	// entrar avances, y uno que llegara con el análisis todavía sin abrir se
	// descartaría por venir "de otro run".
	plazo := e.plazoVigilante
	if plazo <= 0 {
		plazo = plazoDelVigilante(req.DeadlineMs)
	}
	e.enCurso.empezar(req.RunID, repo, req.Branch, plazo, e.alMorirElAnalisis)
	e.tray.set("working", "revisando "+repo+" · rama "+req.Branch)
	e.emitirEvento("working", map[string]string{"repo": repo, "branch": req.Branch})
}

// alAvanzarAnalisis lleva al orbe UN paso del análisis, mientras corre.
//
// Corre en la goroutine de un motor, dentro del camino del commit: aquí no se
// puede bloquear. Por eso NO se toca la bandeja del sistema —sus setters son
// InvokeSync y esperan al hilo de la UI— y sólo se publica en el bus, que en
// Wails despacha en su propia goroutine. El ícono ya dice "working" desde que
// entró la petición y no cambia mientras dura: lo que cambia es lo que el orbe
// cuenta, y eso viaja por este evento.
func (e *escritorio) alAvanzarAnalisis(req *ipc.Request, av pipeline.Avance) {
	v, ok := e.enCurso.avanzar(req.RunID, av)
	if !ok {
		return // avance rezagado, o de otro análisis: pintarlo sería mentir
	}
	e.emitirEvento(eventoProgreso, cargaDeProgreso(v))
}

// alMorirElAnalisis corta el «revisando» que no vuelve.
//
// Se llega aquí cuando un análisis lleva callado más que su propio plazo con
// margen: el proceso se tragó un panic, un motor se colgó por encima del
// deadline, el pipe murió a media etapa. El orbe no puede quedarse afirmando que
// hay una revisión en marcha que ya no existe — es la misma mentira por omisión
// que el ✓ verde sobre un análisis omitido, sólo que sin caducidad.
//
// Va a "degraded" y no a reponerOrbe() —el estado real del último análisis
// completo— a propósito. Reponer sería honesto sobre el pasado y mudo sobre lo
// que acaba de pasar: el commit que el dev ACABA de hacer se quedaría enseñando
// el veredicto verde del anterior, que es exactamente lo que orbStateFor
// documenta como inaceptable ("la señal prudente es la que pide mirar, nunca la
// que tranquiliza"). Un análisis que no terminó es un agujero de cobertura del
// tamaño entero del commit, y "degraded" es justo eso: ve a mirar.
//
// No se toca porProyecto: ahí vive el último análisis que SÍ terminó, y el panel
// tiene que seguir pudiendo enseñarlo. Lo que se corrige es lo que el orbe
// afirma ahora mismo.
func (e *escritorio) alMorirElAnalisis(repo, rama string) {
	log.Printf("orbe: el análisis de %s (rama %s) no volvió; se corta el «revisando»", repo, rama)
	e.tray.set("degraded", fmt.Sprintf(
		"%s · rama %s · el análisis no terminó — no sé qué quedó sin revisar", repo, rama))
}

func (e *escritorio) alTerminarAnalisis(req *ipc.Request, resp *ipc.Response) {
	// Lo PRIMERO: cerrar el análisis en curso. Deja sin efecto al vigilante y
	// cierra la puerta a los avances rezagados, así que a partir de esta línea
	// nada puede volver a poner al orbe en "revisando".
	e.enCurso.terminar(req.RunID)
	cfg, _ := config.Load(req.RepoRoot)
	maxShow, autoOpen := opcionesUI(cfg)
	// El escritorio se queda con el payload; lo que sigue usa la copia que
	// publica, que es de este hilo y ya nadie va a reescribir por debajo.
	payload := e.registrarAnalisis(construirPayload(req, resp, cfg, maxShow))
	e.actualizarOrbe(payload)

	e.emitirEvento("analysis", payload)
	estado := estadoDelCable(resp)
	shouldOpen := autoOpen == "on_findings" && len(resp.Findings) > 0 ||
		autoOpen != "never" && estado == string(pipeline.Bloqueado)
	if shouldOpen {
		// Las ventanas se tocan desde el hilo de la UI.
		application.InvokeAsync(e.mostrarPanel)
	}

	// Diferenciador D1: el modelo explica los bloqueantes en español
	// claro, sobre TU código. Async, cacheado por fingerprint — el
	// commit ya fue decidido; esto solo enriquece el panel.
	if cfg != nil && estado == string(pipeline.Bloqueado) {
		go explainBlockers(e.app, cfg, req, resp)
	}
}

// opcionesUI saca del proyecto cuántos hallazgos mostrar y cuándo abrir solo
// el panel. Sin configuración legible, los valores por defecto de §12.
func opcionesUI(cfg *config.Config) (maxShow int, autoOpen string) {
	maxShow, autoOpen = 7, "on_block"
	if cfg == nil {
		return maxShow, autoOpen
	}
	if cfg.UI.MaxVisibleFindings > 0 {
		maxShow = cfg.UI.MaxVisibleFindings
	}
	if cfg.UI.AutoOpenPanel != "" {
		autoOpen = cfg.UI.AutoOpenPanel
	}
	return maxShow, autoOpen
}

// construirPayload arma lo que el panel pinta de un análisis terminado.
//
// cfg entra porque la cabecera del panel no describe el ANÁLISIS sino el
// PROYECTO —su stack—, y eso no viaja en la respuesta. Puede ser nil: un repo
// cuyo config no se pudo leer no tiene "cero lenguajes", tiene un problema, y
// el panel no debe presentar lo segundo como lo primero.
func construirPayload(req *ipc.Request, resp *ipc.Response, cfg *config.Config, maxShow int) *panelPayload {
	var languages []string
	if cfg != nil {
		languages = cfg.Languages
	}
	payload := &panelPayload{
		Repo:        filepath.Base(req.RepoRoot),
		RepoRoot:    filepath.ToSlash(req.RepoRoot),
		Branch:      req.Branch,
		AIGenerated: req.AIGenerated,
		Suppressed:  resp.Suppressed,
		Languages:   languages,
		Capas:       resp.Capas,
		Verdict:     resp.Verdict,
		// El motivo del salto llegaba hasta aquí por el pipe y moría en esta
		// línea, que no existía: la UI se quedaba sin poder explicar por qué no
		// se revisó y acababa conjeturándolo.
		Reason:   resp.Reason,
		Blocking: resp.BlockingFindings,
		Advisory: resp.AdvisoryFindings,
		CIParity: resp.CIParity,
		Degraded: resp.Degraded,
		// El veredicto derivado y la garantía rota vienen del daemon (mismo
		// proceso, misma respuesta): el orbe LEE, no re-deriva.
		Outcome:      estadoDelCable(resp),
		GarantiaRota: garantiaDelCable(resp),
		// El diff ya cruzó el pipe en el Request; perderlo aquí es lo que
		// apagaba la zona activa de los archivos limpios en el explorador.
		ChangedFiles: rutasDelDiff(req.StagedFiles),
		MaxShow:      maxShow,
		ElapsedMs:    resp.ElapsedMs,
		At:           time.Now().Format("15:04:05"),
	}
	for _, f := range resp.Findings {
		payload.Findings = append(payload.Findings, panelFinding{
			Finding: f,
			Snippet: snippet(req.RepoRoot, f.File, f.Line),
			IsFact:  f.Source == finding.Deterministic,
		})
	}
	return payload
}

// estadoDelCable y garantiaDelCable leen el outcome de la respuesta con la
// misma prudencia que el hook: si no llegó (no debería pasar: es el mismo
// proceso), no se inventa nada y el orbe cae en su rama de desconocido.
func estadoDelCable(resp *ipc.Response) string {
	if resp.Outcome == nil {
		return ""
	}
	return resp.Outcome.State
}

func garantiaDelCable(resp *ipc.Response) []string {
	if resp.Outcome == nil {
		return nil
	}
	return resp.Outcome.GarantiaRota
}

// rutasDelDiff saca las rutas de los archivos del commit y nada más. El Status y
// el SHA256 no cruzan al payload: al overlay le basta QUÉ archivos se tocaron
// para encender su zona, y lo demás sería equipaje muerto camino de la UI.
//
// Vive aquí y no en overlay.go para que ese archivo siga sin saber de ipc ni de
// gitdiff: sólo consume el payload.
func rutasDelDiff(files []gitdiff.ChangedFile) []string {
	if len(files) == 0 {
		return nil
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

// actualizarOrbe pone el clima del orbe tras un análisis. El COLOR lo decide
// orbStateFor y sólo orbStateFor —aquí se elige el tooltip y si el estado es
// transitorio—, porque cuando cada ruta decidía el suyo acabaron discrepando.
//
// El orbe habla SOLO del proyecto que acabas de tocar.
func (e *escritorio) actualizarOrbe(p *panelPayload) {
	estado := orbStateFor(p)
	tooltip := tooltipDelOrbe(p)
	// El "no corrió" del tooltip nombra la garantía rota, no el Degraded crudo:
	// una política deliberada (daemon:offline, diff grande) no es un "no corrió"
	// y meterla aquí era la contradicción de dos líneas del hook, en chiquito.
	if estado == "degraded" && len(p.GarantiaRota) > 0 {
		tooltip += " — no corrió: " + strings.Join(p.GarantiaRota, ", ")
	}
	// Sólo el verde es transitorio: vuelve a idle a los 15 s porque "todo bien"
	// ya se dijo. Un bloqueo o un agujero de cobertura se quedan hasta que pase
	// otra cosa.
	if estado == "pass" {
		e.tray.setPass(tooltip)
		return
	}
	e.tray.set(estado, tooltip)
}

// reponerOrbe recalcula el orbe desde el estado REAL del proyecto activo.
//
// No restaura una foto guardada, y la diferencia importa: si mientras tanto
// entró un análisis de verdad, una foto vieja lo taparía —que es la forma de
// mentir que se acaba de quitar de todas las demás rutas—. Aquí se vuelve a
// derivar de `activoActual()` con las mismas dos funciones que usa el resto del
// archivo, así que el resultado es por construcción el que se vería si nadie
// hubiera tocado nada.
//
// Sin proyecto activo no se afirma nada: idle, y se dice por qué.
func (e *escritorio) reponerOrbe() {
	p := e.activoActual()
	if p == nil {
		e.tray.set("idle", "aún no has commiteado en un proyecto vigilado")
		return
	}
	e.actualizarOrbe(p)
}

// tooltipDelOrbe es la frase que se lee al pasar el ratón por encima.
//
// El caso omitido tiene la suya porque resumenHallazgos contaba hallazgos y
// devolvía "sin observaciones", que sobre un análisis que no miró nada es
// literalmente falso: no es que no hubiera observaciones, es que no se observó.
// Era la misma mentira que el hook ya dejó de contar, en la superficie de al
// lado, y con el agravante de que aquí no hacía falta adivinar nada — el motivo
// venía en el payload.
func tooltipDelOrbe(p *panelPayload) string {
	// Un repo que nunca se ha analizado no tiene "0 hallazgos": no tiene
	// ninguno porque nadie ha mirado, y decir "sin observaciones" ahí es la
	// misma mentira por omisión que el ✓ verde. El placeholder "—" lo pone el
	// registro cuando se enrola un repo o se cambia a uno que no ha commiteado.
	//
	// Va aquí y no en quien enrola, porque es una propiedad del payload: así lo
	// dicen igual el enrolamiento, el cambio de proyecto desde el panel y el
	// sembrado al arrancar, en vez de que cada camino escriba su propia frase.
	if p.Outcome == "" {
		return fmt.Sprintf("%s · sin análisis todavía — haz un commit aquí", p.Repo)
	}
	if p.Outcome == string(pipeline.Omitido) {
		motivo := p.Reason
		if motivo == "" {
			// Mejor decir que no se revisó sin el porqué que fingir que sí.
			motivo = "el motivo no llegó hasta aquí"
		}
		return fmt.Sprintf("%s · rama %s · sin revisar — %s", p.Repo, p.Branch, motivo)
	}
	if p.Outcome == string(pipeline.Fallido) {
		motivo := p.Reason
		if motivo == "" {
			motivo = "el análisis no pudo terminar"
		}
		return fmt.Sprintf("%s · rama %s · análisis fallido — %s", p.Repo, p.Branch, motivo)
	}
	if p.Outcome == string(pipeline.Degradado) {
		return fmt.Sprintf("%s · rama %s · análisis incompleto — CodeGuard no afirma limpio", p.Repo, p.Branch)
	}
	if p.Outcome != string(pipeline.Limpio) && p.Outcome != string(pipeline.ConAvisos) &&
		p.Outcome != string(pipeline.Bloqueado) {
		return fmt.Sprintf("%s · rama %s · estado no verificable — CodeGuard no afirma limpio", p.Repo, p.Branch)
	}
	// "3 bloqueantes, 1 avisos" es un contador, no una frase. Esto se
	// lee de un vistazo y en singular cuando toca.
	return fmt.Sprintf("%s · rama %s · %s%s", p.Repo, p.Branch,
		resumenHallazgos(p.Blocking, p.Advisory), coberturaDelOrbe(p.Capas))
}

// coberturaDelOrbe añade al tooltip CUÁNTO se miró, no sólo qué se encontró.
//
// Es la diferencia entre "sin observaciones" y "sin observaciones, y estas ocho
// capas lo miraron". El orbe era el único sitio que enseñaba el veredicto sin
// abrir nada, y decía el resultado sin decir el alcance: un ✓ tras un análisis
// con la mitad de los motores caídos se veía idéntico a uno completo.
func coberturaDelOrbe(cs []capas.Capa) string {
	if len(cs) == 0 {
		return ""
	}
	miraron, caidas := 0, 0
	for _, c := range cs {
		switch {
		case c.Cayo():
			caidas++
		case c.Estado == capas.Corrio:
			miraron++
		}
	}
	if caidas > 0 {
		return fmt.Sprintf(" · %d capas revisaron, %d no pudieron", miraron, caidas)
	}
	return fmt.Sprintf(" · %d capas revisaron", miraron)
}
