// Package daemon atiende peticiones del hook por named pipe y corre la
// etapa 2 (compuertas deterministas) del pipeline.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	sgengine "codeguard/internal/engines/semgrep"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/shadow"
	"codeguard/internal/store"
)

// OnResult permite a la UI (F2.4) reaccionar a cada análisis terminado.
type OnResult func(req *ipc.Request, resp *ipc.Response)

type Server struct {
	// OnRequest se dispara al entrar una petición (estado working en la UI).
	OnRequest func(req *ipc.Request)
	// OnCommand atiende peticiones de la CLI hacia la UI (p.ej. abrir el grafo).
	//
	// Recibe la petición ENTERA y no sólo la ruta: el bloqueo por secreto
	// necesita además cuántos fueron, y pasarle a la UI un canal recortado
	// obligaba a inventar un segundo camino para cada comando que llevara un
	// dato más.
	OnCommand func(cmd string, req *ipc.Request)
	// OnProgreso se dispara con cada paso de la etapa 2 MIENTRAS corre, para
	// que el orbe pueda enseñar el análisis avanzando en vez de quedarse mudo
	// los cuatro o cinco segundos que dura.
	//
	// Corre en las goroutines de los motores, en el camino del commit: lo que se
	// haga aquí NO puede bloquear (ver el contrato en pipeline/progreso.go). En
	// nil —que es lo normal fuera del daemon con ventana— no cuesta nada.
	OnProgreso func(req *ipc.Request, av pipeline.Avance)
	OnResult   OnResult
	// Shadow, si no es nil, corre las etapas 3-6 (LLM en sombra) DESPUÉS de
	// responder al hook — nunca en el camino del commit.
	Shadow *shadow.Runner
}

// Engines arma la lista de motores de la etapa 2. Compartida con `codeguard
// ci` (que pasa cache=nil: el runner es efímero y un caché ahí no acierta
// nunca) y con report/baseline/hook, que pasan el caché por archivo si el
// store abre.
func (s *Server) Serve(ctx context.Context) error {
	l, err := ipc.Listen()
	if err != nil {
		return err
	}
	defer l.Close()
	log.Println("daemon escuchando en el pipe del usuario")
	go WarmAll(ctx) // compiladores calientes antes del primer commit del día

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed") {
				return nil
			}
			log.Println("aviso: error transitorio al aceptar conexión en pipe:", err)
			time.Sleep(20 * time.Millisecond)
			continue
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := ipc.ReadRequest(conn)
	if err != nil {
		log.Println("petición inválida o timeout:", err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	// Comandos que no son análisis (los manda la CLI para que la UI actúe).
	if req.Command != "" {
		if s.OnCommand != nil {
			s.OnCommand(req.Command, req)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = ipc.WriteResponse(conn, &ipc.Response{RunID: req.RunID, Verdict: "ok"}) // ack de comando; si el pipe se cerró, no hay nada que hacer
		return
	}
	if s.OnRequest != nil {
		s.OnRequest(req)
	}
	go RememberRepo(req.RepoRoot) // para precalentar en el próximo arranque
	resp := s.Analyze(ctx, req)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := ipc.WriteResponse(conn, resp); err != nil {
		log.Println("no se pudo responder:", err)
	}
	if s.OnResult != nil {
		s.OnResult(req, resp)
	}
	if s.Shadow != nil && (resp.Verdict == "pass" || resp.Verdict == "block") {
		if cfg, err := config.Load(req.RepoRoot); err == nil && cfg != nil {
			//nolint:gosec // G118: la sombra sobrevive al request a propósito (ver context.Background abajo)
			go func() {
				// El hook persiste el run al recibir esta misma respuesta, en
				// SU proceso. La sombra no puede empezar antes de que esa fila
				// exista: todo lo que escribe cuelga de ella.
				if s.Shadow.Store != nil &&
					!esperarRunPersistido(ctx, s.Shadow.Store, req.RunID, esperaMaximaDelRun) {
					return // esperarRunPersistido ya dejó dicho el porqué
				}
				// context.Background a propósito (no el de la petición): la
				// sombra corre DESPUÉS de responder al hook y sobrevive al
				// cierre de la conexión. Atarla al contexto de la petición la
				// cancelaría justo al empezar.
				s.Shadow.Run(context.Background(), cfg, req, resp.Findings) //nolint:contextcheck // desligado del request a propósito
			}()
		}
	}
	// F4a: el empuje al Postgres central viaja a cuestas del tráfico real —
	// cada análisis es una oportunidad de sincronizar, con throttle para no
	// abrir una conexión por commit. Best-effort puro: jamás toca el commit.
	if s.Shadow != nil && s.Shadow.Store != nil {
		go syncOportunista(s.Shadow.Store)
	}
}

// esperaMaximaDelRun es lo que la sombra aguanta a que el hook escriba la fila
// del run. Treinta segundos es holgadísimo para un INSERT —lo normal se mide en
// milisegundos— y aun así termina: una espera sin tope dejaría goroutines vivas
// para siempre si el hook muere entre responder y persistir, que es justo lo que
// pasa cuando el desarrollador aborta el commit con Ctrl-C.
const esperaMaximaDelRun = 30 * time.Second

// esperarRunPersistido espera a que la fila del run EXISTA antes de dejar
// correr la sombra. Devuelve false si se agotó el tope o si el daemon se apaga.
//
// Aquí había un `time.Sleep(2 * time.Second)` con el comentario «el hook
// persiste el run justo después de recibir la respuesta». Dos segundos no son
// una espera, son una apuesta: quien escribe esa fila es OTRO PROCESO (el del
// hook, ver persistRun en cmd/codeguard) sobre el mismo archivo SQLite, y su
// escritura compite con el antivirus, con el disco y con el empuje oportunista
// que este mismo handle() lanza en paralelo contra la misma base. Cuando el hook
// pasaba de dos segundos, la sombra actualizaba un run que aún no existía: un
// UPDATE de cero filas, que en database/sql no es error, y el risk_score se
// perdía para siempre sin una línea de log.
//
// Sondear la fila convierte la apuesta en un hecho: se espera lo que haga falta
// —no un número fijo elegido de memoria— y si el tope se agota se DICE. Al
// agotarse, la sombra no corre: sus hallazgos y su telemetría cuelgan del run
// por clave foránea, así que sin la fila no habría dónde guardarlos y lo único
// que se conseguiría es quemar tokens en un análisis que nadie podrá leer.
//
// El backoff arranca en 50 ms y se dobla hasta un segundo: el caso normal —la
// fila ya está o llega enseguida— se resuelve en un sondeo o dos, y el caso raro
// no martillea la base justo cuando está contendida, que es lo que lo hacía
// raro.
func esperarRunPersistido(ctx context.Context, st *store.Store, runID string, tope time.Duration) bool {
	inicio := time.Now()
	espera := 50 * time.Millisecond
	var ultimoErr error
	for {
		existe, err := st.RunExiste(runID)
		if existe {
			return true
		}
		if err != nil {
			// Preguntar puede fallar por contención (SQLITE_BUSY) y el
			// siguiente sondeo suele acertar; se guarda el último error para
			// poder decir POR QUÉ si al final se agota el tope.
			ultimoErr = err
		}
		if time.Since(inicio) >= tope {
			log.Printf("sombra: el run %s no apareció en la base tras %s (último error: %v) — "+
				"la sombra no corre porque sus hallazgos no tendrían dónde colgarse",
				runID, tope, ultimoErr)
			return false
		}
		t := time.NewTimer(espera)
		select {
		case <-ctx.Done():
			t.Stop()
			log.Printf("sombra: el daemon se apaga mientras esperaba al run %s — se abandona", runID)
			return false
		case <-t.C:
		}
		if espera < time.Second {
			espera *= 2
		}
	}
}

// El daemon es un proceso longevo: el throttle del empuje oportunista vive en
// variables de paquete, con mutex porque handle() atiende conexiones en
// paralelo.
var (
	sincronizaMu      sync.Mutex
	ultimoIntentoSync time.Time
)

// syncOportunista empuja la telemetría local al central si el DSN está
// configurado y han pasado al menos diez minutos desde el último INTENTO
// (también los fallidos cuentan: un central caído no merece un martilleo por
// commit). Los errores van al log y a ningún otro sitio — la telemetría
// nunca se interpone en un commit.
func syncOportunista(st *store.Store) {
	dsn := os.Getenv(store.EnvTelemetriaDSN)
	if dsn == "" {
		return // sin central configurado no hay nada que empujar ni que avisar
	}
	sincronizaMu.Lock()
	if time.Since(ultimoIntentoSync) < 10*time.Minute {
		sincronizaMu.Unlock()
		return
	}
	ultimoIntentoSync = time.Now()
	sincronizaMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if res, err := st.SyncCentral(ctx, dsn); err != nil {
		log.Printf("sync central oportunista: %v", err)
	} else if res.Total() > 0 {
		log.Printf("sync central: %d fila(s) empujada(s)", res.Total())
	}
}

// Analyze corre la etapa 2 para una petición del hook.
func (s *Server) Analyze(ctx context.Context, req *ipc.Request) *ipc.Response {
	resp := &ipc.Response{RunID: req.RunID, Verdict: "pass", CIParity: true, Degraded: []string{}}
	start := time.Now()
	defer func() { resp.ElapsedMs = time.Since(start).Milliseconds() }()

	cfg, err := config.Load(req.RepoRoot)
	if err != nil || cfg == nil {
		resp.Verdict = "skipped"
		// El motivo viaja: un "no se analizó nada" sin explicación es de los que
		// el dev aprende a ignorar. Se distinguen los dos casos porque el remedio
		// no es el mismo — uno se arregla con `codeguard init` y el otro editando
		// el YAML que está roto.
		if err != nil {
			resp.Reason = "no se pudo leer .codeguard/config.yaml: " + err.Error()
		} else {
			resp.Reason = "repo no enrolado (falta .codeguard/config.yaml)"
		}
		resp.Degraded = append(resp.Degraded, "config:unreadable")
		return resp
	}
	// ci_parity §8: rulepack y config del daemon deben coincidir con los del
	// hook. Si el archivo cambió ENTRE la lectura del hook y la nuestra (p.ej.
	// un `codeguard init` corriendo a la par), se relee una vez antes de
	// declarar rota la paridad — así no se asusta al dev por una carrera.
	if cfg.Hash != req.ConfigHash || cfg.Rulepack != req.RulepackVersion {
		if again, err2 := config.Load(req.RepoRoot); err2 == nil && again != nil &&
			again.Hash == req.ConfigHash && again.Rulepack == req.RulepackVersion {
			cfg = again
		} else {
			resp.CIParity = false
			if cfg.Rulepack != req.RulepackVersion {
				resp.ParityReason = fmt.Sprintf("el rulepack cambió durante el commit (%s → %s): vuelve a intentarlo",
					req.RulepackVersion, cfg.Rulepack)
			} else {
				resp.ParityReason = "la configuración cambió durante el commit: vuelve a intentarlo"
			}
			log.Printf("paridad rota en %s: config %s≠%s, rulepack %s≠%s",
				filepath.Base(req.RepoRoot), short(cfg.Hash), short(req.ConfigHash),
				cfg.Rulepack, req.RulepackVersion)
		}
	}
	rulepack := RulepackDir(req.RepoRoot, cfg.Rulepack)
	// Reglas del propio repo: se aplican (es el respaldo legítimo cuando la
	// versión no está instalada), pero no se puede prometer paridad con el CI
	// —nadie ha comprobado que ese directorio contenga las reglas que dice su
	// número— y sobre todo se DICE, que era lo que faltaba.
	if RulepackEsDelRepo(req.RepoRoot, cfg.Rulepack) {
		resp.CIParity = false
		resp.ParityReason = fmt.Sprintf("las reglas salieron del rulepack vendoreado en este repo "+
			"(rulepacks/%s), no del instalado: son las que trae el repositorio", cfg.Rulepack)
		log.Printf("rulepack del repo en %s: %s", filepath.Base(req.RepoRoot), rulepack)
	}
	if _, err := os.Stat(rulepack); err != nil {
		resp.CIParity = false
		// Este camino rompía la paridad EN SILENCIO: el dev leía "no puedo
		// garantizar que pase el CI" en cada commit y no había una sola línea
		// en ningún log que dijera por qué. Ahora dice qué versión se buscó,
		// dónde, y qué versiones sí están instaladas — con eso el aviso se
		// resuelve solo en vez de convertirse en ruido que se aprende a ignorar.
		instaladas := RulepacksInstalados(req.RepoRoot)
		if len(instaladas) == 0 {
			instaladas = []string{"ninguna"}
		}
		resp.ParityReason = fmt.Sprintf("este repo pinnea el rulepack %s y no está instalado (hay: %s) — corre `codeguard repair`",
			cfg.Rulepack, strings.Join(instaladas, ", "))
		log.Printf("paridad rota en %s: el repo pinnea el rulepack %q y no está en %s (instaladas: %s)",
			filepath.Base(req.RepoRoot), cfg.Rulepack, rulepack, strings.Join(instaladas, ", "))
	}

	deadline := time.Duration(req.DeadlineMs) * time.Millisecond
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	// Margen H3: los motores se cortan ANTES del deadline del hook, para que
	// la respuesta (aunque degradada) siempre llegue a tiempo. Un tsc frío
	// se degrada aquí y el CI lo aplica como bloqueante.
	deadline -= 700 * time.Millisecond
	if deadline < time.Second {
		deadline = time.Second
	}
	var demoted map[string]bool
	var cache sgengine.Cache
	if s.Shadow != nil && s.Shadow.Store != nil {
		// Si la consulta falla (SQLITE_BUSY, base cerrada), demoted queda nil y
		// las reglas que la organización degradó a advisory vuelven a BLOQUEAR en
		// este run. El lado seguro es ése y se mantiene, pero callarlo es la
		// pérdida silenciosa de siempre: el dev vería bloqueado un commit que
		// debía pasar sin una línea que lo explique. Se registra y se declara en
		// Degraded, que es el canal que el diseño ya usa para «este análisis
		// corrió con menos de lo prometido».
		var errDegradadas error
		demoted, errDegradadas = s.Shadow.Store.DemotedRules(req.RepoID, 5, 0.20)
		if errDegradadas != nil {
			log.Printf("no se pudieron leer las reglas degradadas de %s (%v): en este run "+
				"las degradaciones NO se aplican y esas reglas bloquean", req.RepoID, errDegradadas)
			resp.Degraded = append(resp.Degraded, "demoted:unavailable")
		}
		// El caché por archivo brilla justo aquí: un commit bloqueado se
		// reintenta con N-1 archivos idénticos, y esos ya no se re-analizan.
		cache = CachePorArchivo(s.Shadow.Store, req.RepoID, "", filepath.Base(req.RepoRoot), cfg)
	}
	// El progreso se ata a ESTA petición: el consumidor necesita saber de qué
	// análisis le hablan para no pintar el avance de un commit sobre otro.
	var progreso func(pipeline.Avance)
	if s.OnProgreso != nil {
		progreso = func(av pipeline.Avance) { s.OnProgreso(req, av) }
	}
	res, err := pipeline.Run(ctx, pipeline.Options{
		Config:       cfg,
		Diff:         &gitdiff.Diff{Files: req.StagedFiles, Unified: req.DiffUnified, Lines: req.DiffLines},
		Secrets:      nil, // ya corrió en el hook
		Engines:      Engines(cfg, false, cache),
		Rulepack:     rulepack,
		Timeout:      deadline,
		Suppressions: baseline.LoadOrWarn(req.RepoRoot),
		DemotedRules: demoted,
		Progreso:     progreso,
	})
	if err != nil {
		// La respuesta nació optimista ("pass", arriba) y este camino la
		// devolvía tal cual: cualquier consumidor que mire Verdict sin mirar
		// Degraded heredaba un visto bueno de un análisis que no corrió. El
		// mismo trato que la config ilegible: no analicé, no doy veredicto.
		resp.Verdict = "skipped"
		resp.Reason = "el análisis no corrió: " + err.Error()
		resp.Degraded = append(resp.Degraded, fmt.Sprintf("pipeline:%v", err))
		return resp
	}
	resp.Verdict = string(res.Verdict)
	// El motivo acompaña al veredicto. Sólo el pipeline sabe por qué se saltó el
	// análisis, y hasta aquí ese dato moría en este proceso: el hook recibía un
	// "skipped" mudo y no tenía con qué explicarlo. Va sin condición porque en
	// los veredictos que no son skipped el pipeline lo deja vacío.
	resp.Reason = res.Reason
	resp.BlockingFindings = res.BlockingFindings
	resp.AdvisoryFindings = res.AdvisoryFindings
	resp.Suppressed = res.Suppressed
	resp.Degraded = append(resp.Degraded, res.Degraded...)
	// El estado por capa viaja para que el panel pueda decir qué miró cada motor.
	resp.Capas = res.Capas
	// El daemon asigna los IDs: el hook persiste con los mismos y el panel
	// puede referenciarlos en el feedback (etapa 9).
	for i := range res.Findings {
		if res.Findings[i].ID == "" {
			res.Findings[i].ID = store.NewULID()
		}
	}
	resp.Findings = res.Findings
	return resp
}
