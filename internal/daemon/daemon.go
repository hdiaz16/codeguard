// Package daemon atiende peticiones del hook por named pipe y corre la
// etapa 2 (compuertas deterministas) del pipeline. La etapa 1 (secretos)
// ya corrió en el proceso del hook.
package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	gvengine "codeguard/internal/engines/govulncheck"
	"codeguard/internal/engines/linters"
	sgengine "codeguard/internal/engines/semgrep"
	sqengine "codeguard/internal/engines/squawk"
	stengine "codeguard/internal/engines/staticcheck"
	tvengine "codeguard/internal/engines/trivy"
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
func Engines(cfg *config.Config, inCI bool, cache sgengine.Cache) []engines.Engine {
	var migGlobs []string
	var migDialecto string
	if cfg != nil {
		migGlobs = cfg.Paths.Migrations
		migDialecto = cfg.Paths.DialectoMigraciones()
	}
	return []engines.Engine{
		&sgengine.Engine{Cache: cache},
		&sqengine.Engine{MigrationGlobs: migGlobs, Dialect: migDialecto},
		// Política §7: CVE crítico advierte en local, bloquea en CI.
		&tvengine.Engine{BlockCritical: inCI, SkipDBUpdate: !inCI, Cache: cache},
		// Alcanzabilidad: trivy dice "el CVE está en tu go.sum"; govulncheck
		// demuestra si el código lo llama. Misma política local/CI que trivy,
		// y en el hook sólo corre cuando cambian las dependencias — recorre el
		// módulo entero y el presupuesto del hook no está para eso.
		&gvengine.Engine{BlockReachable: inCI, SoloManifiestos: !inCI, Cache: cache},
		// Semántica SSA sobre los paquetes tocados: bugs demostrables en el
		// flujo real de valores, no patrones de texto. Lint de severidad
		// error bloquea (§7), la misma política que govet.
		&stengine.Engine{Cache: cache},
		linters.GoFmt{Cache: cache},
		linters.GoVet{Cache: cache},
		linters.Ruff{Cache: cache},
		// Tipos en Python, la última casilla que le faltaba al lenguaje: ruff ve
		// formato y lint, nadie veía los tipos. Sólo aplica si el repo YA
		// configuró mypy (mypy.ini, [mypy] en setup.cfg o [tool.mypy] en
		// pyproject.toml), por la misma razón que eslint: imponer comprobación
		// de tipos a un equipo que no la eligió sería puro ruido. El caché es
		// por proyecto —mypy sigue los imports, no analiza archivos sueltos— y
		// lleva dentro qué archivos se le pasaron.
		linters.Mypy{Cache: cache},
		// tsc compila el proyecto entero por cambio de un archivo: sin caché,
		// cada informe de un monorepo con frontend pagaría la compilación.
		linters.Tsc{Cache: cache},
		// Formato y estilo de TS/JS, que hasta aquí no tenían NADA (tsc sólo ve
		// tipos). Corre el eslint o el biome que el repo ya configuró, con sus
		// reglas; si no configura ninguno no aplica, y el caché es por archivo
		// con la huella de esa config dentro de la clave.
		linters.ESLint{Cache: cache},
		linters.DotnetFormat{Cache: cache},
		// Compilación de C#: hasta aquí un `; expected` en un .cs llegaba entero
		// al CI, porque dotnet format sólo mira el formato. Compila el .csproj
		// tocado (nunca la solución) con --no-restore y -t:Rebuild, así que el
		// caché por huella de proyecto no es un lujo: es lo que evita pagar la
		// compilación en cada informe.
		linters.DotnetBuild{Cache: cache},
		// CVEs de NuGet, el hueco que trivy no cubre: sin packages.lock.json no
		// encuentra NADA en un .csproj (verificado). Misma política local/CI que
		// trivy y govulncheck, y en el hook sólo cuando cambian los manifiestos
		// — este comando sí restaura y sí va a la red.
		linters.DotnetVuln{BlockCritical: inCI, SoloManifiestos: !inCI, Cache: cache},
		// Formato de Java, que hasta aquí no tenía NADA: el lenguaje sólo contaba
		// con las reglas de la casa (semgrep) y las dependencias (trivy), así que
		// la discusión sobre dónde va la llave se pagaba entera en la revisión.
		// google-java-format sólo mira el fuente —no compila ni necesita
		// classpath—, que es lo que lo hace apto para el camino del commit.
		// Caché por archivo: el formateador no tiene configuración, así que el
		// mismo contenido da siempre el mismo veredicto.
		linters.JavaFmt{Cache: cache},
		// Calidad de Java sobre el AST, el govet/staticcheck del otro lado. PMD y
		// no SpotBugs porque SpotBugs analiza bytecode y exigiría compilar el
		// proyecto, que no cabe en el presupuesto del hook. Caché por archivo, no
		// por proyecto como tsc o dotnet-build: PMD evalúa cada archivo por su
		// cuenta, así que tocar 1 de 200 cuesta 1.
		linters.JavaLint{Cache: cache},
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// RulepackDir resuelve el rulepack pinneado, en orden: vendoreado en el repo,
// junto al binario, un nivel arriba del binario, y la instalación estándar del
// usuario.
//
// Los dos últimos no son "por si acaso". El binario instalado vive en
// CodeGuard\bin y los rulepacks se copian ahí y también un nivel arriba; pero
// cualquier binario que NO sea el instalado —una compilación de desarrollo, una
// copia portable— no tiene rulepacks al lado, y entonces todo repo que no los
// vendoree pierde las 119 reglas de la casa EN SILENCIO. Se reprodujo en un
// repo de prueba: semgrep "corrió" en 0 ms con 0 hallazgos y la baseline se
// escribió sin cobertura de reglas. La instalación estándar es el último
// recurso porque siempre está donde está, sin importar quién arrancó el proceso.
// El del repo va el ÚLTIMO, y esto es una decisión de seguridad, no de orden.
//
// Iba primero, y con eso el repo ANALIZADO decidía qué reglas se le aplicaban:
// bastaba traer un `rulepacks/<la version que pinnea>/` con reglas de relleno
// para que las de la casa no llegaran a mirar el código. Medido: el mismo
// archivo con una inyección SQL de manual sale BLOQUEADO con el rulepack
// instalado y "formato/lint/tipos/reglas/migraciones ✓  listo — commit
// permitido" con el del repo. Sin carrera y sin atacante sofisticado: basta
// clonar el repositorio.
//
// El vendoreado sigue existiendo porque resuelve un fallo real —un binario que
// no es el instalado no tiene rulepacks al lado, y sin esto cada repo perdería
// las 119 reglas EN SILENCIO—, pero como RESPALDO: se usa cuando la versión no
// está instalada, que es el caso que lo justificó. Si están las dos, el mismo
// número nombrando dos artefactos distintos es una colisión, y en una colisión
// gana el de la organización: la versión es una promesa de paridad con el CI.
//
// Un equipo que de verdad necesite reglas propias las publica con SU número de
// versión; lo que no puede es reutilizar el de la casa para otra cosa.
func RulepackDir(repoRoot, version string) string {
	local := filepath.Join(repoRoot, "rulepacks", version)
	var candidatos []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidatos = append(candidatos,
			filepath.Join(dir, "rulepacks", version),
			filepath.Join(filepath.Dir(dir), "rulepacks", version))
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		candidatos = append(candidatos, filepath.Join(base, "CodeGuard", "rulepacks", version))
	}
	candidatos = append(candidatos, local)
	for _, c := range candidatos {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Ninguno existe: se devuelve la ruta del repo para que el mensaje de error
	// hable del sitio donde el dev PODRÍA vendorearlo.
	return local
}

// RulepackEsDelRepo dice si las reglas que se van a aplicar salen del repo
// analizado en vez de las instaladas.
//
// Existe para poder DECIRLO. El hook ya avisaba a gritos cuando el rulepack
// falta ("las reglas de la casa NO se aplicaron"), y callaba cuando lo
// sustituyen — que es peor, porque no deja rastro: el veredicto sale con su ✓ y
// nadie sabe qué reglas corrieron.
func RulepackEsDelRepo(repoRoot, version string) bool {
	return RulepackDir(repoRoot, version) == filepath.Join(repoRoot, "rulepacks", version)
}

// RulepacksInstalados lista las versiones disponibles junto al binario y
// vendoreadas en el repo, ordenadas de más nueva a más vieja. Los nombres son
// fechas (2026.08.2), así que el orden lexicográfico inverso basta salvo por
// el número final: se compara por partes para que .10 no quede antes que .9.
func RulepacksInstalados(repoRoot string) []string {
	vistos := map[string]bool{}
	var out []string
	// Los mismos sitios que mira RulepackDir, para que "instaladas: ..." no
	// contradiga a la resolución.
	dirs := []string{filepath.Join(repoRoot, "rulepacks")}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		dirs = append(dirs, filepath.Join(dir, "rulepacks"), filepath.Join(filepath.Dir(dir), "rulepacks"))
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		dirs = append(dirs, filepath.Join(base, "CodeGuard", "rulepacks"))
	}
	for _, d := range dirs {
		entradas, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entradas {
			if e.IsDir() && !vistos[e.Name()] {
				vistos[e.Name()] = true
				out = append(out, e.Name())
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return masNuevo(out[i], out[j]) })
	return out
}

func masNuevo(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			if na != nb {
				return na > nb
			}
			continue
		}
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return len(pa) > len(pb)
}

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
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	req, err := ipc.ReadRequest(conn)
	if err != nil {
		log.Println("petición inválida:", err)
		return
	}
	// Comandos que no son análisis (los manda la CLI para que la UI actúe).
	if req.Command != "" {
		if s.OnCommand != nil {
			s.OnCommand(req.Command, req)
		}
		_ = ipc.WriteResponse(conn, &ipc.Response{RunID: req.RunID, Verdict: "ok"}) // ack de comando; si el pipe se cerró, no hay nada que hacer
		return
	}
	if s.OnRequest != nil {
		s.OnRequest(req)
	}
	go RememberRepo(req.RepoRoot) // para precalentar en el próximo arranque
	resp := s.Analyze(ctx, req)
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
				// El hook persiste el run justo después de recibir la respuesta;
				// esta espera evita actualizar un run que aún no existe.
				time.Sleep(2 * time.Second)
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
		demoted, _ = s.Shadow.Store.DemotedRules(req.RepoID, 5, 0.20)
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
		Suppressions: baseline.Load(req.RepoRoot),
		DemotedRules: demoted,
		Progreso:     progreso,
	})
	if err != nil {
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
