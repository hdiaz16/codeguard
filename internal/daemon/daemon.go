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
	"time"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	gvengine "codeguard/internal/engines/govulncheck"
	"codeguard/internal/engines/linters"
	sgengine "codeguard/internal/engines/semgrep"
	sqengine "codeguard/internal/engines/squawk"
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
	OnCommand func(cmd, repoRoot string)
	OnResult  OnResult
	// Shadow, si no es nil, corre las etapas 3-6 (LLM en sombra) DESPUÉS de
	// responder al hook — nunca en el camino del commit.
	Shadow *shadow.Runner
}

// Engines arma la lista de motores de la etapa 2. Compartida con `codeguard ci`.
func Engines(cfg *config.Config, inCI bool) []engines.Engine {
	var migGlobs []string
	var migDialecto string
	if cfg != nil {
		migGlobs = cfg.Paths.Migrations
		migDialecto = cfg.Paths.DialectoMigraciones()
	}
	return []engines.Engine{
		&sgengine.Engine{},
		&sqengine.Engine{MigrationGlobs: migGlobs, Dialect: migDialecto},
		// Política §7: CVE crítico advierte en local, bloquea en CI.
		&tvengine.Engine{BlockCritical: inCI, SkipDBUpdate: !inCI},
		// Alcanzabilidad: trivy dice "el CVE está en tu go.sum"; govulncheck
		// demuestra si el código lo llama. Misma política local/CI que trivy,
		// y en el hook sólo corre cuando cambian las dependencias — recorre el
		// módulo entero y el presupuesto del hook no está para eso.
		&gvengine.Engine{BlockReachable: inCI, SoloManifiestos: !inCI},
		linters.GoFmt{},
		linters.GoVet{},
		linters.Ruff{},
		linters.Tsc{},
		linters.DotnetFormat{},
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// RulepackDir resuelve el rulepack pinneado: primero vendoreado en el repo,
// después junto al binario.
func RulepackDir(repoRoot, version string) string {
	local := filepath.Join(repoRoot, "rulepacks", version)
	if _, err := os.Stat(local); err == nil {
		return local
	}
	if exe, err := os.Executable(); err == nil {
		alt := filepath.Join(filepath.Dir(exe), "rulepacks", version)
		if _, err := os.Stat(alt); err == nil {
			return alt
		}
	}
	return local
}

// RulepacksInstalados lista las versiones disponibles junto al binario y
// vendoreadas en el repo, ordenadas de más nueva a más vieja. Los nombres son
// fechas (2026.08.2), así que el orden lexicográfico inverso basta salvo por
// el número final: se compara por partes para que .10 no quede antes que .9.
func RulepacksInstalados(repoRoot string) []string {
	vistos := map[string]bool{}
	var out []string
	dirs := []string{filepath.Join(repoRoot, "rulepacks")}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "rulepacks"))
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
			s.OnCommand(req.Command, req.RepoRoot)
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
}

// Analyze corre la etapa 2 para una petición del hook.
func (s *Server) Analyze(ctx context.Context, req *ipc.Request) *ipc.Response {
	resp := &ipc.Response{RunID: req.RunID, Verdict: "pass", CIParity: true, Degraded: []string{}}
	start := time.Now()
	defer func() { resp.ElapsedMs = time.Since(start).Milliseconds() }()

	cfg, err := config.Load(req.RepoRoot)
	if err != nil || cfg == nil {
		resp.Verdict = "skipped"
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
			log.Printf("paridad rota en %s: config %s≠%s, rulepack %s≠%s",
				filepath.Base(req.RepoRoot), short(cfg.Hash), short(req.ConfigHash),
				cfg.Rulepack, req.RulepackVersion)
		}
	}
	rulepack := RulepackDir(req.RepoRoot, cfg.Rulepack)
	if _, err := os.Stat(rulepack); err != nil {
		resp.CIParity = false
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
	if s.Shadow != nil && s.Shadow.Store != nil {
		demoted, _ = s.Shadow.Store.DemotedRules(req.RepoID, 5, 0.20)
	}
	res, err := pipeline.Run(ctx, pipeline.Options{
		Config:       cfg,
		Diff:         &gitdiff.Diff{Files: req.StagedFiles, Unified: req.DiffUnified},
		Secrets:      nil, // ya corrió en el hook
		Engines:      Engines(cfg, false),
		Rulepack:     rulepack,
		Timeout:      deadline,
		Suppressions: baseline.Load(req.RepoRoot),
		DemotedRules: demoted,
	})
	if err != nil {
		resp.Degraded = append(resp.Degraded, fmt.Sprintf("pipeline:%v", err))
		return resp
	}
	resp.Verdict = string(res.Verdict)
	resp.BlockingFindings = res.BlockingFindings
	resp.AdvisoryFindings = res.AdvisoryFindings
	resp.Suppressed = res.Suppressed
	resp.Degraded = append(resp.Degraded, res.Degraded...)
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
