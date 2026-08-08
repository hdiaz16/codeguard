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
	"time"

	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/engines/linters"
	sgengine "codeguard/internal/engines/semgrep"
	sqengine "codeguard/internal/engines/squawk"
	tvengine "codeguard/internal/engines/trivy"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/store"
)

// OnResult permite a la UI (F2.4) reaccionar a cada análisis terminado.
type OnResult func(req *ipc.Request, resp *ipc.Response)

type Server struct {
	// OnRequest se dispara al entrar una petición (estado working en la UI).
	OnRequest func(req *ipc.Request)
	OnResult  OnResult
}

// Engines arma la lista de motores de la etapa 2. Compartida con `codeguard ci`.
func Engines(cfg *config.Config, inCI bool) []engines.Engine {
	var migGlobs []string
	if cfg != nil {
		migGlobs = cfg.Paths.Migrations
	}
	return []engines.Engine{
		&sgengine.Engine{},
		&sqengine.Engine{MigrationGlobs: migGlobs},
		// Política §7: CVE crítico advierte en local, bloquea en CI.
		&tvengine.Engine{BlockCritical: inCI, SkipDBUpdate: !inCI},
		linters.GoFmt{},
		linters.GoVet{},
		linters.Ruff{},
		linters.Tsc{},
		linters.DotnetFormat{},
	}
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

func (s *Server) Serve(ctx context.Context) error {
	l, err := ipc.Listen()
	if err != nil {
		return err
	}
	defer l.Close()
	log.Println("daemon escuchando en el pipe del usuario")

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
	if s.OnRequest != nil {
		s.OnRequest(req)
	}
	resp := s.Analyze(ctx, req)
	if err := ipc.WriteResponse(conn, resp); err != nil {
		log.Println("no se pudo responder:", err)
	}
	if s.OnResult != nil {
		s.OnResult(req, resp)
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
	// ci_parity §8: rulepack y config del daemon deben coincidir con los del hook.
	if cfg.Hash != req.ConfigHash || cfg.Rulepack != req.RulepackVersion {
		resp.CIParity = false
	}
	rulepack := RulepackDir(req.RepoRoot, cfg.Rulepack)
	if _, err := os.Stat(rulepack); err != nil {
		resp.CIParity = false
	}

	deadline := time.Duration(req.DeadlineMs) * time.Millisecond
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	res, err := pipeline.Run(ctx, pipeline.Options{
		Config:   cfg,
		Diff:     &gitdiff.Diff{Files: req.StagedFiles, Unified: req.DiffUnified},
		Secrets:  nil, // ya corrió en el hook
		Engines:  Engines(cfg, false),
		Rulepack: rulepack,
		Timeout:  deadline,
	})
	if err != nil {
		resp.Degraded = append(resp.Degraded, fmt.Sprintf("pipeline:%v", err))
		return resp
	}
	resp.Verdict = string(res.Verdict)
	resp.BlockingFindings = res.BlockingFindings
	resp.AdvisoryFindings = res.AdvisoryFindings
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
