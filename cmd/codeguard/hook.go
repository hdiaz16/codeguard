package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines"
	glengine "codeguard/internal/engines/gitleaks"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/store"
)

const hookDeadline = 5 * time.Second

func hookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Puntos de entrada de los hooks de git (los invocan los shims de .githooks)",
		Hidden: true,
	}
	cmd.AddCommand(preCommitCmd(), prepareCommitMsgCmd(), postCommitCmd())
	return cmd
}

// lastRunFile guarda el run id entre pre-commit y prepare-commit-msg/post-commit.
func lastRunFile(repoRoot string) string {
	return filepath.Join(repoRoot, ".git", "codeguard-lastrun")
}

func preCommitCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "pre-commit",
		RunE: func(cmd *cobra.Command, args []string) error { return runPreCommit() },
	}
}

// P4: el hook nunca falla por sí mismo — cualquier error interno sale 0,
// salvo la compuerta de secretos (fail-closed).
func runPreCommit() error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "CodeGuard  error interno (se permite el commit):", r)
			os.Exit(0)
		}
	}()

	repoRoot, err := gitdiff.RepoRoot(".")
	if err != nil {
		return nil // fuera de un repo: nada que hacer
	}
	cfg, err := config.Load(repoRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CodeGuard  config ilegible (se permite el commit):", err)
		return nil
	}
	if cfg == nil {
		return nil // repo no enrolado
	}
	diff, err := gitdiff.Staged(repoRoot)
	if err != nil || len(diff.Files) == 0 {
		return nil
	}

	start := time.Now()
	progress := func(s string) { fmt.Fprintf(os.Stderr, "CodeGuard  %s\n", s) }

	// ── Etapa 1: secretos, en este proceso, fail-closed ──
	secretsEng := &glengine.Engine{Mode: "staged"}
	secretFindings, err := secretsEng.Run(context.Background(), engines.Input{RepoRoot: repoRoot, Files: diff.Files})
	if err != nil {
		if errors.Is(err, glengine.ErrUnavailable) {
			progress("BLOQUEADO: la compuerta de secretos no pudo correr (fail-closed)")
			progress("repara con: codeguard repair   —   detalle: " + err.Error())
			os.Exit(1)
		}
		progress("secretos ✗ (error no fatal: " + err.Error() + ")")
	}
	if len(secretFindings) > 0 {
		progress(fmt.Sprintf("secretos ✗  BLOQUEADO: %d secreto(s) en el diff — NADA salió a la red", len(secretFindings)))
		for _, f := range secretFindings {
			progress(fmt.Sprintf("  %s:%d  %s", f.File, f.Line, f.Message))
		}
		progress("rota la credencial PRIMERO; borrarla del historial no la invalida")
		os.Exit(1)
	}
	progress("secretos ✓")

	// ── Run id para el trailer (prepare-commit-msg) ──
	runID := store.NewULID()
	os.WriteFile(lastRunFile(repoRoot), []byte(runID), 0o644)

	// ── Señal de código generado por IA (RADAR): variables de entorno de la
	// herramienta que invoca el commit. Sube el riesgo (+20) y se etiqueta. ──
	aiGenerated := false
	for _, v := range []string{"CLAUDECODE", "CLAUDE_CODE", "CURSOR_AGENT", "GITHUB_COPILOT_AGENT", "AIDER_MODEL", "GEMINI_CLI"} {
		if os.Getenv(v) != "" {
			aiGenerated = true
			break
		}
	}

	// ── Etapa 2: en el daemon; sin daemon, local degradado ──
	req := &ipc.Request{
		RunID:           runID,
		RepoRoot:        repoRoot,
		RepoID:          store.CanonicalRepoID(gitRemote(repoRoot)),
		Branch:          gitBranch(repoRoot),
		StagedFiles:     diff.Files,
		DiffUnified:     diff.Unified,
		RulepackVersion: cfg.Rulepack,
		ConfigHash:      cfg.Hash,
		AIGenerated:     aiGenerated,
		DeadlineMs:      int(hookDeadline.Milliseconds()),
	}
	var res *pipeline.Result
	degraded := []string{}
	resp, err := ipc.Call(req, hookDeadline)
	if err == nil {
		res = &pipeline.Result{
			Verdict:          pipeline.Verdict(resp.Verdict),
			BlockingFindings: resp.BlockingFindings,
			AdvisoryFindings: resp.AdvisoryFindings,
			Degraded:         resp.Degraded,
			Findings:         resp.Findings,
			ElapsedMs:        resp.ElapsedMs,
		}
		if !resp.CIParity {
			progress("aviso: tu rulepack/config no coincide — no puedo garantizar que pase el CI")
		}
	} else {
		degraded = append(degraded, "daemon:offline")
		ctx, cancel := context.WithTimeout(context.Background(), hookDeadline)
		defer cancel()
		res, err = pipeline.Run(ctx, pipeline.Options{
			Config:       cfg,
			Diff:         diff,
			Secrets:      nil, // ya corrió arriba
			Engines:      daemon.Engines(cfg, false),
			Rulepack:     daemon.RulepackDir(repoRoot, cfg.Rulepack),
			Timeout:      hookDeadline,
			Suppressions: baseline.Load(repoRoot),
		})
		if err != nil {
			progress("análisis local falló (se permite el commit): " + err.Error())
			return nil
		}
		res.Degraded = append(res.Degraded, degraded...)
	}

	// ── Veredicto en la terminal (§12.1.1) ──
	gates := "formato/lint/tipos/reglas/migraciones"
	if res.BlockingFindings > 0 {
		progress(gates + " ✗")
		for _, f := range res.Findings {
			if f.Blocking {
				progress(fmt.Sprintf("  [%s] %s:%d  %s", f.RuleKey, f.File, f.Line, f.Message))
			}
		}
		progress(fmt.Sprintf("BLOQUEADO: %d problema(s) que el CI también rechazaría  (%.1f s)",
			res.BlockingFindings, time.Since(start).Seconds()))
	} else {
		progress(fmt.Sprintf("%s ✓   (%.1f s)", gates, time.Since(start).Seconds()))
		if res.AdvisoryFindings > 0 {
			progress(fmt.Sprintf("listo — commit permitido; %d sugerencia(s) en el panel", res.AdvisoryFindings))
		} else {
			progress("listo — commit permitido")
		}
	}
	if len(res.Degraded) > 0 {
		progress("capas no revisadas: " + strings.Join(res.Degraded, ", "))
	}

	if err := persistRun(repoRoot, cfg, res, len(diff.Files), false, runID); err != nil {
		fmt.Fprintln(os.Stderr, "CodeGuard  aviso: no se pudo registrar el run:", err)
	}
	if res.BlockingFindings > 0 {
		// Sin run id pendiente: si el dev reintenta con --no-verify,
		// prepare-commit-msg (que --no-verify NO salta) no debe pegar un
		// trailer viejo que camufle el bypass.
		os.Remove(lastRunFile(repoRoot))
		os.Exit(1)
	}
	return nil
}

func prepareCommitMsgCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "prepare-commit-msg <archivo-mensaje>",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return nil
			}
			runID, err := os.ReadFile(lastRunFile(repoRoot))
			if err != nil {
				return nil // no hubo análisis (repo no enrolado, diff vacío...)
			}
			msgFile := args[0]
			msg, err := os.ReadFile(msgFile)
			if err != nil {
				return nil
			}
			if strings.Contains(string(msg), "Codeguard-Run-Id:") {
				return nil
			}
			trailer := fmt.Sprintf("\nCodeguard-Run-Id: %s\n", strings.TrimSpace(string(runID)))
			return os.WriteFile(msgFile, append(msg, []byte(trailer)...), 0o644)
		},
	}
}

func postCommitCmd() *cobra.Command {
	return &cobra.Command{
		Use: "post-commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return nil
			}
			defer os.Remove(lastRunFile(repoRoot))
			cfg, err := config.Load(repoRoot)
			if err != nil || cfg == nil {
				return nil
			}
			out, err := exec.Command("git", "-C", repoRoot, "log", "-1", "--format=%B").Output()
			if err != nil {
				return nil
			}
			if strings.Contains(string(out), "Codeguard-Run-Id:") {
				return nil // commit analizado, todo en orden
			}
			// --no-verify se saltó pre-commit y commit-msg, pero no a nosotros:
			// se registra el bypass (§7.1) — señal de producto, no castigo.
			return persistBypass(repoRoot, cfg)
		},
	}
}

func persistBypass(repoRoot string, cfg *config.Config) error {
	res := &pipeline.Result{Verdict: pipeline.Skipped, Degraded: []string{}, Findings: []finding.Finding{}}
	return persistWith(repoRoot, cfg, res, 0, true)
}
