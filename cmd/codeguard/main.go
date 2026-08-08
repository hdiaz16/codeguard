// codeguard — binario único (ADR-03): el mismo que corre en local y en CI.
// Fase 1: subcomando `ci` con el pipeline determinista y salida SARIF.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	glengine "codeguard/internal/engines/gitleaks"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
	"codeguard/internal/sarif"
	"codeguard/internal/store"
)

var version = "0.1.0-fase1"

func main() {
	root := &cobra.Command{
		Use:           "codeguard",
		Short:         "Análisis de código pre-commit con paridad hacia el CI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(ciCmd(), versionCmd(), hookCmd(), installCmd(), repairCmd(), daemonCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "codeguard:", err)
		os.Exit(2)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Versión del binario",
		Run: func(*cobra.Command, []string) {
			fmt.Println("codeguard", version)
		},
	}
}

func ciCmd() *cobra.Command {
	var base, head, format, out, repoDir string
	var shadow bool

	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Analiza el rango base..head (modo CI / sombra)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(repoDir)
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil {
				return err
			}

			var diff *gitdiff.Diff
			if cfg != nil {
				if diff, err = gitdiff.Range(repoRoot, base, head); err != nil {
					return err
				}
			} else {
				diff = &gitdiff.Diff{}
			}

			rulepack := ""
			if cfg != nil {
				rulepack = filepath.Join(repoRoot, "rulepacks", cfg.Rulepack)
				if _, statErr := os.Stat(rulepack); statErr != nil {
					// rulepack distribuido junto al binario (repos que no vendorean reglas)
					if exe, exeErr := os.Executable(); exeErr == nil {
						alt := filepath.Join(filepath.Dir(exe), "rulepacks", cfg.Rulepack)
						if _, altErr := os.Stat(alt); altErr == nil {
							rulepack = alt
						}
					}
				}
			}

			inCI := os.Getenv("GITHUB_ACTIONS") == "true"
			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:   cfg,
				Diff:     diff,
				Secrets:  &glengine.Engine{Mode: "range", Base: base, Head: head},
				Engines:  daemon.Engines(cfg, inCI),
				Rulepack: rulepack,
				Timeout:  5 * time.Minute,
			})
			if err != nil {
				return err
			}

			printSummary(res)

			if format == "sarif" && out != "" {
				if err := sarif.Write(out, version, res.Findings); err != nil {
					return fmt.Errorf("escribiendo SARIF: %w", err)
				}
				fmt.Printf("SARIF: %s (%d resultados)\n", out, len(res.Findings))
			}

			if cfg != nil {
				if err := persist(repoRoot, cfg, res, len(diff.Files)); err != nil {
					// La telemetría nunca tumba el análisis (P4).
					fmt.Fprintln(os.Stderr, "aviso: no se pudo persistir el run:", err)
				}
			}

			// Modo sombra (fase 1): registra todo, nunca falla el job.
			if !shadow && res.Verdict == pipeline.Block {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "commit base")
	cmd.Flags().StringVar(&head, "head", "HEAD", "commit head")
	cmd.Flags().StringVar(&format, "format", "sarif", "formato de salida (sarif)")
	cmd.Flags().StringVar(&out, "out", "", "archivo de salida")
	cmd.Flags().StringVar(&repoDir, "repo", ".", "directorio dentro del repo")
	cmd.Flags().BoolVar(&shadow, "shadow", false, "modo sombra: registra pero nunca falla el job")
	cmd.MarkFlagRequired("base")
	return cmd
}

func printSummary(res *pipeline.Result) {
	switch res.Verdict {
	case pipeline.Skipped:
		fmt.Println("codeguard: análisis omitido —", res.Reason)
		return
	case pipeline.Block:
		if res.Reason != "" {
			fmt.Println("codeguard: BLOQUEADO —", res.Reason)
		} else {
			fmt.Printf("codeguard: BLOQUEADO — %d problema(s) bloqueante(s), %d aviso(s)\n",
				res.BlockingFindings, res.AdvisoryFindings)
		}
	default:
		fmt.Printf("codeguard: OK — 0 bloqueantes, %d aviso(s)\n", res.AdvisoryFindings)
	}
	if len(res.Degraded) > 0 {
		fmt.Println("capas degradadas:", strings.Join(res.Degraded, ", "))
	}
	for _, f := range res.Findings {
		mark := "aviso "
		if f.Blocking {
			mark = "BLOQUEA"
		}
		fmt.Printf("  [%s] %s %s:%d  %s\n", mark, f.RuleKey, f.File, f.Line, f.Message)
	}
	_ = finding.Finding{}
}

func persist(repoRoot string, cfg *config.Config, res *pipeline.Result, filesChanged int) error {
	return persistWith(repoRoot, cfg, res, filesChanged, false)
}

func persistWith(repoRoot string, cfg *config.Config, res *pipeline.Result, filesChanged int, bypassed bool) error {
	dbDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard")
	if dbDir == filepath.Join("", "codeguard") { // sin LOCALAPPDATA (runner Linux)
		dbDir = filepath.Join(os.TempDir(), "codeguard")
	}
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dbDir, "codeguard.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	remote := gitRemote(repoRoot)
	repoID := store.CanonicalRepoID(remote)
	if remote == "" {
		repoID = store.CanonicalRepoID("local/" + filepath.Base(repoRoot))
	}
	if err := st.UpsertRepo(repoID, remote, filepath.Base(repoRoot)); err != nil {
		return err
	}
	env := "local"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		env = "ci"
	}
	return st.SaveRun(store.RunMeta{
		RunID:       store.NewULID(),
		RepoID:      repoID,
		Branch:      gitBranch(repoRoot),
		RulepackVer: cfg.Rulepack,
		ConfigHash:  cfg.Hash,
		Environment: env,
		Bypassed:    bypassed,
	}, res, filesChanged)
}

func gitRemote(repoRoot string) string {
	out, err := exec.Command("git", "-C", repoRoot, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitBranch(repoRoot string) string {
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
