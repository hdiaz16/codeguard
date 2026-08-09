package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/gitdiff"
	"codeguard/internal/registry"
)

// codeguard status: verificación de enrolamiento. Responde de un vistazo
// "¿este repo (o todos) tienen CodeGuard bien puesto?" — y qué le falta.

type chequeo struct {
	ok      bool
	detalle string
}

func statusCmd() *cobra.Command {
	var todos bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Verifica el enrolamiento: config, hooks, baseline, rulepack y paridad",
		RunE: func(cmd *cobra.Command, args []string) error {
			var roots []string
			if todos {
				for _, r := range registry.Load() {
					roots = append(roots, r.Root)
				}
				if len(roots) == 0 {
					fmt.Println("no hay proyectos registrados todavía (corre `codeguard init` en uno)")
					return nil
				}
			} else {
				root, err := gitdiff.RepoRoot(".")
				if err != nil {
					return fmt.Errorf("no estás dentro de un repo git (usa --todos): %w", err)
				}
				roots = []string{root}
			}

			problemas := 0
			for i, root := range roots {
				if i > 0 {
					fmt.Println()
				}
				if n := revisarRepo(root); n > 0 {
					problemas += n
				}
			}
			fmt.Println()
			if problemas == 0 {
				fmt.Println("✅ todo en orden")
			} else {
				fmt.Printf("⚠️  %d punto(s) por atender — arriba está el comando de cada uno\n", problemas)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&todos, "todos", false, "revisar todos los proyectos registrados en esta máquina")
	return cmd
}

func revisarRepo(root string) int {
	fmt.Printf("── %s\n   %s\n", filepath.Base(root), filepath.ToSlash(root))
	if _, err := os.Stat(root); err != nil {
		fmt.Println("   ✗ la carpeta ya no existe")
		return 1
	}

	checks := map[string]chequeo{}
	orden := []string{"config", "hooks", "hooksPath", "binpath", "rulepack", "baseline", "informe"}

	// 1. config del repo
	cfg, err := config.Load(root)
	switch {
	case err != nil:
		checks["config"] = chequeo{false, "ilegible: " + err.Error() + " → revisa .codeguard/config.yaml"}
	case cfg == nil:
		checks["config"] = chequeo{false, "NO enrolado → corre `codeguard init`"}
	default:
		checks["config"] = chequeo{true, fmt.Sprintf("rulepack %s · %s", cfg.Rulepack, strings.Join(cfg.Languages, ", "))}
	}

	// 2. los tres hooks
	faltan := []string{}
	for _, h := range []string{"pre-commit", "prepare-commit-msg", "post-commit"} {
		if _, err := os.Stat(filepath.Join(root, ".githooks", h)); err != nil {
			faltan = append(faltan, h)
		}
	}
	if len(faltan) == 0 {
		checks["hooks"] = chequeo{true, "los 3 presentes"}
	} else {
		checks["hooks"] = chequeo{false, "faltan " + strings.Join(faltan, ", ") + " → `codeguard install`"}
	}

	// 3. git apunta a ellos
	if out, err := exec.Command("git", "-C", root, "config", "core.hooksPath").Output(); err == nil &&
		strings.TrimSpace(string(out)) == ".githooks" {
		checks["hooksPath"] = chequeo{true, "core.hooksPath = .githooks"}
	} else {
		checks["hooksPath"] = chequeo{false, "core.hooksPath sin configurar → `codeguard install`"}
	}

	// 4. el shim sabe dónde está el binario
	if out, err := exec.Command("git", "-C", root, "config", "codeguard.binpath").Output(); err == nil {
		bin := filepath.Join(strings.TrimSpace(string(out)), "codeguard.exe")
		if _, err := os.Stat(bin); err == nil {
			checks["binpath"] = chequeo{true, filepath.ToSlash(filepath.Dir(bin))}
		} else {
			checks["binpath"] = chequeo{false, "apunta a un binario inexistente → `codeguard install`"}
		}
	} else {
		checks["binpath"] = chequeo{false, "codeguard.binpath sin configurar → `codeguard install`"}
	}

	// 5. rulepack resoluble (esto es la PARIDAD con el CI)
	if cfg != nil {
		dir := daemon.RulepackDir(root, cfg.Rulepack)
		if _, err := os.Stat(dir); err == nil {
			donde := "junto al binario"
			if strings.HasPrefix(filepath.ToSlash(dir), filepath.ToSlash(root)) {
				donde = "vendoreado en el repo"
			}
			checks["rulepack"] = chequeo{true, cfg.Rulepack + " (" + donde + ")"}
		} else {
			checks["rulepack"] = chequeo{false,
				"no encuentro el rulepack " + cfg.Rulepack + " → sin paridad con el CI; reinstala o vendoréalo"}
		}
	}

	// 6. baseline
	if n := len(baseline.Load(root)); n > 0 {
		checks["baseline"] = chequeo{true, fmt.Sprintf("%d hallazgos preexistentes suprimidos", n)}
	} else if cfg != nil {
		checks["baseline"] = chequeo{false, "sin baseline → lo viejo bloqueará; corre `codeguard baseline`"}
	}

	// 7. informe para agentes
	if raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(reportFile))); err == nil {
		if strings.Contains(string(raw), "✅ COMPLETADO") {
			checks["informe"] = chequeo{true, "HALLAZGOS.md sin pendientes"}
		} else {
			checks["informe"] = chequeo{false, "HALLAZGOS.md con pendientes → pásaselo a tu agente"}
		}
	} else {
		checks["informe"] = chequeo{true, "sin informe (genera uno con `codeguard report`)"}
	}

	fallos := 0
	for _, k := range orden {
		c, existe := checks[k]
		if !existe {
			continue
		}
		mark := "✓"
		if !c.ok {
			mark = "✗"
			fallos++
		}
		fmt.Printf("   %s %-10s %s\n", mark, k, c.detalle)
	}
	return fallos
}
