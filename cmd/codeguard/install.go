package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines/identidad"
	"codeguard/internal/gitdiff"
	"codeguard/internal/registry"
)

// Los shims van con LF y shebang sh: Git for Windows los ejecuta vía bash
// (MSYS2). CRLF produce "bad interpreter" (§4.1).
const shimTemplate = `#!/bin/sh
# instalado por codeguard install — no editar a mano
exec "$(git config codeguard.binpath)/codeguard.exe" hook %s "$@"
`

func installCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Instala los hooks de CodeGuard en el repo actual (core.hooksPath)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return fmt.Errorf("no estás dentro de un repo git: %w", err)
			}
			hooksDir := filepath.Join(repoRoot, ".githooks")
			if err := os.MkdirAll(hooksDir, 0o755); err != nil {
				return err
			}
			for _, hook := range []string{"pre-commit", "prepare-commit-msg", "post-commit"} {
				shim := fmt.Sprintf(shimTemplate, hook)
				path := filepath.Join(hooksDir, hook)
				// WriteFile respeta los LF del template; nunca CRLF.
				if err := os.WriteFile(path, []byte(shim), 0o755); err != nil {
					return err
				}
			}

			// .gitattributes: los shims siempre LF, en cualquier máquina (§4.1).
			gaPath := filepath.Join(repoRoot, ".gitattributes")
			const gaRule = ".githooks/* text eol=lf"
			ga, _ := os.ReadFile(gaPath)
			if !strings.Contains(string(ga), gaRule) {
				f, err := os.OpenFile(gaPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					return err
				}
				fmt.Fprintf(f, "%s\n", gaRule)
				f.Close()
			}

			exe, err := os.Executable()
			if err != nil {
				return err
			}
			binDir := filepath.ToSlash(filepath.Dir(exe))
			for _, kv := range [][2]string{
				{"core.hooksPath", ".githooks"},
				{"codeguard.binpath", binDir},
			} {
				if out, err := exec.Command("git", "-C", repoRoot, "config", kv[0], kv[1]).CombinedOutput(); err != nil {
					return fmt.Errorf("git config %s: %v: %s", kv[0], err, out)
				}
			}

			// Registrar el proyecto también aquí: el dev que recibe la config
			// por `git pull` solo corre `install`, nunca `init`.
			registry.Add(repoRoot, filepath.Base(repoRoot), "")

			fmt.Println("CodeGuard instalado en", repoRoot)
			fmt.Println("  hooks:   .githooks/{pre-commit, prepare-commit-msg, post-commit}")
			fmt.Println("  binario:", binDir)
			if _, err := os.Stat(filepath.Join(repoRoot, ".codeguard", "config.yaml")); err != nil {
				fmt.Println("  FALTA .codeguard/config.yaml — sin él el repo no está enrolado y el hook no hace nada")
			}
			return nil
		},
	}
}

// repararRulepack mueve el pin del repo a una versión instalada cuando la que
// tiene desapareció. Sin esto, retirar una versión dejaba repos analizando con
// cero reglas de la casa, y el único aviso era una línea de "capas no
// revisadas" que nadie lee.
func repararRulepack() error {
	raiz, err := gitdiff.RepoRoot(".")
	if err != nil {
		return nil // fuera de un repo no hay nada que reparar
	}
	cfg, err := config.Load(raiz)
	if err != nil || cfg == nil {
		return nil // repo no enrolado: es asunto de `codeguard init`
	}
	if _, err := os.Stat(daemon.RulepackDir(raiz, cfg.Rulepack)); err == nil {
		fmt.Printf("  ok    rulepack %s\n", cfg.Rulepack)
		return nil
	}

	disponibles := daemon.RulepacksInstalados(raiz)
	if len(disponibles) == 0 {
		return fmt.Errorf("FALTA rulepack %s y no hay ninguno instalado → reinstala CodeGuard", cfg.Rulepack)
	}
	nueva := disponibles[0]

	ruta := filepath.Join(raiz, ".codeguard", "config.yaml")
	raw, err := os.ReadFile(ruta)
	if err != nil {
		return fmt.Errorf("FALTA rulepack %s y no pude leer %s: %v", cfg.Rulepack, ruta, err)
	}
	re := regexp.MustCompile(`(?m)^rulepack:.*$`)
	if !re.Match(raw) {
		return fmt.Errorf("FALTA rulepack %s; añade a mano `rulepack: \"%s\"` en %s", cfg.Rulepack, nueva, ruta)
	}
	actualizado := re.ReplaceAll(raw, []byte(fmt.Sprintf(`rulepack: "%s"`, nueva)))
	if err := os.WriteFile(ruta, actualizado, 0o644); err != nil {
		return fmt.Errorf("no pude escribir %s: %v", ruta, err)
	}
	fmt.Printf("  ok    rulepack %s → %s (el %s ya no está instalado)\n", cfg.Rulepack, nueva, cfg.Rulepack)
	fmt.Println("        revisa la baseline: las reglas nuevas pueden marcar código preexistente")
	return nil
}

func repairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repair",
		Short: "Verifica y repara las dependencias del agente (gitleaks, semgrep...)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ok := true
			for _, tool := range []struct{ bin, hint string }{
				{"gitleaks", "go install github.com/zricethezav/gitleaks/v8@latest"},
				{"semgrep", "pip install semgrep"},
				{"squawk", "pip install squawk-cli"},
				{"ruff", "pip install ruff"},
			} {
				if _, err := exec.LookPath(tool.bin); err != nil {
					ok = false
					fmt.Printf("  FALTA %-9s → instala con: %s\n", tool.bin, tool.hint)
				} else {
					fmt.Printf("  ok    %s\n", tool.bin)
				}
			}
			if err := repararRulepack(); err != nil {
				ok = false
				fmt.Println("  " + err.Error())
			}
			// Identidad de los motores descargables: que estén no basta, tienen
			// que ser los que publicaron sus autores.
			for _, r := range identidad.Verificar(DirMotores()) {
				switch r.Estado {
				case identidad.Verificado:
					fmt.Printf("  ok    %s v%s (binario publicado)\n", r.Motor, r.Version)
				case identidad.Ausente:
					// Ya lo reporta el bloque de herramientas de arriba.
				default:
					ok = false
					fmt.Printf("  ALERTA %s: %s → revisa con `codeguard engines`\n", r.Motor, r.Detalle)
				}
			}
			if !ok {
				fmt.Println("\nsin gitleaks la compuerta de secretos es fail-closed y bloquea los commits")
				os.Exit(1)
			}
			fmt.Println("todo en orden")
			return nil
		},
	}
}
