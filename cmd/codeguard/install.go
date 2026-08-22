package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"codeguard/internal/gitdiff"
	"codeguard/internal/registry"
)

// Los shims van con LF y shebang sh: Git for Windows los ejecuta vía bash
// (MSYS2). CRLF produce "bad interpreter" (§4.1).
const shimTemplate = `#!/bin/sh
# instalado por codeguard install — no editar a mano
exec "$(git config codeguard.binpath)/%s" hook %s "$@"
`

// dirGanchos es NUESTRO directorio de ganchos, el que apunta core.hooksPath.
// Está aquí y no en tres literales sueltos porque ahora hay que compararlo
// contra lo que el repo ya tuviera: escribirlo y reconocerlo tienen que ser el
// mismo valor siempre.
const dirGanchos = ".githooks"

// banderaSustituir es el permiso explícito para apagar los ganchos de otro
// gestor. Se llama así y no `--force` por dos razones medidas en este repo:
// `init` ya tiene un `--force` que significa otra cosa (regenerar la config), y
// un nombre genérico se teclea de memoria. El nombre dice el objeto —los
// ganchos— y el verbo destructivo: sustituir no es añadir.
const banderaSustituir = "sustituir-hooks"

func installCmd() *cobra.Command {
	var sustituir bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Instala los hooks de CodeGuard en el repo actual (core.hooksPath)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return fmt.Errorf("no estás dentro de un repo git: %w", err)
			}
			// Antes de escribir NADA. Si el repo ya tiene un gestor de ganchos,
			// apagarlo es una decisión de quien conoce el repo, y negarse tiene
			// que dejarlo exactamente como estaba.
			ajeno, err := hooksPathAjeno(repoRoot)
			if err != nil {
				return err
			}
			if ajeno != nil {
				if !sustituir {
					return errors.New(ajeno.explicar("install"))
				}
				fmt.Fprint(cmd.OutOrStdout(), ajeno.avisoSustitucion())
			}
			hooksDir := filepath.Join(repoRoot, dirGanchos)
			if err := os.MkdirAll(hooksDir, 0o755); err != nil {
				return err
			}
			// El binario se resuelve ANTES de escribir nada: si no se sabe a qué
			// invocar, no se dejan ganchos a medio instalar que fallen en cada
			// commit. Y el shim lleva el nombre REAL del ejecutable en vez del
			// literal codeguard.exe: con el literal, el binario tiene que
			// llamarse exactamente así o los ganchos no encuentran nada (los
			// tests de extremo a extremo ya cargan con esa restricción).
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			binario := filepath.Base(exe)
			for _, hook := range []string{"pre-commit", "prepare-commit-msg", "post-commit"} {
				shim := fmt.Sprintf(shimTemplate, binario, hook)
				path := filepath.Join(hooksDir, hook)
				// WriteFile respeta los LF del template; nunca CRLF.
				if err := os.WriteFile(path, []byte(shim), 0o755); err != nil {
					return err
				}
			}

			// .gitattributes: los shims siempre LF, en cualquier máquina (§4.1).
			gaPath := filepath.Join(repoRoot, ".gitattributes")
			const gaRule = dirGanchos + "/* text eol=lf"
			ga, _ := os.ReadFile(gaPath)
			if !strings.Contains(string(ga), gaRule) {
				f, err := os.OpenFile(gaPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					return err
				}
				// Si el .gitattributes que ya había no termina en salto de
				// línea (típico si se editó a mano), anexar directo pegaría la
				// regla al final de esa última línea y dejaría las dos rotas.
				regla := gaRule
				if len(ga) > 0 && ga[len(ga)-1] != '\n' {
					regla = "\n" + gaRule
				}
				// Los errores de escritura y de cierre se comprueban: si esta
				// regla no llega al .gitattributes, los shims se checan con
				// CRLF en otra máquina y git falla con "bad interpreter".
				// Perderla en silencio rompe el enrolamiento de quien clone.
				_, werr := fmt.Fprintf(f, "%s\n", regla)
				if cerr := f.Close(); werr != nil || cerr != nil {
					return fmt.Errorf("no se pudo escribir la regla de fin de línea en %s: %w",
						gaPath, errors.Join(werr, cerr))
				}
			}

			binDir := filepath.ToSlash(filepath.Dir(exe))
			for _, kv := range [][2]string{
				{"core.hooksPath", dirGanchos},
				{"codeguard.binpath", binDir},
			} {
				if out, err := gitCmd("-C", repoRoot, "config", kv[0], kv[1]).CombinedOutput(); err != nil {
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
	cmd.Flags().BoolVar(&sustituir, banderaSustituir, false,
		"instalar aunque el repo use otro gestor de ganchos (husky, lefthook…): los suyos dejan de correr")
	return cmd
}

