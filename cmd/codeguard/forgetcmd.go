package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"codeguard/internal/gitdiff"
	"codeguard/internal/registry"
)

func forgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget [ruta]",
		Short: "Quita un proyecto de la lista del agente (no toca el repo)",
		Long: "Deja de mostrar un proyecto en el panel y en el explorador.\n\n" +
			"No desinstala nada ni toca el repositorio: los hooks siguen donde estén. " +
			"Para desenrolarlo del todo usa `git config --unset core.hooksPath` y borra " +
			".githooks/ y .codeguard/.\n\n" +
			"Un proyecto cuya carpeta ya no existe se olvida solo; esto es para los que " +
			"siguen en disco.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruta := ""
			if len(args) == 1 {
				ruta = args[0]
			} else {
				raiz, err := gitdiff.RepoRoot(".")
				if err != nil {
					return fmt.Errorf("no estás dentro de un repo git: pasa la ruta como argumento")
				}
				ruta = raiz
			}
			abs, err := filepath.Abs(ruta)
			if err != nil {
				abs = ruta
			}
			if registry.Remove(abs) {
				fmt.Printf("%s ya no aparece en el panel\n", filepath.Base(abs))
				return nil
			}
			fmt.Fprintf(os.Stderr, "%s no estaba en la lista\n", abs)
			return nil
		},
	}
}
