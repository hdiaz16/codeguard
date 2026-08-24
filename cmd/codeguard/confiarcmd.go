package main

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/confianza"
	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
)

// codeguard confiar: el opt-in TOFU de la clase config-ejecutable (W4, Q3).
// Enseña QUÉ config o binarios del repo se van a confiar ANTES de confiarlos
// —como baseline enseña la deuda que acepta— y registra el digest FUERA del
// repo (%LOCALAPPDATA%), para que la confianza no viaje en el propio repo que
// pide confiar. Si esa config cambia después, el digest cambia y vuelve a
// pedirse: TOFU, no un cheque en blanco.
func confiarCmd() *cobra.Command {
	var si, revocar bool
	cmd := &cobra.Command{
		Use:   "confiar",
		Short: "Confía en la configuración ejecutable de este repo (eslint.config.js, targets de MSBuild, plugins de mypy)",
		Long: "Los motores que ejecutan configuración o binarios del repo analizado " +
			"(eslint, tsc, mypy, dotnet-build) NO corren hasta que confías en ellos: " +
			"un repo hostil puede esconder código en esa configuración y tocaría tu " +
			"máquina fuera del proyecto. Este comando registra tu confianza para ESTE " +
			"repo; si la configuración cambia, se vuelve a preguntar.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil {
				return err
			}
			if cfg == nil {
				return fmt.Errorf("el repo no está enrolado: falta %s", config.RelPath)
			}

			if revocar {
				if err := confianza.Revocar(repoRoot); err != nil {
					return fmt.Errorf("no se pudo revocar la confianza: %w", err)
				}
				fmt.Println("confianza revocada: los motores de config-ejecutable volverán a degradarse en este repo")
				return nil
			}

			// La confianza es del repo entero (Detectar lista los rastreados).
			arts := confianza.Detectar(repoRoot)
			if len(arts) == 0 {
				fmt.Println("este repo no trae configuración ejecutable: no hay nada que confiar,")
				fmt.Println("y los motores corren normal (ninguno ejecuta código del repo).")
				return nil
			}

			digest := confianza.Digest(arts)
			if confianza.Confiado(repoRoot, digest) {
				fmt.Println("ya confías en la configuración ejecutable actual de este repo. Nada que hacer.")
				return nil
			}

			// Se ENSEÑA lo que se va a confiar, como baseline enseña la deuda.
			fmt.Println("Vas a confiar en que CodeGuard EJECUTE esta configuración/binarios del repo:")
			for _, a := range arts {
				fmt.Printf("  [%s] %s\n", a.Clase, a.Ruta)
			}
			fmt.Println("\nUn repo hostil puede esconder código aquí que toque tu máquina fuera del proyecto.")
			fmt.Println("Confía SÓLO si reconoces este repo y su configuración.")

			if !si {
				fmt.Print("\n¿Confiar y dejar que estos motores corran en este repo? [s/N]: ")
				linea, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				resp := strings.TrimSpace(strings.ToLower(linea))
				if resp != "s" && resp != "si" && resp != "sí" {
					return fmt.Errorf("cancelado: la confianza NO se registró (los motores siguen degradados)")
				}
			}

			if err := confianza.Registrar(repoRoot, digest, time.Now().UTC().Format(time.RFC3339)); err != nil {
				return fmt.Errorf("no se pudo registrar la confianza: %w", err)
			}
			fmt.Println("\nconfianza registrada: eslint/tsc/mypy/dotnet-build ya corren en este repo.")
			fmt.Println("si su configuración cambia, se te preguntará de nuevo.")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&si, "si", "y", false, "confiar sin confirmación interactiva")
	cmd.Flags().BoolVar(&revocar, "revocar", false, "retirar la confianza de este repo")
	return cmd
}
