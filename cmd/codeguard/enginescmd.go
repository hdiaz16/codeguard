package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"codeguard/internal/engines/identidad"
)

// DirMotores es donde el instalador deja los binarios descargables.
func DirMotores() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "CodeGuard", "engines")
}

func enginesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "engines",
		Short: "Verifica que los motores instalados sean los que publicaron sus autores",
		Long: "Compara el SHA-256 de cada motor descargable contra los hashes " +
			"publicados por sus autores en los checksums de cada release.\n\n" +
			"Los motores de Python (semgrep, squawk, ruff) no aparecen: los instala " +
			"pip contra PyPI con sus propias firmas, no los distribuimos nosotros.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := DirMotores()
			fmt.Println("motores en", dir)
			fmt.Println()

			problemas := 0
			for _, r := range identidad.Verificar(dir) {
				etiqueta := r.Motor
				if r.Critico {
					etiqueta += " (crítico)"
				}
				switch r.Estado {
				case identidad.Verificado:
					fmt.Printf("  ✓ %-20s v%s — coincide con el binario publicado\n", etiqueta, r.Version)
				case identidad.Ausente:
					fmt.Printf("  · %-20s no instalado\n", etiqueta)
				default:
					problemas++
					fmt.Printf("  ✗ %-20s %s\n", etiqueta, r.Detalle)
					if r.SHA256 != "" {
						fmt.Printf("      instalado: %s\n", r.SHA256)
						for _, v := range identidad.VersionesConocidas(r.Motor) {
							fmt.Printf("      esperado:  %s  (v%s)\n", v.SHA256Exe, v.Version)
						}
					}
				}
			}

			if problemas == 0 {
				fmt.Println("\ntodos los motores instalados son los publicados por sus autores")
				return nil
			}
			fmt.Println("\nUn motor que no reconocemos puede ser:")
			fmt.Println("  1. una versión más nueva que instalaste a mano — actualiza el manifiesto")
			fmt.Println("     (internal/engines/identidad/motores.json) con el hash de su release")
			fmt.Println("  2. un binario alterado — bórralo y reinstala con install.ps1")
			fmt.Println("\nHasta aclararlo, trata sus resultados con reserva: un gitleaks")
			fmt.Println("manipulado puede no reportar ni un solo secreto.")
			os.Exit(1)
			return nil
		},
	}
}
