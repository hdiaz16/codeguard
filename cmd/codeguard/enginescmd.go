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

	"codeguard/internal/engines/identidad"
	"codeguard/internal/engines/proc"
)

// DirMotores es donde el instalador deja los binarios descargables.
func DirMotores() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "CodeGuard", "engines")
}

func enginesCmd() *cobra.Command {
	var auditar bool
	cmd := &cobra.Command{
		Use:   "engines",
		Short: "Verifica que los motores instalados sean los que publicaron sus autores",
		Long: "Compara el SHA-256 de cada motor descargable contra los hashes " +
			"publicados por sus autores en los checksums de cada release.\n\n" +
			"Los motores de Python (semgrep, squawk, ruff) no aparecen: los instala " +
			"pip contra PyPI con sus propias firmas, no los distribuimos nosotros.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := DirMotores()
			if auditar {
				return auditarMotores(dir)
			}
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

			fmt.Println()
			fmt.Println("Contención con la que corren:")
			if activo, err := proc.SandboxActivo(); activo {
				fmt.Println("  ✓ token restringido    sin privilegios salvo recorrer directorios")
			} else {
				fmt.Printf("  ✗ token restringido    NO disponible: %v\n", err)
				fmt.Println("      los motores corren con los privilegios completos de tu sesión")
			}
			fmt.Printf("  ✓ entorno acotado      %d variables retenidas (la API key del modelo no viaja)\n", proc.Filtradas())
			fmt.Println("  ✓ job object           mueren con el plazo, con sus hijos; tope de memoria y de procesos")
			fmt.Println("  ✓ sin interfaz         sin portapapeles, escritorio ni ventanas de otros")
			fmt.Println("  · sistema de archivos  sin restringir: un motor tiene que leer el repo")

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
	cmd.Flags().BoolVar(&auditar, "auditar", false,
		"escanea con trivy los motores que distribuimos, en busca de CVEs propios")
	return cmd
}

// auditarMotores mira si lo que NOSOTROS instalamos trae vulnerabilidades.
//
// `codeguard engines` responde "¿este binario es el que publicó su autor?".
// Esto responde la otra mitad: "¿y lo que publicó su autor está sano?". Un
// motor puede coincidir con su hash a la perfección y arrastrar un CVE crítico
// dentro; el hash sólo prueba que nadie lo tocó por el camino.
//
// Sale con 1 si hay algo crítico o alto, para que el CI pueda usarlo como
// compuerta: una herramienta de seguridad que reparte binarios sin mirarlos
// pide una confianza que no se ganó.
func auditarMotores(dir string) error {
	fmt.Println("auditando lo que CodeGuard instala en tu equipo…")
	fmt.Println()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, err := identidad.Auditar(ctx, dir, dirPaquetesPython(), "")
	if err != nil {
		return err
	}
	if len(a.Escaneados) > 0 {
		fmt.Println("escaneados:", strings.Join(a.Escaneados, ", "))
	}
	// Lo que no se pudo mirar se dice SIEMPRE: dar por limpio lo que no se
	// revisó es el fallo que este proyecto lleva un mes persiguiendo.
	for _, o := range a.Omitidos {
		fmt.Println("  · sin revisar:", o)
	}
	fmt.Println()

	graves := a.Graves()
	if len(a.Riesgos) == 0 {
		fmt.Println("✓ sin vulnerabilidades conocidas en los motores que distribuimos")
		return nil
	}
	fmt.Printf("%d vulnerabilidad(es) en total, %d crítica(s)/alta(s)\n\n", len(a.Riesgos), len(graves))
	for _, r := range graves {
		arreglo := "sin versión corregida publicada"
		if r.Corregida != "" {
			arreglo = "corregida en " + r.Corregida
		}
		fmt.Printf("  ✗ %-18s %s [%s] en %s@%s — %s\n",
			r.Artefacto, r.CVE, r.Severidad, r.Paquete, r.Version, arreglo)
	}
	if len(graves) == 0 {
		fmt.Println("ninguna crítica ni alta: no bloquea el reparto, pero conviene subirlas")
		return nil
	}
	fmt.Println("\nSube la versión del motor en internal/engines/identidad/motores.json")
	fmt.Println("(con el hash de la release nueva) y vuelve a construir el instalador.")
	os.Exit(1)
	return nil
}

// dirPaquetesPython pregunta a Python dónde instaló pip los paquetes de
// usuario, en vez de adivinar la ruta: depende de la versión de Python.
func dirPaquetesPython() string {
	out, err := exec.Command("python", "-c",
		"import sysconfig; print(sysconfig.get_path('purelib', 'nt_user'))").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
