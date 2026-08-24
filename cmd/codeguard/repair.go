package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/engines/identidad"
	"codeguard/internal/gitdiff"
	"codeguard/internal/rulepack"
)

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
	if _, err := rulepack.Resolver(raiz, cfg.Rulepack); err == nil {
		fmt.Printf("  ok    rulepack %s\n", cfg.Rulepack)
		return nil
	}

	disponibles := rulepack.RulepacksInstalados(raiz)
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
				{"mypy", "pip install mypy"},
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
				case identidad.NoArranca:
					// Avisa SIN tocar `ok`, por el mismo motivo que en `engines`:
					// el artefacto es el publicado —el hash cuadra— y lo que falta
					// es un runtime más nuevo en esta máquina. No es un incidente
					// de cadena de suministro.
					//
					// Y aquí importa más que allí: `dist\instalar-motores.ps1` corre
					// `codeguard repair` como verificación final del asistente y
					// propaga su código de salida. Con esto en `default`, un JDK
					// viejo hacía que el instalador CERRARA EN FALLO —tras un
					// mensaje sobre gitleaks, que estaba impecable— por algo que
					// `repair` no puede arreglar jamás: reinstalar devuelve el mismo
					// jar con el mismo hash.
					fmt.Printf("  aviso %s v%s: es el binario publicado pero no arranca aquí\n", r.Motor, r.Version)
					fmt.Printf("        %s\n", r.Detalle)
				case identidad.Ausente:
					// Ya lo reporta el bloque de herramientas de arriba.
				default:
					ok = false
					fmt.Printf("  ALERTA %s: %s → revisa con `codeguard engines`\n", r.Motor, r.Detalle)
				}
			}
			if !ok {
				fmt.Println("\nsin gitleaks la compuerta de secretos es fail-closed y bloquea los commits")
				return errors.New("faltan dependencias del agente: revisa las líneas FALTA/ALERTA de arriba")
			}
			fmt.Println("todo en orden")
			return nil
		},
	}
}
