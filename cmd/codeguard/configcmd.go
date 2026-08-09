package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/llm"
)

func configCmd() *cobra.Command {
	var listar, probar bool
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Abre la configuración del modelo que aconseja",
		Long: "El modelo aconseja y nunca bloquea, así que cambiarlo no altera qué " +
			"reglas se aplican ni la paridad con el CI.\n\n" +
			"Tu elección se guarda fuera del repositorio: no viaja en ningún commit " +
			"ni cambia la configuración del equipo.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if probar {
				return probarConfigActual()
			}
			if listar {
				return mostrarConfigLLM()
			}
			repoRoot, _ := gitdiff.RepoRoot(".")
			if _, err := ipc.Call(&ipc.Request{
				Command: "open-config", RepoRoot: repoRoot, DeadlineMs: 3000,
			}, 3*time.Second); err != nil {
				fmt.Fprintln(os.Stderr, "el agente no está corriendo: arráncalo o usa `codeguard config --ver`")
				return err
			}
			fmt.Println("configuración abierta en la ventana del agente")
			return nil
		},
	}
	cmd.Flags().BoolVar(&listar, "ver", false, "mostrar la configuración actual en la terminal")
	cmd.Flags().BoolVar(&probar, "probar", false, "hacer una llamada real al modelo configurado")
	return cmd
}

// probarConfigActual comprueba la configuración vigente sin abrir la ventana:
// en una máquina sin interfaz —o por SSH— sigue siendo la forma de saber si
// la capa de consejo va a funcionar.
func probarConfigActual() error {
	repoRoot, err := gitdiff.RepoRoot(".")
	if err != nil {
		return fmt.Errorf("no estás dentro de un repo git: %w", err)
	}
	cfg, err := config.Load(repoRoot)
	if err != nil || cfg == nil {
		return fmt.Errorf("este repo no está enrolado: no hay modelo configurado")
	}
	fmt.Printf("probando %s en %s…\n", nonEmptyOr(cfg.LLM.Model, "(sin modelo)"), cfg.LLM.Endpoint)
	detalle, err := llm.Probar(cfg.LLM, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "FALLÓ:", err)
		os.Exit(1)
	}
	fmt.Println("OK —", detalle)
	return nil
}

func mostrarConfigLLM() error {
	fmt.Println("Proveedores que CodeGuard sabe usar:")
	for _, p := range llm.Proveedores {
		llave := "necesita clave"
		if !p.NecesitaKey {
			llave = "sin clave (local)"
		}
		fmt.Printf("  %-20s %-9s %s\n", p.ID, p.Dialecto, llave)
	}

	repoRoot, err := gitdiff.RepoRoot(".")
	if err != nil {
		return nil
	}
	cfg, err := config.Load(repoRoot)
	if err != nil || cfg == nil {
		fmt.Println("\nEste repo no está enrolado: no hay configuración que mostrar.")
		return nil
	}

	origen := "del equipo (versionada en el repo)"
	if cfg.LLMLocal {
		origen = "PERSONAL, sólo en esta máquina — " + config.RutaLLMLocal()
	}
	fmt.Println("\nConfiguración activa:", origen)
	fmt.Printf("  proveedor  %s\n", nonEmptyOr(cfg.LLM.Provider, "(deducido del endpoint)"))
	fmt.Printf("  endpoint   %s\n", nonEmptyOr(cfg.LLM.Endpoint, "(sin configurar)"))
	fmt.Printf("  modelo     %s\n", nonEmptyOr(cfg.LLM.Model, "(sin configurar)"))
	fmt.Printf("  rápido     %s\n", nonEmptyOr(cfg.LLM.ModelFast, cfg.LLM.Model))

	if cfg.LLM.APIKeyEnv == "" {
		fmt.Println("  clave      no hace falta")
	} else if os.Getenv(cfg.LLM.APIKeyEnv) != "" {
		fmt.Printf("  clave      %s ✓ configurada\n", cfg.LLM.APIKeyEnv)
	} else {
		fmt.Printf("  clave      %s ✗ VACÍA — la capa de consejo no correrá\n", cfg.LLM.APIKeyEnv)
	}
	return nil
}

func nonEmptyOr(s, alterno string) string {
	if s == "" {
		return alterno
	}
	return s
}
