package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/llm"
	"codeguard/internal/secreto"
)

func configCmd() *cobra.Command {
	var listar, probar bool
	var guardarClaveDe string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Abre la configuración del modelo que aconseja",
		Long: "El modelo aconseja y nunca bloquea, así que cambiarlo no altera qué " +
			"reglas se aplican ni la paridad con el CI.\n\n" +
			"Tu elección se guarda fuera del repositorio: no viaja en ningún commit " +
			"ni cambia la configuración del equipo.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if guardarClaveDe != "" {
				return guardarClaveDeStdin(guardarClaveDe)
			}
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
	cmd.Flags().StringVar(&guardarClaveDe, "guardar-clave", "",
		"guarda en el Administrador de credenciales la clave que se lea por la entrada estándar (p.ej. --guardar-clave FOUNDRY_API_KEY)")
	return cmd
}

// guardarClaveDeStdin mete la clave en la bóveda leyéndola por la ENTRADA
// ESTÁNDAR, nunca por un argumento.
//
// Existe para que el instalador deje de escribirla en texto plano en
// HKCU\Environment, que era la precondición del agujero que se cerró en esta
// remediación: cualquier proceso del usuario la leía con un `Get-ChildItem
// Env:`, y el daemon la heredaba a sus hijos hasta que migraba.
//
// Y se lee por stdin y no por parámetro por una segunda razón, independiente de
// la primera: un argumento de línea de órdenes es visible en la lista de
// procesos mientras dura, y en PowerShell queda además en el historial del
// usuario. Con un pipe no aparece en ninguno de los dos sitios.
func guardarClaveDeStdin(variable string) error {
	crudo, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("no se pudo leer la clave de la entrada estándar: %w", err)
	}
	// Se recorta el salto de línea que añade cualquier pipe, pero NADA más: una
	// clave puede llevar caracteres que parezcan basura y no lo son.
	clave := strings.Trim(string(crudo), " \r\n\t")
	if clave == "" {
		return fmt.Errorf("no llegó ninguna clave por la entrada estándar: "+
			"se esperaba algo como `\"$clave\" | codeguard config --guardar-clave %s`", variable)
	}
	if !secreto.Disponible() {
		return fmt.Errorf("el Administrador de credenciales no está disponible en esta máquina: " +
			"no hay dónde guardar la clave a salvo")
	}
	if err := secreto.Guardar(variable, clave); err != nil {
		return fmt.Errorf("no se pudo guardar %s en el Administrador de credenciales: %w", variable, err)
	}
	// Se relee para no dar por buena una escritura que no cuajó: sin esta
	// comprobación, el instalador diría "guardada" y la capa del modelo
	// aparecería apagada sin explicación.
	guardada, err := secreto.Leer(variable)
	if err != nil {
		return fmt.Errorf("%s se escribió pero no se pudo releer: %w", variable, err)
	}
	if guardada != clave {
		return fmt.Errorf("el Administrador de credenciales devolvió una clave distinta para %s", variable)
	}
	fmt.Println(variable, "guardada en el Administrador de credenciales "+
		"(no queda copia en el registro ni en el entorno)")
	return nil
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

	switch {
	case cfg.LLM.APIKeyEnv == "":
		fmt.Println("  clave      no hace falta")
	case claveEnBoveda(cfg.LLM.APIKeyEnv):
		// Se distingue de la del entorno porque el remedio es distinto: una
		// clave en la bóveda la ve cualquier proceso al leerla, así que si algo
		// no funciona no es "abre una terminal nueva".
		fmt.Printf("  clave      %s ✓ guardada en el Administrador de credenciales\n", cfg.LLM.APIKeyEnv)
	case os.Getenv(cfg.LLM.APIKeyEnv) != "":
		fmt.Printf("  clave      %s ✓ configurada (en el entorno)\n", cfg.LLM.APIKeyEnv)
		fmt.Println("             el agente la moverá al Administrador de credenciales al arrancar")
	case definidaEnElUsuario(cfg.LLM.APIKeyEnv):
		// Windows sólo entrega las variables de usuario a los procesos que
		// arrancan DESPUÉS de definirlas. Decir "vacía" aquí manda al dev a
		// buscar una clave que ya tiene, y a redefinirla encima.
		fmt.Printf("  clave      %s ✓ definida en tu usuario, pero esta terminal es anterior\n",
			cfg.LLM.APIKeyEnv)
		fmt.Println("             abre una terminal nueva (el agente sí la ve si arrancó después)")
	default:
		fmt.Printf("  clave      %s ✗ sin definir — la capa de consejo no correrá\n", cfg.LLM.APIKeyEnv)
		fmt.Println("             defínela desde `codeguard config` o como variable de entorno")
	}
	return nil
}

func nonEmptyOr(s, alterno string) string {
	if s == "" {
		return alterno
	}
	return s
}

// claveEnBoveda dice si la clave vive en el Administrador de credenciales.
// Multiplataforma sin build tags: el paquete secreto ya responde que no hay
// bóveda fuera de Windows.
func claveEnBoveda(variable string) bool {
	v, err := secreto.Leer(variable)
	return err == nil && v != ""
}
