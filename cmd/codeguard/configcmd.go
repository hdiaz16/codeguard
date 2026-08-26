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
	var guardarClaveDe, olvidarClaveDe string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Abre la configuración del modelo que aconseja",
		Long: "El modelo aconseja y nunca bloquea, así que cambiarlo no altera qué " +
			"reglas se aplican ni la paridad con el CI.\n\n" +
			"Tu elección se guarda fuera del repositorio: no viaja en ningún commit " +
			"ni cambia la configuración del equipo.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if guardarClaveDe != "" && olvidarClaveDe != "" {
				return fmt.Errorf("--guardar-clave y --olvidar-clave hacen lo contrario: elige una")
			}
			if guardarClaveDe != "" {
				return guardarClaveDeStdin(guardarClaveDe)
			}
			if olvidarClaveDe != "" {
				return olvidarClaveGuardada(olvidarClaveDe)
			}
			if probar {
				return probarConfigActual()
			}
			if listar {
				return mostrarConfigLLM()
			}
			// El error se comprueba ANTES del IPC: descartándolo, fuera de un
			// repo git se mandaba un RepoRoot vacío y el fallo salía como «el
			// agente no está corriendo», que manda a reiniciar el agente cuando
			// lo que pasa es otra cosa.
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return fmt.Errorf("no estás dentro de un repo git: %w", err)
			}
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
	cmd.Flags().StringVar(&olvidarClaveDe, "olvidar-clave", "",
		"borra del Administrador de credenciales la clave guardada (p.ej. --olvidar-clave FOUNDRY_API_KEY)")
	return cmd
}

// olvidarClaveGuardada quita del Administrador de credenciales la clave que
// `--guardar-clave` dejó ahí.
//
// Existía la mitad de la operación y no la otra: se podía meter una clave de
// API en la bóveda de Windows desde el producto, y NO sacarla. Quien rotaba
// su clave, dejaba el proyecto o se equivocaba de cuenta se quedaba con un
// secreto vivo en su máquina y sin una sola orden para retirarlo — había que
// abrir el Administrador de credenciales a mano y saber que CodeGuard guarda
// bajo el nombre que compone secreto.Nombre. Una herramienta que ayuda a
// guardar secretos y no sabe soltarlos deja al usuario peor de lo que lo
// encontró.
func olvidarClaveGuardada(variable string) error {
	if !secreto.Disponible() {
		return fmt.Errorf("el Administrador de credenciales no está disponible en esta máquina: " +
			"no hay bóveda de la que borrar")
	}
	// Se mira ANTES para poder distinguir «la borré» de «no había nada»:
	// Borrar es idempotente a propósito, así que sin esta lectura las dos
	// situaciones darían el mismo mensaje y el usuario no sabría si de verdad
	// tenía una clave guardada.
	_, errAntes := secreto.Leer(variable)
	habia := errAntes == nil
	if errAntes != nil && !secreto.NoEncontrado(errAntes) {
		return fmt.Errorf("no se pudo consultar %s en el Administrador de credenciales: %w", variable, errAntes)
	}

	if err := secreto.Borrar(variable); err != nil {
		return fmt.Errorf("no se pudo borrar %s del Administrador de credenciales: %w", variable, err)
	}

	// Se RELEE por la misma razón que al guardar: dar por buena una escritura
	// que no cuajó es lo que convierte un fallo en un secreto fantasma.
	if v, err := secreto.Leer(variable); err == nil && v != "" {
		return fmt.Errorf("%s se mandó borrar pero el Administrador de credenciales sigue devolviéndola", variable)
	} else if err != nil && !secreto.NoEncontrado(err) {
		return fmt.Errorf("%s se borró pero la bóveda no se pudo releer para confirmarlo: %w", variable, err)
	}

	if habia {
		fmt.Println(variable, "borrada del Administrador de credenciales")
	} else {
		fmt.Println(variable, "no estaba guardada en el Administrador de credenciales: no había nada que olvidar")
	}

	// La verdad incómoda, dicha aquí y no descubierta mañana: el agente MIGRA
	// al arrancar cualquier clave que encuentre en su entorno y no esté ya en
	// la bóveda (MigrarClaveDelEntorno). Si la variable sigue definida en el
	// entorno del usuario, esto no la olvida: la devuelve el próximo arranque.
	if os.Getenv(variable) != "" {
		fmt.Printf("  ojo: %s sigue definida en el entorno de esta terminal.\n", variable)
		fmt.Println("  El agente vuelve a guardar en la bóveda toda clave que vea en su entorno al")
		fmt.Println("  arrancar, así que para olvidarla de verdad quítala también de tus variables")
		fmt.Println("  de usuario y abre una terminal nueva.")
	}
	return nil
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
	const maxStdinKeyBytes = 64 * 1024
	crudo, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinKeyBytes))
	if err != nil {
		return fmt.Errorf("no se pudo leer la clave de la entrada estándar: %w", err)
	}
	// Se recortan el salto de línea que añade cualquier pipe Y los espacios o
	// tabuladores de los extremos, que es lo que trae un pegado desde el portal
	// del proveedor. Nada de lo de dentro se toca: una clave puede llevar
	// caracteres que parezcan basura y no lo son.
	//
	// Se auditó como corrupción de claves con espacios legítimos en los
	// extremos, y se dejó a propósito: ninguna API key conocida los lleva, y
	// guardar la clave con el espacio del pegado la vuelve inválida — el fallo
	// aparecería mucho después, como un error de autenticación que no señala a
	// aquí. El comentario anterior decía «NADA más» y contradecía al código.
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
		// Se devuelve el error y NO se imprime aquí: main ya lo escribe en
		// stderr con el prefijo "codeguard:", y hacer las dos cosas sacaba el
		// mismo fallo dos veces.
		return fmt.Errorf("la prueba del modelo falló: %w", err)
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
	default:
		// Aquí vivía un cuarto caso: «definida en tu usuario, pero esta
		// terminal es anterior» (Windows solo entrega las variables de usuario
		// a los procesos que arrancan DESPUÉS de definirlas). Se apoyaba en
		// definidaEnElUsuario, que al adoptarse Zero-Registry pasó a devolver
		// false SIEMPRE, en los dos builds: la rama era inalcanzable y el
		// mensaje no se imprimió nunca más. Se retiró en la limpieza de
		// 2026-08-25 porque una rama que no puede ejecutarse miente sobre lo
		// que el diagnóstico sabe.
		//
		// Si ese aviso vuelve a hacer falta, hay que LEER de verdad
		// HKCU\Environment. Leer no contradice Zero-Registry —esa decisión es
		// sobre no GUARDAR credenciales ahí— pero es una decisión de producto,
		// no una reparación, y por eso no se toma de oficio.
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
