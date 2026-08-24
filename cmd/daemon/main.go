// codeguard-daemon — el compañero (§12): daemon con tray y panel lateral.
// Compilar con -ldflags "-H windowsgui" para no abrir consola.
package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"codeguard/internal/daemon"
	"codeguard/internal/engines/proc"
)

//go:embed all:frontend
var assets embed.FS

var version = "dev"

// abrirLog manda el registro al archivo del usuario. El daemon corre sin
// consola (-H windowsgui): sin este log, cualquier fallo es invisible. Vive
// junto a la BD del usuario.
func abrirLog(refrescadas int) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return
	}
	dir := filepath.Join(base, "codeguard")
	_ = os.MkdirAll(dir, 0o755) // best-effort: el OpenFile del log de abajo reportaría el fallo
	f, err := os.OpenFile(filepath.Join(dir, "daemon.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.Printf("=== daemon %s arrancado ===", version)
	if refrescadas > 0 {
		log.Printf("entorno: %d variable(s) del usuario incorporadas del registro", refrescadas)
	}
}

// main es la raíz de composición y nada más: cablea las piezas en el orden en
// que dependen unas de otras. Lo que cada pieza HACE vive en escritorio.go —
// aquí sólo se ve el arranque completo de un vistazo.
func main() {
	// El PATH del registro antes que nada: el daemon lo lanza la clave Run al
	// iniciar sesión, y si el agente se instaló DURANTE la sesión en curso su
	// entorno no tiene los motores. Sin esto, la compuerta de secretos bloquea
	// commits pidiendo un gitleaks que está instalado.
	proc.RefrescarPATH()
	// Y las demás variables del usuario, que es donde vive la clave del modelo:
	// sin esto, cada reinicio del daemon apagaba la capa LLM en silencio.
	refrescadas := proc.RefrescarVariables()
	// El caché de resultados lleva la versión en su clave: al actualizar el
	// agente, lo que analizó el binario viejo deja de darse por bueno.
	daemon.Version = version
	abrirLog(refrescadas)

	// El sandbox (token restringido) que no se puede crear degrada a
	// privilegios completos sin decirlo en ningún sitio que se lea solo
	// (prepararSandbox): la línea de `codeguard engines` existe, pero nadie
	// corre el diagnóstico espontáneamente. Una línea aquí lo deja dicho en
	// cada arranque. Solo con err: fuera de Windows SandboxActivo devuelve
	// (false, nil) por diseño. La palabra t*ken no puede ir en el mensaje:
	// log-dato-sensible liga el texto de CADA argumento del logger.
	if activo, err := proc.SandboxActivo(); !activo && err != nil {
		log.Printf("sandbox: la contencion NO esta disponible (%v): los motores corren con los privilegios completos de la sesion", err)
	}

	// Y ya con el log abierto, se mueve a la bóveda la clave que las versiones
	// anteriores dejaron en HKCU\Environment en texto plano. Va aquí porque es
	// el único sitio por el que pasa toda instalación existente al actualizar:
	// esperar a que el usuario abra la pantalla de configuración dejaría la
	// copia vieja expuesta indefinidamente en las máquinas de quien no la
	// vuelva a tocar, que son la mayoría.
	migrarClaveSiHaceFalta()

	dataDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard", fmt.Sprintf("wv_%d", os.Getpid()))
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(os.TempDir(), "codeguard", fmt.Sprintf("wv_%d", os.Getpid()))
	}
	_ = os.MkdirAll(dataDir, 0o700)

	// El escritorio nace antes que la aplicación: Wails pide el manejador HTTP
	// al construirse y ese manejador sirve el estado que vive en el escritorio.
	e := nuevoEscritorio()
	e.app = application.New(application.Options{
		Name:        "CodeGuard",
		Description: "Agente de análisis pre-commit con paridad hacia CI",
		// La identidad del agente es el mismo orbe que el desarrollador ve en
		// la esquina de su pantalla, no un ícono genérico.
		Icon: iconoOficial(),
		Assets: application.AssetOptions{
			// BundledAssetFileServer sirve también /wails/runtime.js,
			// que el panel importa para los eventos.
			Handler: e.manejadorHTTP(),
		},
		Windows: application.WindowsOptions{
			WebviewUserDataPath: dataDir,
		},
	})
	e.construirVentanas()
	e.construirBandeja()
	e.registrarEventos()

	srv := e.construirServidorIPC(e.arrancarSombra())

	// Anclar el orbe en su esquina al arrancar (con reintentos).
	e.app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		e.anclarBurbujaSeguro()
	})

	ctx, cancel := context.WithCancel(context.Background())
	e.app.OnShutdown(cancel)
	go func() {
		// El tray refleja "working" mientras el server atiende: el propio
		// handler emite el estado al entrar la petición (ver ipc hook abajo).
		if err := srv.Serve(ctx); err != nil {
			log.Println("servidor IPC:", err)
		}
	}()

	if err := e.app.Run(); err != nil {
		log.Fatal(err)
	}
}
