//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// La ventana negra que se abría al pulsar "Historial".
//
// El daemon se compila con -H windowsgui (dist/build-dist.ps1): no tiene consola
// propia. Cuando un proceso SIN consola lanza un ejecutable DE consola, Windows
// no lo deja mudo: le crea una consola nueva y la MUESTRA. El historial llama a
// git para resolver el identificador del repo, y por eso cada visita a la
// pestaña sacaba una ventana en la cara del desarrollador.
//
// Esta prueba mide eso de verdad en vez de leer el código, en tres procesos:
//
//	prueba ──> ayudante lanzador (suelta su consola con FreeConsole)
//	                     ├─> reportero armado A MANO      (control)
//	                     └─> reportero armado con comandoDaemon
//
// FreeConsole reproduce la condición del daemon: lo que hace que Windows regale
// una consola nueva no es el subsistema del PE, es que el padre no tenga
// ninguna. Medido: con un padre compilado -H windowsgui y con un padre de
// consola que llama a FreeConsole, el hijo crudo da hwnd≠0 e IsWindowVisible=1
// en los dos casos. Así la prueba no necesita compilar un binario GUI aparte.
//
// El reportero es este mismo binario de test —de consola, que es el requisito—
// reejecutado en otro modo, y dice qué consola le tocó.
//
// El CONTROL no es decorativo: si el proceso lanzador no consigue reproducir la
// condición (por ejemplo en un entorno donde ya no haya consola que soltar y
// Windows se comporte de otro modo), la prueba se salta en vez de pasar en
// verde sin haber comprobado nada. Un guardián que no puede fallar no guarda.
func TestElHistorialNoAbreVentanaDeConsola(t *testing.T) {
	informe := filepath.Join(t.TempDir(), "veredicto.txt")

	lanzador := exec.Command(os.Args[0], "-test.run=^TestAyudanteLanzador$", "-test.timeout=60s")
	lanzador.Env = append(os.Environ(), envModoConsola+"=lanzador", envInformeConsola+"="+informe)
	salida, err := lanzador.CombinedOutput()
	if err != nil {
		t.Fatalf("el ayudante lanzador falló: %v\n%s", err, salida)
	}

	crudo, ok := veredicto(t, informe, "control")
	if !ok || !crudo.visible {
		t.Skipf("no se pudo reproducir la condición del daemon en esta máquina "+
			"(el hijo armado a mano dio %v); sin control, la prueba no probaría nada", crudo)
	}
	tratado, ok := veredicto(t, informe, "constructor")
	if !ok {
		t.Fatalf("el ayudante no reportó el caso del constructor:\n%s", leer(t, informe))
	}
	if tratado.visible {
		t.Errorf("comandoDaemon abrió una ventana de consola VISIBLE (%v): "+
			"es la ventana negra que el desarrollador ve al abrir el historial. "+
			"El constructor tiene que pasar por proc.SinVentana", tratado)
	}
}

// TestAyudanteLanzador no es una prueba: es el proceso del medio. Corre sólo
// cuando lo invoca TestElHistorialNoAbreVentanaDeConsola, y se salta siempre en
// una ejecución normal del paquete.
func TestAyudanteLanzador(t *testing.T) {
	if os.Getenv(envModoConsola) != "lanzador" {
		t.Skip("ayudante: sólo corre reejecutado desde TestElHistorialNoAbreVentanaDeConsola")
	}
	informe := os.Getenv(envInformeConsola)
	dir := filepath.Dir(informe)

	// Soltar la consola heredada de `go test`. A partir de aquí este proceso
	// está como el daemon: sin consola que dar a sus hijos.
	_, _, _ = procFreeConsole.Call()

	crudo := filepath.Join(dir, "crudo.txt")
	aMano := exec.Command(os.Args[0], "-test.run=^TestAyudanteReportero$", "-test.timeout=60s")
	aMano.Env = append(os.Environ(), envModoConsola+"=reportero", envInformeConsola+"="+crudo)

	porConstructor := filepath.Join(dir, "constructor.txt")
	// El camino REAL de producción: el mismo constructor que usa gitCmdDaemon.
	// Se le añaden las dos variables al entorno que ya acotó comandoDaemon, sin
	// tocar SysProcAttr, que es lo que la prueba mide.
	conCtor := comandoDaemon(os.Args[0], "-test.run=^TestAyudanteReportero$", "-test.timeout=60s")
	conCtor.Env = append(conCtor.Env, envModoConsola+"=reportero", envInformeConsola+"="+porConstructor)

	var lineas []string
	for _, caso := range []struct {
		nombre string
		cmd    *exec.Cmd
		arch   string
	}{
		{"control", aMano, crudo},
		{"constructor", conCtor, porConstructor},
	} {
		if err := caso.cmd.Run(); err != nil {
			lineas = append(lineas, caso.nombre+"=fallo "+err.Error())
			continue
		}
		b, err := os.ReadFile(caso.arch)
		if err != nil {
			lineas = append(lineas, caso.nombre+"=sin-reporte "+err.Error())
			continue
		}
		lineas = append(lineas, caso.nombre+"="+strings.TrimSpace(string(b)))
	}
	if err := os.WriteFile(informe, []byte(strings.Join(lineas, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAyudanteReportero tampoco es una prueba: es el hijo de consola que dice
// qué ventana le dio Windows.
func TestAyudanteReportero(t *testing.T) {
	if os.Getenv(envModoConsola) != "reportero" {
		t.Skip("ayudante: sólo corre reejecutado desde TestAyudanteLanzador")
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	var vis uintptr
	if hwnd != 0 {
		vis, _, _ = procIsWindowVisible.Call(hwnd)
	}
	linea := fmt.Sprintf("hwnd=%d visible=%d", hwnd, vis)
	if err := os.WriteFile(os.Getenv(envInformeConsola), []byte(linea), 0o600); err != nil {
		t.Fatal(err)
	}
}

// El contrato del constructor, comprobado sin lanzar nada.
//
// La prueba de arriba mide el efecto real pero deja pasar la mutación de quitar
// UNO de los dos atributos: medido, HideWindow y CREATE_NO_WINDOW bastan por
// separado para que no se vea la ventana (con HideWindow la consola existe pero
// nace oculta; con CREATE_NO_WINDOW ni se crea). Ésta fija los dos, para que
// quitar cualquiera de ellos se ponga rojo aquí.
func TestElConstructorDelDaemonPideVentanaOculta(t *testing.T) {
	const creationNoWindow = 0x08000000
	for _, caso := range []struct {
		nombre string
		cmd    *exec.Cmd
	}{
		{"comandoDaemon", comandoDaemon("git", "--version")},
		{"gitCmdDaemon", gitCmdDaemon(t.TempDir(), "config", "--get", "remote.origin.url")},
	} {
		if caso.cmd.SysProcAttr == nil {
			t.Errorf("%s: SysProcAttr nil — el hijo abrirá una ventana de consola", caso.nombre)
			continue
		}
		spa := caso.cmd.SysProcAttr
		if !spa.HideWindow {
			t.Errorf("%s: falta HideWindow", caso.nombre)
		}
		if spa.CreationFlags&creationNoWindow == 0 {
			t.Errorf("%s: falta CREATE_NO_WINDOW", caso.nombre)
		}
	}
}

// Ocultar la ventana no puede romper lo que la ventana acompañaba.
//
// El constructor no sólo añadió SysProcAttr: también acota el entorno del hijo.
// Un git que se queda sin las variables que necesita falla en silencio y
// repoIDDe cae al identificador de respaldo — el historial saldría VACÍO sobre
// una base llena, que es exactamente el fallo que este código existe para
// evitar, y sin ventana negra nadie sospecharía nada. Esta prueba recorre el
// camino real del historial contra el repo de verdad.
func TestElHistorialSigueResolviendoElRepo(t *testing.T) {
	raiz, err := os.Getwd() // cmd/daemon, dentro del repo
	if err != nil {
		t.Fatal(err)
	}
	if id := repoIDDe(raiz); id == "" {
		t.Error("repoIDDe devolvió vacío: el historial no podría emparejar ninguna corrida")
	}
}

const (
	envModoConsola    = "CODEGUARD_TEST_CONSOLA"
	envInformeConsola = "CODEGUARD_TEST_INFORME"
)

var (
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procIsWindowVisible  = user32.NewProc("IsWindowVisible")
	procFreeConsole      = kernel32.NewProc("FreeConsole")
)

type reporte struct {
	hwnd    uintptr
	visible bool
	crudo   string
}

func (r reporte) String() string { return r.crudo }

func veredicto(t *testing.T, informe, clave string) (reporte, bool) {
	t.Helper()
	for _, l := range strings.Split(leer(t, informe), "\n") {
		valor, hay := strings.CutPrefix(strings.TrimSpace(l), clave+"=")
		if !hay {
			continue
		}
		var r reporte
		r.crudo = valor
		var vis int
		if _, err := fmt.Sscanf(valor, "hwnd=%d visible=%d", &r.hwnd, &vis); err != nil {
			return r, false
		}
		r.visible = vis != 0
		return r, true
	}
	return reporte{}, false
}

func leer(t *testing.T, ruta string) string {
	t.Helper()
	// El ayudante escribe el informe justo antes de salir; leer sin más ha
	// bastado siempre, pero un reintento corto sale más barato que un flaky.
	for i := 0; i < 20; i++ {
		if b, err := os.ReadFile(ruta); err == nil {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}
