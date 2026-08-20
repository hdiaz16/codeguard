//go:build windows

package identidad

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	envModoConsola    = "CODEGUARD_TEST_CONSOLA_IDENTIDAD"
	envInformeConsola = "CODEGUARD_TEST_INFORME_IDENTIDAD"
)

var (
	kernel32ID           = syscall.NewLazyDLL("kernel32.dll")
	user32ID             = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow = kernel32ID.NewProc("GetConsoleWindow")
	procIsWindowVisible  = user32ID.NewProc("IsWindowVisible")
	procFreeConsole      = kernel32ID.NewProc("FreeConsole")
)

// La ventana negra que abriría la comprobación de arranque, medida.
//
// El daemon va a importar este paquete —es la única fuente que distingue
// "instalado" de "instalado pero no arranca"— y no tiene consola propia. Esta
// prueba reproduce esa condición en un proceso intermedio que suelta la suya con
// FreeConsole: medido, es equivalente a compilar con -H windowsgui, y así no
// hace falta construir un binario GUI aparte.
//
//	prueba ──> lanzador (FreeConsole)
//	                ├─> reportero armado A MANO        (control)
//	                └─> reportero armado con comandoIdentidad
//
// El CONTROL manda: si el hijo crudo no sale con ventana visible, esta máquina
// no reproduce la condición y la prueba se SALTA en vez de pasar en verde sin
// haber comprobado nada.
func TestLaComprobacionDeArranqueNoAbreVentana(t *testing.T) {
	informe := filepath.Join(t.TempDir(), "veredicto.txt")

	lanzador := exec.Command(os.Args[0], "-test.run=^TestAyudanteLanzadorID$", "-test.timeout=60s")
	lanzador.Env = append(os.Environ(), envModoConsola+"=lanzador", envInformeConsola+"="+informe)
	if salida, err := lanzador.CombinedOutput(); err != nil {
		t.Fatalf("el ayudante lanzador falló: %v\n%s", err, salida)
	}

	crudo, ok := veredictoID(t, informe, "control")
	if !ok || !crudo.visible {
		t.Skipf("esta máquina no reproduce la condición del daemon (control: %s); "+
			"sin control la prueba no probaría nada", crudo.crudo)
	}
	tratado, ok := veredictoID(t, informe, "constructor")
	if !ok {
		t.Fatalf("el ayudante no reportó el caso del constructor")
	}
	if tratado.visible {
		t.Errorf("comandoIdentidad abrió una ventana de consola VISIBLE (%s): "+
			"con el daemon importando este paquete, el dev vería una ventana negra "+
			"por cada motor JVM que se comprueba", tratado.crudo)
	}
}

func TestAyudanteLanzadorID(t *testing.T) {
	if os.Getenv(envModoConsola) != "lanzador" {
		t.Skip("ayudante: sólo corre reejecutado")
	}
	informe := os.Getenv(envInformeConsola)
	dir := filepath.Dir(informe)
	_, _, _ = procFreeConsole.Call()

	crudo := filepath.Join(dir, "crudo.txt")
	aMano := exec.Command(os.Args[0], "-test.run=^TestAyudanteReporteroID$", "-test.timeout=60s")
	aMano.Env = append(os.Environ(), envModoConsola+"=reportero", envInformeConsola+"="+crudo)

	porCtor := filepath.Join(dir, "ctor.txt")
	// El camino REAL: el mismo constructor que usan noArranca y la auditoría.
	conCtor := comandoIdentidad(t.Context(), os.Args[0],
		"-test.run=^TestAyudanteReporteroID$", "-test.timeout=60s")
	conCtor.Env = append(os.Environ(), envModoConsola+"=reportero", envInformeConsola+"="+porCtor)

	var lineas []string
	for _, caso := range []struct {
		nombre string
		cmd    *exec.Cmd
		arch   string
	}{
		{"control", aMano, crudo},
		{"constructor", conCtor, porCtor},
	} {
		if err := caso.cmd.Run(); err != nil {
			lineas = append(lineas, caso.nombre+"=fallo "+err.Error())
			continue
		}
		b, err := os.ReadFile(caso.arch)
		if err != nil {
			lineas = append(lineas, caso.nombre+"=sin-reporte")
			continue
		}
		lineas = append(lineas, caso.nombre+"="+strings.TrimSpace(string(b)))
	}
	if err := os.WriteFile(informe, []byte(strings.Join(lineas, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAyudanteReporteroID(t *testing.T) {
	if os.Getenv(envModoConsola) != "reportero" {
		t.Skip("ayudante: sólo corre reejecutado")
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	var vis uintptr
	if hwnd != 0 {
		vis, _, _ = procIsWindowVisible.Call(hwnd)
	}
	if err := os.WriteFile(os.Getenv(envInformeConsola),
		[]byte(fmt.Sprintf("hwnd=%d visible=%d", hwnd, vis)), 0o600); err != nil {
		t.Fatal(err)
	}
}

type reporteID struct {
	visible bool
	crudo   string
}

func veredictoID(t *testing.T, informe, clave string) (reporteID, bool) {
	t.Helper()
	b, err := os.ReadFile(informe)
	if err != nil {
		return reporteID{}, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		valor, hay := strings.CutPrefix(strings.TrimSpace(l), clave+"=")
		if !hay {
			continue
		}
		var hwnd, vis int
		if _, err := fmt.Sscanf(valor, "hwnd=%d visible=%d", &hwnd, &vis); err != nil {
			return reporteID{crudo: valor}, false
		}
		return reporteID{visible: vis != 0, crudo: valor}, true
	}
	return reporteID{}, false
}
