package proc

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestEntornoNoFiltraSecretos(t *testing.T) {
	t.Setenv("FOUNDRY_API_KEY", "no-debe-salir-de-aqui")
	t.Setenv("ANTHROPIC_API_KEY", "tampoco")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ni-esta")
	t.Setenv("GITHUB_TOKEN", "ni-esta-otra")

	env := strings.Join(Entorno(), "\n")
	for _, prohibida := range []string{
		"FOUNDRY_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
		"no-debe-salir-de-aqui", "tampoco", "ni-esta",
	} {
		if strings.Contains(env, prohibida) {
			t.Errorf("el entorno de los motores contiene %q", prohibida)
		}
	}
}

// Una variable nueva e inesperada tampoco debe pasar: es la razón de que la
// lista sea de permitidos y no de prohibidos.
func TestEntornoRechazaLoDesconocido(t *testing.T) {
	t.Setenv("VARIABLE_QUE_NADIE_PREVIO", "secreto-del-futuro")
	if strings.Contains(strings.Join(Entorno(), "\n"), "VARIABLE_QUE_NADIE_PREVIO") {
		t.Error("una variable no prevista se coló al entorno de los motores")
	}
}

func TestEntornoConservaLoNecesario(t *testing.T) {
	env := Entorno()
	claves := map[string]bool{}
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i > 0 {
			claves[strings.ToUpper(e[:i])] = true
		}
	}
	// Sin PATH no se encuentra ni el binario del motor; sin SystemRoot
	// Windows no arranca el proceso.
	necesarias := []string{"PATH"}
	if runtime.GOOS == "windows" {
		necesarias = append(necesarias, "SYSTEMROOT", "TEMP")
	} else {
		necesarias = append(necesarias, "HOME")
	}
	for _, necesaria := range necesarias {
		if !claves[necesaria] {
			t.Errorf("falta %s: los motores no podrían correr", necesaria)
		}
	}
}

func TestEntornoLosExtraGanan(t *testing.T) {
	t.Setenv("PYTHONUTF8", "0")
	env := Entorno("PYTHONUTF8=1")
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, "PYTHONUTF8=") {
			n++
			if e != "PYTHONUTF8=1" {
				t.Errorf("el extra no ganó: %q", e)
			}
		}
	}
	if n != 1 {
		t.Errorf("PYTHONUTF8 aparece %d veces; debe aparecer una", n)
	}
}

// La prueba que de verdad importa: lanzar un proceso como lo hace un motor y
// comprobar que la clave no está en SU entorno, no sólo en la lista.
func TestUnProcesoRealNoVeLaApiKey(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	t.Setenv("FOUNDRY_API_KEY", "clave-secreta-de-prueba")

	cmd := exec.Command("cmd", "/c", "set")
	cmd.Env = Entorno("PYTHONUTF8=1")
	salida, err := Correr(context.Background(), cmd, MaxSalida)
	if err != nil {
		t.Fatalf("falló la ejecución de cmd.exe: %v", err)
	}
	visto := string(salida.Combinada())

	if strings.Contains(visto, "clave-secreta-de-prueba") {
		t.Error("el proceso hijo recibió la API key del modelo")
	}
	if !strings.Contains(strings.ToUpper(visto), "PYTHONUTF8=1") {
		t.Error("el proceso hijo no recibió las variables que sí necesita")
	}
}

// El sandbox puede no estar disponible (política de la máquina, Windows viejo).
// Lo que no puede es fallar en silencio: si no está, hay que poder decirlo.
func TestSandboxSeSabeSiEstaActivo(t *testing.T) {
	activo, err := SandboxActivo()
	if runtime.GOOS != "windows" {
		if activo {
			t.Error("fuera de Windows no hay token restringido")
		}
		return
	}
	if !activo {
		t.Logf("sandbox no disponible en esta máquina: %v", err)
		if err == nil {
			t.Error("si el sandbox no está activo, debe haber un motivo que mostrar")
		}
		return
	}
	if err != nil {
		t.Errorf("sandbox activo pero con error: %v", err)
	}
}

// Con el token restringido los motores tienen que seguir corriendo: un
// sandbox que rompe el análisis no sirve de nada.
func TestElSandboxNoRompeLaEjecucion(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	if activo, _ := SandboxActivo(); !activo {
		t.Skip("sandbox no disponible en esta máquina")
	}
	cmd := exec.Command("cmd", "/c", "echo funciona")
	cmd.Env = Entorno()
	salida, err := Correr(context.Background(), cmd, MaxSalida)
	if err != nil {
		t.Fatalf("el proceso no corrió dentro del sandbox: %v", err)
	}
	if !strings.Contains(string(salida.Stdout), "funciona") {
		t.Errorf("salida inesperada: %q", salida.Stdout)
	}
}

// El refresco de variables incorpora lo que falta y NO pisa lo que el proceso
// ya tiene: una variable presente puede venir de una decisión deliberada de la
// sesión (un venv activo, una clave exportada a mano para una prueba), y
// sobreescribirla con la del registro rompería esa intención.
//
// Este refresco existe porque la clave del modelo vive en HKCU\Environment: sin
// él, cada reinicio del daemon arrancaba sin la clave y la capa LLM se apagaba
// sola mientras la configuración decía "sin configurar" y la clave llevaba días
// guardada. Se comprobó con la sonda: antes=false → refrescadas=1 → después=true.
func TestIncorporarNoPisaLoQueYaEstaEnElProceso(t *testing.T) {
	t.Setenv("CG_PRUEBA_YA_PUESTA", "de-la-sesion")
	// CG_PRUEBA_NUEVA no existe en el proceso a propósito.

	n := incorporar(map[string]string{
		"CG_PRUEBA_YA_PUESTA": "del-registro",
		"CG_PRUEBA_NUEVA":     "del-registro",
	})
	t.Cleanup(func() { _ = os.Unsetenv("CG_PRUEBA_NUEVA") })

	if n != 1 {
		t.Errorf("sólo debía incorporar la que faltaba; incorporó %d", n)
	}
	if got := os.Getenv("CG_PRUEBA_YA_PUESTA"); got != "de-la-sesion" {
		t.Errorf("pisó la variable de la sesión: %q", got)
	}
	if got := os.Getenv("CG_PRUEBA_NUEVA"); got != "del-registro" {
		t.Errorf("no incorporó la que faltaba: %q", got)
	}
}

// Una variable vacía en el registro no se incorpora como vacía: sería
// indistinguible de "no está" para quien luego hace os.Getenv.
func TestIncorporarSinVariablesNoHaceNada(t *testing.T) {
	if n := incorporar(nil); n != 0 {
		t.Errorf("sin variables no hay nada que incorporar; devolvió %d", n)
	}
}
