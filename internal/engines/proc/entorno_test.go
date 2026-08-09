package proc

import (
	"context"
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
	for _, necesaria := range []string{"PATH", "SYSTEMROOT", "TEMP"} {
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
	salida, _ := Correr(context.Background(), cmd, MaxSalida)
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
