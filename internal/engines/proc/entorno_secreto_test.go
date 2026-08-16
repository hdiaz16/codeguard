package proc

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"codeguard/internal/secreto"
)

// La clave que la bóveda gestiona NO puede volver al entorno del proceso desde
// el registro, aunque la copia vieja siga ahí.
//
// Es el cierre del círculo de la migración. Sin esta barrera, quitar la clave
// del entorno no sirve de nada mientras exista la copia del registro: el
// siguiente RefrescarVariables la ve "ausente del proceso" (entorno.go:104),
// la da por incorporable y la reinyecta. Pasaba en dos sitios reales — el
// round-trip de la pantalla de configuración, que recarga el estado y vuelve a
// refrescar, y la CLI, que refresca al arrancar y NUNCA migra.
//
// La bóveda es la fuente de verdad: si tiene la clave, la copia del registro es
// un resto, no una fuente.
func TestIncorporarNoResucitaUnSecretoQueYaEstaEnLaBoveda(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("sin bóveda fuera de Windows")
	}
	const variable = "CG_PRUEBA_SECRETO_BOVEDA"
	if err := secreto.Guardar(variable, "la-buena-en-la-boveda"); err != nil {
		t.Skipf("sin bóveda utilizable: %v", err)
	}
	t.Cleanup(func() {
		_ = secreto.Borrar(variable)
		_ = os.Unsetenv(variable)
	})
	_ = os.Unsetenv(variable)

	n := incorporar(map[string]string{
		variable:          "la-copia-rezagada-del-registro",
		"CG_PRUEBA_LLANA": "esta-sí-entra",
	})
	t.Cleanup(func() { _ = os.Unsetenv("CG_PRUEBA_LLANA") })

	if v, hay := os.LookupEnv(variable); hay {
		t.Errorf("reinyectó al proceso un secreto de la bóveda (%q): a partir de "+
			"aquí lo hereda cualquier hijo sin cmd.Env", v)
	}
	if n != 1 {
		t.Errorf("incorporó %d variables; esperaba 1 (sólo la que no es secreto)", n)
	}
	if os.Getenv("CG_PRUEBA_LLANA") != "esta-sí-entra" {
		t.Error("la barrera se llevó por delante una variable normal: el refresco " +
			"tiene que seguir funcionando para todo lo demás")
	}
}

// EntornoGit conserva las variables GIT_* y sigue dejando fuera la clave.
//
// Las GIT_* no son un capricho: git las usa para saber QUÉ índice mira. Con
// `git commit -a`, git prepara un índice temporal y se lo pasa al hook en
// GIT_INDEX_FILE; si la filtramos, `git diff --cached` leería el índice real y
// analizaríamos un conjunto de cambios distinto del que se está commiteando —
// una compuerta de seguridad mirando el archivo equivocado, sin decir nada.
func TestEntornoGitConservaLasGitPeroNoLaClave(t *testing.T) {
	t.Setenv("FOUNDRY_API_KEY", "clave-que-git-no-necesita")
	t.Setenv("GIT_INDEX_FILE", "C:\\repo\\.git\\next-index-1234")
	t.Setenv("GIT_DIR", "C:\\repo\\.git")

	env := EntornoGit()
	unido := strings.Join(env, "\n")

	for _, necesaria := range []string{
		"GIT_INDEX_FILE=C:\\repo\\.git\\next-index-1234",
		"GIT_DIR=C:\\repo\\.git",
	} {
		if !strings.Contains(unido, necesaria) {
			t.Errorf("falta %q: git miraría el índice equivocado", necesaria)
		}
	}
	if strings.Contains(unido, "clave-que-git-no-necesita") {
		t.Error("la clave del modelo viaja hasta git")
	}
	// Y lo que Entorno ya garantizaba sigue en pie.
	if !strings.Contains(strings.ToUpper(unido), "PATH=") {
		t.Error("sin PATH git no encuentra ni sus propios subcomandos")
	}
}

// Un secreto con nombre GIT_* tampoco pasa: el prefijo abre la puerta a git, no
// a la bóveda.
func TestEntornoGitNoDejaPasarUnSecretoConNombreGit(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("sin bóveda fuera de Windows")
	}
	const variable = "GIT_PRUEBA_CLAVE_GESTIONADA"
	if err := secreto.Guardar(variable, "secreto-con-nombre-de-git"); err != nil {
		t.Skipf("sin bóveda utilizable: %v", err)
	}
	t.Cleanup(func() { _ = secreto.Borrar(variable) })
	t.Setenv(variable, "secreto-con-nombre-de-git")

	if strings.Contains(strings.Join(EntornoGit(), "\n"), "secreto-con-nombre-de-git") {
		t.Error("un secreto de la bóveda se coló por el prefijo GIT_")
	}
}

// La prueba que de verdad cuenta para git: un proceso real lanzado con este
// entorno no ve la clave.
func TestUnProcesoRealConEntornoGitNoVeLaClave(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	t.Setenv("FOUNDRY_API_KEY", "clave-secreta-de-prueba-git")
	t.Setenv("GIT_INDEX_FILE", "indice-de-prueba")

	cmd := exec.Command("cmd", "/c", "set")
	cmd.Env = EntornoGit()
	salida, _ := Correr(context.Background(), cmd, MaxSalida)
	visto := string(salida.Combinada())

	if strings.Contains(visto, "clave-secreta-de-prueba-git") {
		t.Error("el proceso hijo recibió la API key del modelo")
	}
	if !strings.Contains(visto, "indice-de-prueba") {
		t.Error("el proceso hijo no recibió GIT_INDEX_FILE, que es lo que le dice " +
			"a git qué índice está commiteando")
	}
}
