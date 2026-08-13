//go:build windows

package proc

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ¿El sandbox es real?
//
// Existía el código y estaba cableado en Correr, pero eso no es lo mismo que
// que haga algo: `prepararSandbox` se rinde en silencio si no puede crear el
// token, y un sandbox que falla callado es indistinguible de no tenerlo. Esta
// prueba lo mide desde fuera, comparando los privilegios que Windows le da al
// mismo programa lanzado de las dos maneras.
//
// Se compara contra un lanzamiento NORMAL en la misma máquina y no contra una
// lista fija de privilegios: lo que hay en el token depende de si la cuenta es
// administradora, del dominio y de la política, así que una lista escrita a
// mano pasaría aquí y fallaría en el equipo de al lado.
func TestElSandboxQuitaPrivilegiosDeVerdad(t *testing.T) {
	activo, err := SandboxActivo()
	if !activo {
		t.Skipf("el token restringido no está disponible en esta máquina: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// whoami /priv enumera los privilegios del token del proceso que lo corre.
	sinCaja, err := exec.CommandContext(ctx, "whoami", "/priv").Output()
	if err != nil {
		t.Skipf("no se pudo correr whoami sin sandbox: %v", err)
	}
	conCaja, err := Correr(ctx, exec.CommandContext(ctx, "whoami", "/priv"), MaxSalida)
	if err != nil {
		t.Fatalf("whoami no corrió dentro del sandbox: %v", err)
	}

	libres := privilegios(string(sinCaja))
	presos := privilegios(string(conCaja.Stdout))

	if len(libres) == 0 {
		t.Skip("whoami no listó privilegios; sin base de comparación")
	}
	if len(presos) >= len(libres) {
		t.Fatalf("el sandbox NO está quitando nada: sin caja %d privilegios, con caja %d.\n"+
			"El código de contención existe y está cableado, pero no surte efecto — que es "+
			"exactamente el fallo que no se ve por leer el código.", len(libres), len(presos))
	}
	// SeChangeNotify se conserva a propósito: sin él un motor no puede recorrer
	// directorios, que es literalmente su trabajo.
	for _, p := range presos {
		if !strings.EqualFold(p, "SeChangeNotifyPrivilege") {
			t.Errorf("sobrevivió un privilegio que debería haberse caído: %s", p)
		}
	}
	t.Logf("privilegios: %d sin sandbox → %d dentro (%v)", len(libres), len(presos), presos)
}

// El sandbox no debe romper el trabajo: un motor tiene que poder leer el repo.
// Si al restringir el token se perdiera el acceso a archivos, los motores
// devolverían "limpio" por no poder leer nada — la peor forma de fallar.
func TestDentroDelSandboxTodaviaSePuedeLeerElDisco(t *testing.T) {
	if activo, _ := SandboxActivo(); !activo {
		t.Skip("sin token restringido no hay nada que comprobar")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	salida, err := Correr(ctx, exec.CommandContext(ctx, "cmd", "/c", "dir", dir), MaxSalida)
	if err != nil {
		t.Fatalf("dentro del sandbox no se pudo listar un directorio: %v", err)
	}
	if len(salida.Stdout) == 0 {
		t.Error("listar un directorio no devolvió nada; el motor estaría ciego y diría 'limpio'")
	}
}

// La otra mitad de la contención: el Job Object con KILL_ON_JOB_CLOSE tiene
// que matar a los NIETOS, no sólo al hijo directo.
//
// Importa de verdad con semgrep y trivy, que son lanzadores de Python con
// subprocesos propios: `exec.CommandContext` mata al lanzador y los hijos
// seguían vivos, invisibles para un hook que ya devolvió el control al usuario.
//
// La prueba lanza un nieto desligado que, si sobrevive, deja un archivo unos
// segundos después. Si el archivo aparece, el nieto escapó.
func TestElJobObjectMataALosNietos(t *testing.T) {
	if testing.Short() {
		t.Skip("espera unos segundos a que el nieto intente sobrevivir")
	}
	dir := t.TempDir()
	marca := filepath.Join(dir, "el-nieto-sobrevivio.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// `start /b` desliga al nieto del hijo: cmd sale enseguida y el nieto queda
	// suelto. Sin job object, nadie lo vuelve a mirar.
	orden := "start /b cmd /c \"ping -n 6 127.0.0.1 >nul & echo vivo > \"" + marca + "\"\""
	if _, err := Correr(ctx, exec.CommandContext(ctx, "cmd", "/c", orden), MaxSalida); err != nil {
		t.Fatalf("no se pudo lanzar el árbol de prueba: %v", err)
	}

	// Correr ya volvió y cerró el job. Se espera más de lo que tarda el nieto.
	time.Sleep(9 * time.Second)

	if _, err := os.Stat(marca); err == nil {
		t.Fatal("el nieto sobrevivió al cierre del job: un motor puede dejar procesos " +
			"corriendo después de que el hook le diga al usuario que terminó")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no se pudo comprobar la marca: %v", err)
	}
}

func privilegios(salida string) []string {
	var out []string
	for _, l := range strings.Split(salida, "\n") {
		campo := strings.Fields(strings.TrimSpace(l))
		if len(campo) > 0 && strings.HasPrefix(campo[0], "Se") && strings.HasSuffix(campo[0], "Privilege") {
			out = append(out, campo[0])
		}
	}
	return out
}
