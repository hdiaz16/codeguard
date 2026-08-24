package pipeline_test

import (
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// contenerDaemon mete el daemon de la prueba en un Job Object con
// KILL_ON_JOB_CLOSE, para que Windows lo mate PASE LO QUE PASE con el proceso
// de pruebas.
//
// El t.Cleanup con Kill() no basta, y esto no es teórico: en esta máquina
// quedó un codeguard-daemon.exe de las 23:36 corriendo desde el %TEMP% de una
// corrida anterior. Cleanup sólo corre si el binario de pruebas llega a
// ejecutarlo; cuando `go test` se muere de golpe —se agota el -timeout y el
// runtime aborta el proceso, alguien corta la sesión, el arnés lo mata— el
// daemon se queda huérfano, y Windows no adopta ni reapea a los hijos de un
// proceso muerto.
//
// El job es de otra naturaleza: el handle lo tiene el proceso de pruebas, y
// cuando ese proceso desaparece —por la vía que sea, incluido TerminateProcess—
// el sistema cierra sus handles y KILL_ON_JOB_CLOSE acaba con todo lo que
// quede dentro. Es la única forma en Windows de atar la vida de un hijo a la
// del padre.
//
// Es el mismo mecanismo que internal/engines/proc usa para que los nietos de
// semgrep y trivy no sobrevivan al hook; aquí se repite en vez de reutilizarse
// porque aquél va dentro de una política de contención (token restringido,
// topes de memoria, restricciones de interfaz) que a un daemon de prueba no le
// corresponde: lo único que se quiere de él es que muera cuando muera quien lo
// arrancó.
//
// Sin límites de memoria ni de procesos a propósito: el daemon levanta Wails y
// WebView2, que engendran lo suyo, y estrangularlos aquí convertiría esta red
// de seguridad en una fuente de fallos intermitentes.
func contenerDaemon(t *testing.T, c *exec.Cmd) {
	t.Helper()
	if c.Process == nil {
		t.Fatal("contenerDaemon: el proceso no había arrancado")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatalf("no se pudo crear el job object para el daemon: %v", err)
	}
	// Cerrar el handle es lo que dispara la matanza. Se hace también en el
	// camino de éxito: al terminar la prueba, el daemon se va con él.
	t.Cleanup(func() { _ = windows.CloseHandle(job) })

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		t.Fatalf("no se pudo configurar el job object del daemon: %v", err)
	}

	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(c.Process.Pid),
	)
	if err != nil {
		t.Fatalf("no se pudo abrir el daemon %d para contenerlo: %v", c.Process.Pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		t.Fatalf("no se pudo meter el daemon %d en el job: %v", c.Process.Pid, err)
	}
}
