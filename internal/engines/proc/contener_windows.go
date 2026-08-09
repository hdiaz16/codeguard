//go:build windows

package proc

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// contener mete el proceso recién arrancado en un Job Object marcado con
// KILL_ON_JOB_CLOSE. Al cerrar el handle del job —cosa que hacemos siempre,
// terminen bien o mal— Windows mata a todo lo que quede dentro, incluidos los
// nietos.
//
// Esto importa de verdad con Semgrep y Trivy: ambos son lanzadores de Python
// que arrancan subprocesos propios. exec.CommandContext mata al lanzador al
// vencer el plazo y los subprocesos siguen vivos consumiendo CPU, invisibles
// para el hook que ya devolvió el control.
//
// Queda una ventana mínima entre Start y AssignProcessToJobObject en la que el
// hijo podría engendrar un nieto que escape del job. Cerrarla exige arrancar
// suspendido, y os/exec no expone el handle del hilo principal para reanudarlo.
// Con motores conocidos —no código hostil— la ventana no es un riesgo real.
func contener(c *exec.Cmd) (func(), error) {
	if c.Process == nil {
		return nil, fmt.Errorf("el proceso no había arrancado")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear el job object: %w", err)
	}
	limpiar := func() { windows.CloseHandle(job) }

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
		limpiar()
		return nil, fmt.Errorf("no se pudo configurar el job object: %w", err)
	}

	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(c.Process.Pid),
	)
	if err != nil {
		limpiar()
		return nil, fmt.Errorf("no se pudo abrir el proceso %d: %w", c.Process.Pid, err)
	}
	defer windows.CloseHandle(h)

	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		limpiar()
		return nil, fmt.Errorf("no se pudo asignar el proceso al job: %w", err)
	}
	return limpiar, nil
}
