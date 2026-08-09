//go:build windows

package proc

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sandbox de los motores. No es una máquina virtual ni un contenedor: es
// reducir lo que un binario de terceros puede hacer en la máquina del
// desarrollador, usando lo que Windows ya ofrece.
//
// Tres capas, de más a menos importante:
//
//  1. Entorno acotado (entorno.go): los motores dejan de recibir la API key
//     del modelo y cualquier otro secreto que viva en el entorno del daemon.
//  2. Token restringido: el proceso pierde todos los privilegios salvo el de
//     notificación de cambios. Un gitleaks comprometido ya no puede depurar
//     otros procesos, apagar el equipo ni tomar propiedad de archivos.
//  3. Job Object con límites duros y restricciones de interfaz: tope de
//     memoria y de procesos, y prohibición de tocar el portapapeles, el
//     escritorio, los parámetros del sistema o las ventanas de otros.
//
// Lo que NO hace: no restringe el acceso al sistema de archivos. Un motor
// tiene que leer el repositorio, y aislar eso exigiría un AppContainer con
// ACLs sobre cada repo, con un coste de arranque y una fragilidad que no
// compensan frente a binarios que verificamos por hash (ver identidad).

const (
	// Sin límite de memoria un motor con fuga se lleva la máquina por delante.
	// 4 GB es holgado: el pico medido de trivy sobre un monorepo ronda 1 GB.
	maxMemoriaJob = 4 << 30
	// Semgrep abre un proceso por núcleo; 64 deja sitio de sobra y aun así
	// corta una bomba de forks.
	maxProcesos = 64
)

// Constantes de restricción de interfaz que x/sys/windows no exporta.
const (
	jobObjectBasicUIRestrictions = 4

	uilimitHandles          = 0x00000001 // no usar handles de USER de fuera del job
	uilimitReadClipboard    = 0x00000002
	uilimitWriteClipboard   = 0x00000004
	uilimitSystemParameters = 0x00000008
	uilimitDisplaySettings  = 0x00000010
	uilimitGlobalAtoms      = 0x00000020
	uilimitDesktop          = 0x00000040
	uilimitExitWindows      = 0x00000080

	disableMaxPrivilege = 0x1
)

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")

	// El token se crea una vez y se reutiliza: derivarlo en cada commit
	// costaba una llamada al sistema por motor sin ganar nada.
	tokenUnaVez sync.Once
	tokenCache  windows.Token
	tokenErr    error
)

// prepararSandbox ajusta el comando ANTES de arrancarlo. Se llama siempre;
// si el token restringido no se puede crear, el motor corre igual y quien
// llama se entera por SandboxActivo().
func prepararSandbox(c *exec.Cmd) {
	tok, err := tokenRestringido()
	if err != nil {
		return
	}
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Token = syscall.Token(tok)
}

// SandboxActivo dice si el token restringido está disponible en esta máquina.
// Se expone para poder mostrarlo en el diagnóstico: un sandbox que falla en
// silencio es indistinguible de no tener sandbox.
func SandboxActivo() (bool, error) {
	_, err := tokenRestringido()
	return err == nil, err
}

// tokenRestringido deriva del token del daemon uno sin privilegios.
//
// DISABLE_MAX_PRIVILEGE quita todos los privilegios menos SeChangeNotify, que
// hace falta para recorrer directorios. No toca los SIDs ni los permisos de
// archivos: el motor sigue pudiendo leer el repositorio, que es su trabajo.
func tokenRestringido() (windows.Token, error) {
	tokenUnaVez.Do(func() {
		var actual windows.Token
		err := windows.OpenProcessToken(
			windows.CurrentProcess(),
			windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
			&actual,
		)
		if err != nil {
			tokenErr = fmt.Errorf("no se pudo abrir el token del proceso: %w", err)
			return
		}
		defer actual.Close()

		var restringido windows.Token
		r, _, e := procCreateRestrictedToken.Call(
			uintptr(actual),
			uintptr(disableMaxPrivilege),
			0, 0, // SIDs a deshabilitar
			0, 0, // privilegios a borrar (los cubre DISABLE_MAX_PRIVILEGE)
			0, 0, // SIDs restrictivos: ninguno, romperían el acceso al repo
			uintptr(unsafe.Pointer(&restringido)),
		)
		if r == 0 {
			tokenErr = fmt.Errorf("CreateRestrictedToken falló: %w", e)
			return
		}
		tokenCache = restringido
	})
	return tokenCache, tokenErr
}

// contener mete el proceso recién arrancado en un Job Object con límites.
//
// KILL_ON_JOB_CLOSE es lo que mata a los nietos: al cerrar el handle del job
// —cosa que hacemos siempre, terminen bien o mal— Windows acaba con todo lo
// que quede dentro. Importa con Semgrep y Trivy, que son lanzadores de Python
// con subprocesos propios: exec.CommandContext mata al lanzador y los hijos
// seguían vivos, invisibles para el hook que ya devolvió el control.
//
// Queda una ventana mínima entre Start y AssignProcessToJobObject en la que el
// hijo podría engendrar un nieto que escape. Cerrarla exige arrancar suspendido
// y os/exec no expone el handle del hilo principal para reanudarlo. Con
// binarios verificados por hash, no con código hostil, la ventana no es un
// riesgo real.
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
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
				windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
				windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
			ActiveProcessLimit: maxProcesos,
		},
		JobMemoryLimit: maxMemoriaJob,
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

	// Un linter no tiene nada que hacer en el portapapeles, el escritorio ni
	// las ventanas de otros programas. Prohibirlo no le cuesta nada y quita
	// de en medio toda una familia de abusos.
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{
		UIRestrictionsClass: uilimitHandles | uilimitReadClipboard |
			uilimitWriteClipboard | uilimitSystemParameters |
			uilimitDisplaySettings | uilimitGlobalAtoms |
			uilimitDesktop | uilimitExitWindows,
	}
	// Si esto falla no abortamos: las restricciones de interfaz son la capa
	// menos crítica y perderlas no justifica dejar sin analizar el commit.
	windows.SetInformationJobObject(
		job,
		jobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)),
		uint32(unsafe.Sizeof(ui)),
	)

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
