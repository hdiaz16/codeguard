//go:build windows

package secreto

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW   = advapi32.NewProc("CredWriteW")
	procCredReadW    = advapi32.NewProc("CredReadW")
	procCredDeleteW  = advapi32.NewProc("CredDeleteW")
	procCredFree     = advapi32.NewProc("CredFree")
	errNoEncontrado  = errors.New("no hay ninguna credencial guardada con ese nombre")
	elementoNoExiste = syscall.Errno(1168) // ERROR_NOT_FOUND
)

const (
	credTypeGeneric      = 1
	credPersistLocalMach = 2 // sobrevive al cierre de sesión, no viaja al dominio

	// CRED_MAX_CREDENTIAL_BLOB_SIZE. Medido, no leído en la documentación:
	// 2560 bytes entran y 2561 fallan. Pasarse devuelve "The stub received bad
	// data", que es lo mismo que dice una estructura mal formada — o sea que
	// sin comprobarlo aquí, quien pegue una clave enorme se pasa la tarde
	// buscando un bug de alineación que no existe.
	//
	// De sobra para una clave de API, y 2,5 veces el límite de 1024 de `setx`
	// que fue la razón de escribir el registro a mano en su día. No se pierde
	// nada al mudarse.
	maxBlob = 2560
)

// credential refleja CREDENTIALW de wincred.h. El orden y los tipos importan:
// se pasa por puntero a la API de Windows, así que un campo de más o de menos
// desplaza todo lo que viene detrás.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// Guardar escribe el secreto en el Administrador de credenciales del usuario.
func Guardar(variable, valor string) error {
	destino, err := windows.UTF16PtrFromString(Nombre(variable))
	if err != nil {
		return err
	}
	usuario, err := windows.UTF16PtrFromString(variable)
	if err != nil {
		return err
	}
	comentario, err := windows.UTF16PtrFromString("Clave del modelo de CodeGuard")
	if err != nil {
		return err
	}
	blob := []byte(valor)
	if len(blob) > maxBlob {
		return fmt.Errorf("la clave ocupa %d bytes y el Administrador de credenciales "+
			"admite hasta %d: comprueba que pegaste la clave y no el token entero "+
			"o un archivo", len(blob), maxBlob)
	}
	c := credential{
		Type:               credTypeGeneric,
		TargetName:         destino,
		Comment:            comentario,
		CredentialBlobSize: uint32(len(blob)),
		Persist:            credPersistLocalMach,
		UserName:           usuario,
	}
	if len(blob) > 0 {
		c.CredentialBlob = &blob[0]
	}
	r, _, e := procCredWriteW.Call(uintptr(unsafe.Pointer(&c)), 0)
	// Los buffers y estructuras se mantienen vivos hasta después de la llamada:
	// sin esto el recolector podría moverlos o liberarlos durante la syscall.
	runtime.KeepAlive(&c)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(destino)
	runtime.KeepAlive(usuario)
	runtime.KeepAlive(comentario)
	if r == 0 {
		return fmt.Errorf("no se pudo guardar la credencial: %w", e)
	}
	return nil
}

// Leer devuelve el secreto guardado, o errNoEncontrado si no hay ninguno.
//
// El "no hay" se distingue del "no se pudo" a propósito: quien llama tiene que
// poder caer al método viejo cuando simplemente no se ha migrado todavía, y
// NO callar un fallo real de la bóveda.
func Leer(variable string) (string, error) {
	destino, err := windows.UTF16PtrFromString(Nombre(variable))
	if err != nil {
		return "", err
	}
	var pc *credential
	r, _, e := procCredReadW.Call(
		uintptr(unsafe.Pointer(destino)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&pc)),
	)
	runtime.KeepAlive(destino)
	if r == 0 {
		if errors.Is(e, elementoNoExiste) {
			return "", errNoEncontrado
		}
		return "", fmt.Errorf("no se pudo leer la credencial: %w", e)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pc)))

	if pc.CredentialBlobSize == 0 || pc.CredentialBlob == nil {
		return "", errNoEncontrado
	}
	return string(unsafe.Slice(pc.CredentialBlob, pc.CredentialBlobSize)), nil
}

// Borrar quita el secreto. Que no exista no es un error: borrar dos veces
// tiene que poder hacerse sin que la migración se caiga a la mitad.
func Borrar(variable string) error {
	destino, err := windows.UTF16PtrFromString(Nombre(variable))
	if err != nil {
		return err
	}
	r, _, e := procCredDeleteW.Call(uintptr(unsafe.Pointer(destino)), credTypeGeneric, 0)
	runtime.KeepAlive(destino)
	if r == 0 && !errors.Is(e, elementoNoExiste) {
		return fmt.Errorf("no se pudo borrar la credencial: %w", e)
	}
	return nil
}

// NoEncontrado dice si el error es "aquí no hay nada guardado", que es
// distinto de "la bóveda falló".
func NoEncontrado(err error) bool { return errors.Is(err, errNoEncontrado) }

// Disponible dice si esta máquina tiene bóveda utilizable. Se usa para poder
// decirlo en el diagnóstico en vez de fallar en silencio y volver al registro
// sin que nadie se entere.
func Disponible() bool { return advapi32.Load() == nil }
