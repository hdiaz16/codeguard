//go:build windows

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// lockDeMigraciones toma el mutex nombrado del SO que serializa las
// migraciones ENTRE PROCESOS ([07] del plan). BEGIN IMMEDIATE ya arbitra a
// nivel SQLite, pero su perdedor moría al agotar busy_timeout con «database
// is locked» y cero diagnóstico; el mutex da una espera acotada y un error
// que dice qué está pasando y qué hacer.
//
// Ámbito `Local\` y no `Global\` (turnos 89/92): la BD vive en %LOCALAPPDATA%
// —es POR USUARIO— así que la sesión local es el ámbito correcto por
// construcción, y Global\ exigiría SeCreateGlobalPrivilege que un usuario
// estándar en Terminal Server no tiene: el lock fallaría justo donde más
// sesiones concurrentes hay.
//
// El nombre deriva de la ruta CANÓNICA case-insensitive: dos procesos que
// escriban la misma ruta con grafías distintas (mayúsculas, alias 8.3,
// symlink) deben caer en EL MISMO mutex — dos nombres serían dos mutex y el
// lock no existiría exactamente cuando hace falta.
func lockDeMigraciones(ruta string) (func(), error) {
	if ruta == ":memory:" || strings.HasPrefix(ruta, "file::memory:") {
		// BD privada del proceso: no hay inter-proceso que arbitrar.
		return func() {}, nil
	}
	canonica := ruta
	if eval, err := filepath.EvalSymlinks(ruta); err == nil && eval != "" {
		canonica = eval
	} else if abs, err := filepath.Abs(ruta); err == nil && abs != "" {
		// El archivo puede no existir todavía (primer Open): Abs es el
		// canónico alcanzable.
		canonica = abs
	}
	canonica = strings.ToLower(filepath.Clean(canonica))
	h := sha256.Sum256([]byte(canonica))
	nombre, err := windows.UTF16PtrFromString(`Local\codeguard-migraciones-` + hex.EncodeToString(h[:16]))
	if err != nil {
		return nil, err
	}
	mutex, err := windows.CreateMutex(nil, false, nombre)
	// ERROR_ALREADY_EXISTS no es un error: significa que otro proceso lo creó
	// primero y este handle apunta al MISMO mutex — que es el punto.
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return nil, fmt.Errorf("no se pudo crear el mutex de migraciones: %w", err)
	}
	const plazoMS = 15000
	ev, err := windows.WaitForSingleObject(mutex, plazoMS)
	switch ev {
	case windows.WAIT_OBJECT_0:
		// Nuestro.
	case windows.WAIT_ABANDONED:
		// El dueño anterior murió sin soltar: el SO nos lo transfiere. La
		// transacción de Migrate re-verifica todo contra la BD real, así que
		// heredar el mutex de un proceso muerto es seguro — y se dice.
		fmt.Printf("migraciones: el proceso anterior murió con el lock tomado; se hereda y se re-verifica\n")
	case uint32(windows.WAIT_TIMEOUT):
		windows.CloseHandle(mutex)
		return nil, fmt.Errorf("otro proceso lleva >%ds migrando la misma BD (%s): "+
			"suele ser un daemon o un hook a mitad de arranque — espera a que termine o revisa el administrador de tareas",
			plazoMS/1000, filepath.Base(canonica))
	default:
		windows.CloseHandle(mutex)
		return nil, fmt.Errorf("esperando el mutex de migraciones: %w", err)
	}
	return func() {
		_ = windows.ReleaseMutex(mutex)
		_ = windows.CloseHandle(mutex)
	}, nil
}
