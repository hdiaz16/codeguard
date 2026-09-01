//go:build windows

package linters

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// rutaCanonicaExistente obtiene el nombre final que NTFS asigna a una ruta.
// filepath.EvalSymlinks resuelve enlaces, pero en Windows puede conservar un
// componente 8.3 (RUNNER~1); GetFinalPathNameByHandle devuelve la misma forma
// larga para el directorio raíz y para la ruta impresa por una herramienta.
func rutaCanonicaExistente(ruta string) (string, error) {
	f, err := os.Open(ruta)
	if err != nil {
		return "", err
	}
	defer f.Close()

	const capacidadRutaWindows = 32768
	buf := make([]uint16, capacidadRutaWindows)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], capacidadRutaWindows, 0)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= capacidadRutaWindows {
		return "", fmt.Errorf("ruta final de tamaño inesperado: %d", n)
	}
	final := windows.UTF16ToString(buf[:n])
	switch {
	case strings.HasPrefix(final, `\\?\UNC\`):
		final = `\\` + strings.TrimPrefix(final, `\\?\UNC\`)
	case strings.HasPrefix(final, `\\?\`):
		final = strings.TrimPrefix(final, `\\?\`)
	}
	return filepath.Clean(final), nil
}
