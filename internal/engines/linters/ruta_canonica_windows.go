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
	// GetFinalPathNameByHandle no siempre expande componentes 8.3 en los
	// volúmenes de GitHub Actions. GetLongPathNameW tiene precisamente ese
	// contrato; se aplica antes de abrir para que tanto la raíz como el archivo
	// entren al resto del proceso con los mismos nombres almacenados.
	entrada, err := windows.UTF16PtrFromString(filepath.Clean(ruta))
	if err != nil {
		return "", err
	}
	const capacidadRutaWindows = 32768
	larga := make([]uint16, capacidadRutaWindows)
	nLarga, errLarga := windows.GetLongPathName(entrada, &larga[0], capacidadRutaWindows)
	if errLarga == nil && nLarga > 0 && nLarga < capacidadRutaWindows {
		ruta = windows.UTF16ToString(larga[:nLarga])
	}

	f, err := os.Open(ruta)
	if err != nil {
		return "", err
	}
	defer f.Close()

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
