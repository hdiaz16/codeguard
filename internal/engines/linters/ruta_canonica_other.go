//go:build !windows

package linters

import "path/filepath"

func rutaCanonicaExistente(ruta string) (string, error) {
	return filepath.EvalSymlinks(ruta)
}
