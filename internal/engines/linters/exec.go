package linters

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"codeguard/internal/engines/proc"
)

// runTool ejecuta una herramienta y devuelve stdout+stderr combinados.
// Un exit code != 0 NO es error si hubo salida (los linters salen con 1
// cuando encuentran problemas); sin salida sí es fallo de ejecución.
func runTool(ctx context.Context, dir, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	// Herramientas Python en Windows: sin esto leen/escriben en cp1252
	// y rompen los acentos (mismo fix que en el adaptador de semgrep).
	cmd.Env = append(os.Environ(), "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && !salida.Recortada {
		return "", err // no arrancó (binario ausente, permisos...)
	}
	// Los linters se leen línea por línea: un texto recortado sigue siendo
	// útil, a diferencia de un JSON a medias.
	return string(salida.Combinada()), nil
}

func relTo(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}
