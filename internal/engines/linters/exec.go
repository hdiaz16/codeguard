package linters

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

// runTool ejecuta una herramienta y devuelve stdout+stderr combinados.
// Un exit code != 0 NO es error si hubo salida (los linters salen con 1
// cuando encuentran problemas); sin salida sí es fallo de ejecución.
func runTool(ctx context.Context, dir, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return "", err // no arrancó (binario ausente, permisos...)
	}
	return buf.String(), nil
}

func relTo(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}
