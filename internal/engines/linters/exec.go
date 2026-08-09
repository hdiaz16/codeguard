package linters

import (
	"bytes"
	"context"
	"errors"
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
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && !salida.Recortada {
		return "", err // no arrancó (binario ausente, permisos...)
	}
	// Los linters se leen línea por línea: un texto recortado sigue siendo
	// útil, a diferencia de un JSON a medias.
	return string(salida.Combinada()), nil
}

// runToolStdin ejecuta una herramienta pasándole contenido por la entrada
// estándar y devuelve su salida. Se usa para preguntarle a gofmt cómo
// formatearía un contenido concreto, sin depender de lo que haya en disco.
func runToolStdin(ctx context.Context, dir, bin string, entrada []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = proc.Entorno()
	cmd.Stdin = bytes.NewReader(entrada)
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
	}
	return salida.Stdout, nil
}

func relTo(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}
