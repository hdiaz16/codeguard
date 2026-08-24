//go:build !windows

package proc

import (
	"errors"
	"os/exec"
)

// En Unix el equivalente es un grupo de procesos propio (Setpgid) y un
// kill al grupo entero. CodeGuard sólo se distribuye para Windows hoy, así
// que aquí no contenemos nada — y desde W4 se DICE: contener falla con nombre
// y el reporte de contención viaja con todas las facetas caídas, en vez de
// fingir un sandbox que en este SO no existe.
func contener(*exec.Cmd) (func(), bool, error) {
	return nil, false, errors.New("contención no implementada en este SO")
}

func prepararSandbox(*exec.Cmd) (bool, string) {
	return false, "sandbox no implementado en este SO"
}

// SinVentana: fuera de Windows no hay ventanas de consola que ocultar.
func SinVentana(*exec.Cmd) {}

// SandboxActivo: fuera de Windows no hay token restringido que aplicar.
func SandboxActivo() (bool, error) { return false, nil }
