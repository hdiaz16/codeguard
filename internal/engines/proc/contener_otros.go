//go:build !windows

package proc

import "os/exec"

// En Unix el equivalente es un grupo de procesos propio (Setpgid) y un
// kill al grupo entero. CodeGuard sólo se distribuye para Windows hoy, así
// que aquí no contenemos nada: exec.CommandContext mata al hijo directo y
// los nietos quedan a cargo del sistema.
func contener(*exec.Cmd) (func(), error) { return func() {}, nil }
