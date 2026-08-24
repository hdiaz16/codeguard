//go:build windows

package main

// definidaEnElUsuario ya no consulta el registro de Windows (Zero-Registry).
// Las credenciales viven exclusivamente en el Administrador de credenciales
// o en el entorno del proceso actual.
func definidaEnElUsuario(string) bool {
	return false
}
