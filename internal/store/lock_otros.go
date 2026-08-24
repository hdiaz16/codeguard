//go:build !windows

package store

// En plataformas sin mutex nombrado, el arbitraje inter-proceso queda en el
// BEGIN IMMEDIATE + busy_timeout de SQLite (el producto se distribuye solo
// para Windows; el split portable es deuda planificada de W6).
func lockDeMigraciones(string) (func(), error) {
	return func() {}, nil
}
