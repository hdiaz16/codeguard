//go:build !windows

package proc

// Fuera de Windows el PATH del proceso es el bueno: no hay registro del que
// pueda quedar desincronizado.
func pathVigente() string { return "" }

// variablesDeUsuario: fuera de Windows no hay registro de entorno de usuario.
func variablesDeUsuario() map[string]string { return nil }
