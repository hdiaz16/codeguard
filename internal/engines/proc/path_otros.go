//go:build !windows

package proc

// Fuera de Windows el PATH del proceso es el bueno: no hay registro del que
// pueda quedar desincronizado.
func pathVigente() string { return "" }
