//go:build !windows

package main

// Fuera de Windows no hay un entorno de usuario persistente que consultar: si
// la variable no está en el proceso, no está.
func definidaEnElUsuario(string) bool { return false }
