//go:build windows

package main

import "golang.org/x/sys/windows/registry"

// definidaEnElUsuario mira si la variable existe en el entorno persistente del
// usuario aunque este proceso no la tenga.
//
// Windows entrega las variables de usuario sólo a los procesos que arrancan
// después de definirlas. Sin esta comprobación, una terminal abierta antes de
// configurar la clave reporta "sin definir" y manda al desarrollador a crear
// una que ya tiene.
func definidaEnElUsuario(nombre string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(nombre)
	return err == nil && v != ""
}
