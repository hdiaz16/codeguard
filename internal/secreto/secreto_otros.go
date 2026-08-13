//go:build !windows

package secreto

import "errors"

// Fuera de Windows no hay bóveda que usar. CodeGuard sólo se distribuye para
// Windows hoy; estas funciones existen para que el paquete compile en las
// máquinas donde se corren pruebas o se compila cruzado.
//
// Devuelven "no encontrado" y no un error de verdad para que quien llama caiga
// limpiamente al método de siempre en vez de tratarlo como una avería.

var errNoDisponible = errors.New("no hay bóveda de credenciales en este sistema")

func Guardar(string, string) error { return errNoDisponible }

func Leer(string) (string, error) { return "", errNoDisponible }

func Borrar(string) error { return nil }

func NoEncontrado(err error) bool { return errors.Is(err, errNoDisponible) }

func Disponible() bool { return false }
