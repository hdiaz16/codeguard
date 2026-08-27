//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"

	"codeguard/internal/ipc"
)

// Instancia única del daemon.
//
// El daemon no tenía guarda, y la consecuencia se midió en la máquina de
// Héctor el 2026-08-26: DOS procesos codeguard-daemon.exe vivos, lanzados los
// dos por Explorer al iniciar sesión (un residuo en HKCU\...\Run que el
// instalador .exe nunca limpió, más el acceso directo de Inicio). El segundo
// no conseguía el pipe —«Access is denied»—, lo escribía en el log, y SEGUÍA
// ADELANTE: creaba su WebView2 y su orbe.
//
// Resultado: dos orbes visibles en el mismo rectángulo exacto,
// (2258,1210)-(2558,1390), y el que quedaba ENCIMA en el z-order era el del
// proceso sin pipe. El usuario veía —y clicaba— un orbe que no recibe eventos,
// no cambia de estado y no responde a nada. Su queja fue «no veo el orbe
// inicializarse», y era literalmente cierta: el que veía, no.
//
// Un indicador de seguridad que se pinta sin estar conectado a nada es peor
// que ausente: afirma en silencio que está vigilando.
//
// El nombre sale de ipc.PipeName() y no del SID directamente, y es a
// propósito: CODEGUARD_PIPE sustituye el pipe entero para poder correr una
// instancia aislada (lo usan las pruebas). Si la exclusión se atara al SID,
// esa instancia aislada quedaría bloqueada por el daemon real del usuario, que
// es justo lo que la variable existe para evitar. Un solo origen, un solo
// ámbito.
//
// El prefijo es Local\ y no Global\: crear un objeto en el espacio global
// exige SeCreateGlobalPrivilege, que un usuario normal no tiene, y el agente
// se instala SIN admin (hardening 13). Local\ cubre el caso medido —dos
// arranques en la misma sesión—; el caso entre sesiones distintas del mismo
// usuario lo cubre la segunda defensa: si el servidor IPC no arranca, la
// aplicación se cierra en vez de dejar un orbe mudo (ver main.go).
func nombreDeLaInstancia() (string, error) {
	pipe, err := ipc.PipeName()
	if err != nil {
		return "", err
	}
	// Un nombre de objeto del kernel no admite '\' salvo el del prefijo de
	// espacio de nombres: el del pipe se sustituye.
	return `Local\` + strings.ReplaceAll(pipe, `\`, "_"), nil
}

// adquirirInstanciaUnica devuelve yaExiste=true cuando otro daemon del mismo
// usuario ya está en marcha. El mutex lo suelta Windows al morir el proceso,
// así que un daemon fusilado (taskkill, cierre de sesión, panic) no deja la
// puerta cerrada para el siguiente — que es el modo en que estas guardas
// suelen fallar.
func adquirirInstanciaUnica() (liberar func(), yaExiste bool, err error) {
	nombre, err := nombreDeLaInstancia()
	if err != nil {
		return nil, false, fmt.Errorf("nombre de la instancia: %w", err)
	}
	utf16, err := windows.UTF16PtrFromString(nombre)
	if err != nil {
		return nil, false, fmt.Errorf("nombre de la instancia: %w", err)
	}
	// CreateMutex devuelve el manejador TAMBIÉN cuando el objeto ya existía,
	// con err == ERROR_ALREADY_EXISTS. Hay que cerrarlo igual: no cerrarlo
	// dejaría una referencia viva al mutex del daemon bueno.
	h, err := windows.CreateMutex(nil, false, utf16)
	if err == windows.ERROR_ALREADY_EXISTS {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() { _ = windows.CloseHandle(h) }, false, nil
}
