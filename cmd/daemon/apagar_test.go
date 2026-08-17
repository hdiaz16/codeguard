package main

import (
	"testing"

	"codeguard/internal/ipc"
)

// EL DESINSTALADOR NO TENÍA FORMA DE PEDIR EL APAGADO, ASÍ QUE MATABA.
//
// Y un daemon fusilado con Stop-Process no llega a quitar su icono: Windows
// deja un orbe FANTASMA pintado en la bandeja, que en la barra nueva de
// Windows 11 sólo se va reiniciando Explorer. Se vio en vivo dos veces el
// mismo día — el usuario preguntando por qué había dos orbes.
//
// El comando «apagar» por IPC va por el mismo camino que el botón «Salir de
// CodeGuard» del menú (app.Quit()), que sí desmonta la bandeja antes de morir.
func TestElComandoApagarTerminaPorElCaminoDelMenu(t *testing.T) {
	e, _ := escritorioDePrueba(nil)
	e.tray = &trayState{}
	apagados := 0
	e.apagar = func() { apagados++ }

	e.alComandoDeLaCLI("apagar", &ipc.Request{})

	if apagados != 1 {
		t.Fatalf("apagar se invocó %d veces, se esperaba 1: sin esto el desinstalador "+
			"vuelve al Stop-Process y al orbe fantasma", apagados)
	}
}

// Un comando desconocido no puede apagar nada — ni hacer nada. Es la
// contraparte: si cualquier ruido apagara el daemon, el «apagar» de arriba
// pasaría el test por accidente.
func TestUnComandoDesconocidoNoApaga(t *testing.T) {
	e, _ := escritorioDePrueba(nil)
	e.tray = &trayState{}
	apagados := 0
	e.apagar = func() { apagados++ }

	e.alComandoDeLaCLI("ping", &ipc.Request{})
	e.alComandoDeLaCLI("", &ipc.Request{})

	if apagados != 0 {
		t.Fatalf("un comando que no es «apagar» apagó el daemon %d vez(ces)", apagados)
	}
}
