//go:build windows

package main

import (
	"testing"

	"codeguard/internal/secreto"
)

// El ciclo COMPLETO contra la bóveda real de Windows: guardar, leer, olvidar,
// y comprobar que después no queda nada.
//
// Durante meses existió la mitad de la operación: `--guardar-clave` metía una
// clave de API en el Administrador de credenciales y no había ninguna orden
// para sacarla. secreto.Borrar estaba escrita, probada y documentada desde el
// principio — simplemente no la llamaba nadie. Esta prueba fija que ya sí, y
// que el camino de olvido cumple lo que promete.
//
// Corre contra la bóveda de verdad y no contra un doble a propósito: lo que
// se está afirmando es que el secreto DESAPARECE de la máquina, y eso un
// falso no lo puede demostrar. Usa un nombre de variable propio y lo limpia
// pase lo que pase.
func TestOlvidarClaveBorraDeLaBovedaDeVerdad(t *testing.T) {
	if !secreto.Disponible() {
		t.Skip("sin Administrador de credenciales en esta máquina")
	}
	const variable = "CODEGUARD_PRUEBA_OLVIDAR_CLAVE"
	const valor = "clave-de-prueba-que-no-vale-para-nada"

	t.Cleanup(func() { _ = secreto.Borrar(variable) })

	if err := secreto.Guardar(variable, valor); err != nil {
		t.Fatalf("no se pudo sembrar la clave de prueba: %v", err)
	}
	if v, err := secreto.Leer(variable); err != nil || v != valor {
		t.Fatalf("la siembra no cuajó: v=%q err=%v", v, err)
	}

	if err := olvidarClaveGuardada(variable); err != nil {
		t.Fatalf("olvidar falló: %v", err)
	}

	// Lo que de verdad importa: ya no está.
	if _, err := secreto.Leer(variable); err == nil {
		t.Fatal("la clave sigue en el Administrador de credenciales después de olvidarla")
	} else if !secreto.NoEncontrado(err) {
		t.Fatalf("la bóveda respondió algo que no es «no encontrado»: %v", err)
	}
}

// Olvidar algo que no está no es un error: quien rota una clave o repite la
// orden no debe encontrarse un fallo, y un script de desenrolado tiene que
// poder correr dos veces.
func TestOlvidarUnaClaveQueNoEstaNoFalla(t *testing.T) {
	if !secreto.Disponible() {
		t.Skip("sin Administrador de credenciales en esta máquina")
	}
	const variable = "CODEGUARD_PRUEBA_CLAVE_INEXISTENTE"
	_ = secreto.Borrar(variable) // por si una corrida anterior murió a medias

	if err := olvidarClaveGuardada(variable); err != nil {
		t.Fatalf("olvidar algo ausente debía ser un no-op limpio, salió: %v", err)
	}
	if err := olvidarClaveGuardada(variable); err != nil {
		t.Fatalf("y debía poder repetirse: %v", err)
	}
}
