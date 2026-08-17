//go:build windows

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"codeguard/internal/secreto"
)

// sustituirBoveda cambia los puntos de sustitución y los restaura al terminar.
// Las ramas de error que cubren no se pueden provocar contra el Administrador
// de credenciales real.
func sustituirBoveda(t *testing.T, leer func(string) (string, error), borrar func(string) error) {
	t.Helper()
	leerPrevio, borrarPrevio := leerDeBoveda, borrarDelRegistro
	t.Cleanup(func() { leerDeBoveda, borrarDelRegistro = leerPrevio, borrarPrevio })
	if leer != nil {
		leerDeBoveda = leer
	}
	if borrar != nil {
		borrarDelRegistro = borrar
	}
}

// sustituirGuardado cambia sólo la ESCRITURA en la bóveda.
//
// Va aparte de sustituirBoveda porque hace falta en menos sitios y por un
// motivo distinto: las pruebas de las ramas de error de guardarClave no
// necesitan que la clave llegue a ninguna parte, y hasta ahora escribían una
// credencial de verdad en el Administrador de credenciales del usuario sólo
// para comprobar que el PASO SIGUIENTE fallaba. Si una de ellas muere a mitad
// —un Ctrl-C, un timeout de CI— el t.Cleanup no corre y esa credencial se queda
// ahí. Sustituyendo la escritura, esas dos pruebas dejan de tocar el sistema.
func sustituirGuardado(t *testing.T, guardar func(string, string) error) {
	t.Helper()
	previo := guardarEnBoveda
	t.Cleanup(func() { guardarEnBoveda = previo })
	guardarEnBoveda = guardar
}

const varPruebaEntorno = "CODEGUARD_H003_PRUEBA"

// Guardar la clave no puede dejarla en el entorno de ESTE proceso.
//
// El daemon lanza hijos sin entorno acotado —trivy en warmup.go, npx/tsc en el
// mismo archivo, git en gitdiff.go—, y un proceso hijo sin cmd.Env hereda
// os.Environ() entero. O sea que una sola variable puesta aquí reabre
// exactamente el vector que la mudanza a la bóveda cerró: la clave vuelve a
// viajar a cada herramienta de terceros que el daemon ejecute.
//
// Se comprueban las dos caras porque no son la misma: os.Getenv es lo que ve
// este código, y os.Environ() es lo que se le entrega literalmente al hijo.
func TestGuardarNoDejaLaClaveEnElEntornoDelProceso(t *testing.T) {
	const valor = "clave-que-no-debe-heredarse"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
		_ = borrarVariableUsuario(varPruebaEntorno)
		_ = os.Unsetenv(varPruebaEntorno)
	})
	_ = secreto.Borrar(varPruebaEntorno)
	_ = os.Unsetenv(varPruebaEntorno)

	if err := guardarClave(varPruebaEntorno, valor); err != nil {
		t.Fatalf("guardarClave: %v", err)
	}

	// (a) La clave tiene que estar guardada de verdad: sin esto, "no está en el
	// entorno" se cumpliría también si no se hubiera guardado en ningún sitio.
	got, err := secreto.Leer(varPruebaEntorno)
	if err != nil {
		t.Fatalf("la clave no llegó a la bóveda: %v", err)
	}
	if got != valor {
		t.Errorf("en la bóveda quedó %q, esperaba %q", got, valor)
	}

	// (b) Y no puede estar en el entorno del proceso.
	if v := os.Getenv(varPruebaEntorno); v != "" {
		t.Errorf("la clave quedó en el entorno del daemon (%q): todo hijo lanzado "+
			"sin cmd.Env se la lleva", v)
	}
	for _, e := range os.Environ() {
		if nombre, val, _ := strings.Cut(e, "="); nombre == varPruebaEntorno {
			t.Errorf("la clave viaja en os.Environ() (%q): es literalmente lo que "+
				"recibe un exec.Command sin entorno acotado", val)
		}
	}
}

// El caso de la actualización: el proceso ya ARRASTRABA una copia de la clave
// en su entorno antes de guardar.
//
// No es hipotético — es el camino normal de quien viene de una versión
// anterior. leerConfigLLM llama a proc.RefrescarVariables(), que importa al
// proceso las variables de usuario del registro, así que el daemon arranca con
// la clave vieja dentro. Quitar el os.Setenv de guardarClave no basta para esas
// máquinas: la copia heredada sigue ahí y sigue bajando a cada hijo.
func TestGuardarLimpiaLaCopiaHeredadaEnElEntorno(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
		_ = borrarVariableUsuario(varPruebaEntorno)
		_ = os.Unsetenv(varPruebaEntorno)
	})
	t.Setenv(varPruebaEntorno, "la-que-arrastraba-el-proceso")

	if err := guardarClave(varPruebaEntorno, "la-que-acabo-de-pegar"); err != nil {
		t.Fatalf("guardarClave: %v", err)
	}
	if v := os.Getenv(varPruebaEntorno); v != "" {
		t.Errorf("la copia heredada sigue en el entorno (%q): guardar desde la "+
			"pantalla tiene que dejarlo limpio, no sólo dejar de ensuciarlo", v)
	}
}

// Si la bóveda acepta el guardado pero luego no devuelve lo mismo, hay que
// fallar en voz alta.
//
// Ya no queda copia en el entorno que disimule el fallo: una escritura que se
// pierde en silencio dejaría al usuario con la pantalla diciendo "guardada" y
// la capa LLM apagada. La ida y vuelta es lo único que distingue las dos cosas.
func TestGuardarVerificaLaIdaYVuelta(t *testing.T) {
	const valor = "clave-con-acentos-áéí-y-símbolos-!@#$%^&*()"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
		_ = borrarVariableUsuario(varPruebaEntorno)
		_ = os.Unsetenv(varPruebaEntorno)
	})

	if err := guardarClave(varPruebaEntorno, valor); err != nil {
		t.Fatalf("guardarClave rechazó una clave que la bóveda admite: %v", err)
	}
	if got, _ := secreto.Leer(varPruebaEntorno); got != valor {
		t.Fatalf("la bóveda devolvió %q, esperaba %q", got, valor)
	}
}

// Si la bóveda devuelve OTRA clave, guardar tiene que fallar.
//
// Sin la copia en el entorno que antes disimulaba, este caso deja la pantalla
// diciendo "guardado" y la capa LLM usando una clave que el usuario no escribió
// — un 401 que nadie sabría explicar.
func TestGuardarFallaSiLaBovedaDevuelveOtraClave(t *testing.T) {
	sustituirGuardado(t, func(string, string) error { return nil })
	sustituirBoveda(t, func(string) (string, error) { return "otra-cosa", nil }, nil)

	err := guardarClave(varPruebaEntorno, "la-que-pegué")
	if err == nil {
		t.Fatal("guardó en silencio una clave distinta de la pedida")
	}
	if !strings.Contains(err.Error(), varPruebaEntorno) {
		t.Errorf("el error no dice de qué variable habla: %q", err)
	}
}

// Y si no se puede releer, tampoco se puede prometer que quedó guardada.
func TestGuardarFallaSiNoSePuedeReleerLaClave(t *testing.T) {
	sustituirGuardado(t, func(string, string) error { return nil })
	fallo := errors.New("la bóveda no responde")
	sustituirBoveda(t, func(string) (string, error) { return "", fallo }, nil)

	err := guardarClave(varPruebaEntorno, "la-que-pegué")
	if err == nil {
		t.Fatal("dio por buena una escritura que no pudo comprobar")
	}
	if !errors.Is(err, fallo) {
		t.Errorf("el error no envuelve la causa real: %v", err)
	}
}

// Si el registro se niega a soltar la copia vieja, la clave TIENE que salir
// igualmente del entorno del proceso.
//
// Es la rama que deja el sistema en su peor estado: secreto en la bóveda,
// secreto en el registro y secreto en el daemon. Lo único que se puede arreglar
// desde aquí es lo último, y no hacerlo por haber fallado lo anterior sería
// castigar al usuario dos veces. Que el registro sucio no reinyecte la clave en
// el siguiente refresco lo garantiza la barrera de proc.incorporar.
func TestElProcesoSeLimpiaAunqueElRegistroFalle(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
		_ = borrarVariableUsuario(varPruebaEntorno)
		_ = os.Unsetenv(varPruebaEntorno)
	})
	t.Setenv(varPruebaEntorno, "la-que-arrastraba-el-proceso")
	sustituirBoveda(t, nil, func(string) error { return errors.New("registro de sólo lectura") })

	if err := guardarClave(varPruebaEntorno, "la-que-acabo-de-pegar"); err != nil {
		t.Fatalf("el fallo al borrar el registro no puede abortar el guardado: %v", err)
	}
	if v := os.Getenv(varPruebaEntorno); v != "" {
		t.Errorf("la clave sigue en el entorno del daemon (%q) porque falló un "+
			"borrado que no tiene nada que ver con ella", v)
	}
}
