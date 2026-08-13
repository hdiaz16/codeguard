//go:build windows

package main

import (
	"testing"

	"codeguard/internal/secreto"
	"golang.org/x/sys/windows/registry"
)

const varPrueba = "CODEGUARD_MIGRACION_PRUEBA"

func ponerEnElEntornoDelUsuario(t *testing.T, nombre, valor string) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		t.Skipf("sin acceso a HKCU\\Environment: %v", err)
	}
	defer k.Close()
	if err := k.SetStringValue(nombre, valor); err != nil {
		t.Skipf("no se pudo preparar la variable: %v", err)
	}
}

func leerDelEntornoDelUsuario(t *testing.T, nombre string) string {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(nombre)
	if err != nil {
		return ""
	}
	return v
}

// La migración tiene DOS mitades y la segunda es la que se olvida: copiar a la
// bóveda sin borrar el original deja el secreto igual de expuesto que antes,
// con el agravante de que ya nadie mira ahí. Esta prueba comprueba las dos.
func TestLaClaveViejaSeMuevaYSeBorreDelEntorno(t *testing.T) {
	const valor = "clave-de-prueba-que-debe-migrar"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = borrarVariableUsuario(varPrueba)
	})
	_ = secreto.Borrar(varPrueba)
	ponerEnElEntornoDelUsuario(t, varPrueba, valor)

	MigrarClaveDelEntorno(varPrueba)

	got, err := secreto.Leer(varPrueba)
	if err != nil {
		t.Fatalf("la clave no llegó a la bóveda: %v", err)
	}
	if got != valor {
		t.Errorf("en la bóveda quedó %q, esperaba %q", got, valor)
	}
	if v := leerDelEntornoDelUsuario(t, varPrueba); v != "" {
		t.Errorf("la copia vieja sigue en HKCU\\Environment (%q): migrar sin borrar "+
			"no protege nada, sólo esconde dónde está", v)
	}
}

// Migrar dos veces no puede pisar una clave nueva con una vieja.
//
// Es el escenario real: el usuario actualiza (migra), luego cambia la clave
// desde la pantalla (se guarda en la bóveda), y el daemon reinicia. Si la
// migración no comprobara la bóveda primero y quedara un resto en el registro,
// devolvería la clave anterior y la capa LLM fallaría con un 401 imposible de
// explicar.
func TestNoPisaUnaClaveYaMigrada(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = borrarVariableUsuario(varPrueba)
	})
	if err := secreto.Guardar(varPrueba, "la-nueva-buena"); err != nil {
		t.Fatalf("preparando la bóveda: %v", err)
	}
	ponerEnElEntornoDelUsuario(t, varPrueba, "la-vieja-caducada")

	MigrarClaveDelEntorno(varPrueba)

	if got, _ := secreto.Leer(varPrueba); got != "la-nueva-buena" {
		t.Fatalf("la migración pisó la clave buena con la vieja: quedó %q", got)
	}
}

// Sin nada que migrar no debe tocar nada ni fallar: es el caso de toda
// instalación nueva, o sea el que corre en casi todos los arranques.
func TestSinNadaQueMigrarNoHaceNada(t *testing.T) {
	const inexistente = "CODEGUARD_NO_EXISTE_NI_EN_BOVEDA_NI_EN_ENTORNO"
	MigrarClaveDelEntorno(inexistente)
	if _, err := secreto.Leer(inexistente); !secreto.NoEncontrado(err) {
		t.Errorf("inventó una credencial de la nada: %v", err)
	}
	MigrarClaveDelEntorno("") // y con el nombre vacío tampoco puede caerse
}

// guardarClave es el camino de la pantalla de configuración: además de
// guardar, tiene que dejar limpio el entorno. Si no, quien ya tenía la clave
// ahí la conserva expuesta para siempre por haber pulsado "guardar".
func TestGuardarDesdeLaPantallaLimpiaElEntorno(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = borrarVariableUsuario(varPrueba)
	})
	ponerEnElEntornoDelUsuario(t, varPrueba, "residuo-anterior")

	if err := guardarClave(varPrueba, "la-que-acabo-de-pegar"); err != nil {
		t.Fatalf("guardarClave: %v", err)
	}
	if got, _ := secreto.Leer(varPrueba); got != "la-que-acabo-de-pegar" {
		t.Errorf("en la bóveda quedó %q", got)
	}
	if v := leerDelEntornoDelUsuario(t, varPrueba); v != "" {
		t.Errorf("el residuo sigue en el entorno: %q", v)
	}
}

// Con la clave ya en la bóveda Y una copia rezagada en el registro, hay que
// hacer las dos cosas: respetar la de la bóveda (puede ser más nueva) y borrar
// igualmente la del registro.
//
// La primera versión de la migración salía en cuanto veía la clave en la
// bóveda, así que la copia vieja se quedaba ahí para siempre. Es el mismo error
// contra el que avisa el comentario de guardarClave, cometido tres funciones
// más abajo — y no lo cazó ninguna prueba, sino copiar la clave real a la
// bóveda para una comprobación y ver que el original seguía en su sitio.
func TestLimpiaElRegistroAunqueLaBovedaYaTengaLaClave(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = borrarVariableUsuario(varPrueba)
	})
	if err := secreto.Guardar(varPrueba, "la-nueva-buena"); err != nil {
		t.Fatalf("preparando la bóveda: %v", err)
	}
	ponerEnElEntornoDelUsuario(t, varPrueba, "la-vieja-rezagada")

	MigrarClaveDelEntorno(varPrueba)

	if got, _ := secreto.Leer(varPrueba); got != "la-nueva-buena" {
		t.Errorf("pisó la clave buena: quedó %q", got)
	}
	if v := leerDelEntornoDelUsuario(t, varPrueba); v != "" {
		t.Errorf("dejó la copia vieja en el registro (%q): en esa máquina el secreto "+
			"sigue expuesto y ya nadie mira ahí", v)
	}
}
