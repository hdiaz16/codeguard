//go:build windows

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"codeguard/internal/secreto"
)

// sustituirBoveda cambia el punto de lectura de la bóveda y lo restaura al terminar.
func sustituirBoveda(t *testing.T, leer func(string) (string, error)) {
	t.Helper()
	leerPrevio := leerDeBoveda
	t.Cleanup(func() { leerDeBoveda = leerPrevio })
	if leer != nil {
		leerDeBoveda = leer
	}
}

// sustituirGuardado cambia sólo la ESCRITURA en la bóveda.
func sustituirGuardado(t *testing.T, guardar func(string, string) error) {
	t.Helper()
	previo := guardarEnBoveda
	t.Cleanup(func() { guardarEnBoveda = previo })
	guardarEnBoveda = guardar
}

const varPruebaEntorno = "CODEGUARD_H003_PRUEBA"

// Guardar la clave no puede dejarla en el entorno de ESTE proceso.
func TestGuardarNoDejaLaClaveEnElEntornoDelProceso(t *testing.T) {
	const valor = "clave-que-no-debe-heredarse"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
		_ = os.Unsetenv(varPruebaEntorno)
	})
	_ = secreto.Borrar(varPruebaEntorno)
	_ = os.Unsetenv(varPruebaEntorno)

	if err := guardarClave(varPruebaEntorno, valor); err != nil {
		t.Fatalf("guardarClave: %v", err)
	}

	if v := os.Getenv(varPruebaEntorno); v != "" {
		t.Errorf("guardarClave dejó la variable en os.Getenv (%q)", v)
	}
	if v, ok := enElEntornoDelProceso(varPruebaEntorno); ok {
		t.Errorf("guardarClave dejó la variable en os.Environ() (%q)", v)
	}
}

// Releer lo guardado inmediatamente después: si la bóveda no la admite,
// fallar en voz alta.
func TestGuardarVerificaLaIdaYVuelta(t *testing.T) {
	const valor = "clave-con-acentos-áéí-y-símbolos-!@#$%^&*()"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
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
func TestGuardarFallaSiLaBovedaDevuelveOtraClave(t *testing.T) {
	sustituirGuardado(t, func(string, string) error { return nil })
	sustituirBoveda(t, func(string) (string, error) { return "otra-cosa", nil })

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
	sustituirBoveda(t, func(string) (string, error) { return "", fallo })

	err := guardarClave(varPruebaEntorno, "la-que-pegué")
	if err == nil {
		t.Fatal("dio por buena una escritura que no pudo comprobar")
	}
	if !errors.Is(err, fallo) {
		t.Errorf("el error no envuelve la causa real: %v", err)
	}
}

// Guardar limpia la copia previa del entorno del proceso.
func TestElProcesoSeLimpiaAlGuardar(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaEntorno)
		_ = os.Unsetenv(varPruebaEntorno)
	})
	t.Setenv(varPruebaEntorno, "la-que-arrastraba-el-proceso")

	if err := guardarClave(varPruebaEntorno, "la-que-acabo-de-pegar"); err != nil {
		t.Fatalf("guardarClave: %v", err)
	}
	if v := os.Getenv(varPruebaEntorno); v != "" {
		t.Errorf("la clave sigue en el entorno del daemon (%q)", v)
	}
}
