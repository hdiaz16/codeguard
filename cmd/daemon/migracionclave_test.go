//go:build windows

package main

import (
	"os"
	"testing"

	"codeguard/internal/secreto"
)

const varPrueba = "CODEGUARD_MIGRACION_PRUEBA"

// La migración toma la clave del entorno del proceso (si existe) y la mueve
// a la bóveda de credenciales, limpiando el entorno del proceso.
func TestLaClaveViejaSeMuevaYSeBorreDelEntorno(t *testing.T) {
	const valor = "clave-de-prueba-que-debe-migrar"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = os.Unsetenv(varPrueba)
	})
	_ = secreto.Borrar(varPrueba)
	t.Setenv(varPrueba, valor)

	MigrarClaveDelEntorno(varPrueba)

	got, err := secreto.Leer(varPrueba)
	if err != nil {
		t.Fatalf("la clave no llegó a la bóveda: %v", err)
	}
	if got != valor {
		t.Errorf("en la bóveda quedó %q, esperaba %q", got, valor)
	}
	if v := os.Getenv(varPrueba); v != "" {
		t.Errorf("la copia sigue en el entorno del proceso (%q): migrar debe limpiar el proceso", v)
	}
}

// Migrar dos veces no puede pisar una clave nueva con una vieja.
func TestNoPisaUnaClaveYaMigrada(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = os.Unsetenv(varPrueba)
	})
	if err := secreto.Guardar(varPrueba, "la-nueva-buena"); err != nil {
		t.Fatalf("preparando la bóveda: %v", err)
	}
	t.Setenv(varPrueba, "la-vieja-caducada")

	MigrarClaveDelEntorno(varPrueba)

	if got, _ := secreto.Leer(varPrueba); got != "la-nueva-buena" {
		t.Fatalf("la migración pisó la clave buena con la vieja: quedó %q", got)
	}
}

// Sin nada que migrar no debe tocar nada ni fallar.
func TestSinNadaQueMigrarNoHaceNada(t *testing.T) {
	const inexistente = "CODEGUARD_NO_EXISTE_NI_EN_BOVEDA_NI_EN_ENTORNO"
	MigrarClaveDelEntorno(inexistente)
	if _, err := secreto.Leer(inexistente); !secreto.NoEncontrado(err) {
		t.Errorf("inventó una credencial de la nada: %v", err)
	}
	MigrarClaveDelEntorno("")
}

// guardarClave guarda en la bóveda y limpia el entorno del proceso.
func TestGuardarDesdeLaPantallaLimpiaElEntorno(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = os.Unsetenv(varPrueba)
	})
	t.Setenv(varPrueba, "residuo-anterior")

	if err := guardarClave(varPrueba, "la-que-acabo-de-pegar"); err != nil {
		t.Fatalf("guardarClave: %v", err)
	}
	if got, _ := secreto.Leer(varPrueba); got != "la-que-acabo-de-pegar" {
		t.Errorf("en la bóveda quedó %q", got)
	}
	if v := os.Getenv(varPrueba); v != "" {
		t.Errorf("el residuo sigue en el entorno del proceso: %q", v)
	}
}

// Con la clave ya en la bóveda Y una copia en el entorno, respeta la de la bóveda
// y limpia el entorno.
func TestLimpiaElEntornoAunqueLaBovedaYaTengaLaClave(t *testing.T) {
	t.Cleanup(func() {
		_ = secreto.Borrar(varPrueba)
		_ = os.Unsetenv(varPrueba)
	})
	if err := secreto.Guardar(varPrueba, "la-nueva-buena"); err != nil {
		t.Fatalf("preparando la bóveda: %v", err)
	}
	t.Setenv(varPrueba, "la-vieja-rezagada")

	MigrarClaveDelEntorno(varPrueba)

	if got, _ := secreto.Leer(varPrueba); got != "la-nueva-buena" {
		t.Errorf("pisó la clave buena: quedó %q", got)
	}
	if v := os.Getenv(varPrueba); v != "" {
		t.Errorf("dejó la copia en el entorno del proceso (%q)", v)
	}
}
