package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func crearRuntimePythonDePrueba(t *testing.T, raiz, nombre string) string {
	t.Helper()
	bin := filepath.Join(raiz, nombre, "Scripts", "python.exe")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestRuntimePythonInstaladoExigeUnoSolo(t *testing.T) {
	raiz := t.TempDir()
	if _, err := runtimePythonInstalado(raiz); err == nil || !strings.Contains(err.Error(), "encontraron 0") {
		t.Fatalf("sin runtime: err=%v", err)
	}

	esperado := crearRuntimePythonDePrueba(t, raiz, "python-activo")
	got, err := runtimePythonInstalado(raiz)
	if err != nil {
		t.Fatal(err)
	}
	if got != esperado {
		t.Fatalf("runtime=%q; esperado %q", got, esperado)
	}

	crearRuntimePythonDePrueba(t, raiz, "python-antiguo")
	if _, err := runtimePythonInstalado(raiz); err == nil || !strings.Contains(err.Error(), "encontraron 2") {
		t.Fatalf("runtimes superpuestos: err=%v", err)
	}
}
