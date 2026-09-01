//go:build windows

package linters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func nombreCortoWindows(t *testing.T, ruta string) string {
	t.Helper()
	largo, err := windows.UTF16PtrFromString(ruta)
	if err != nil {
		t.Fatal(err)
	}
	const capacidadRutaCorta = 32768
	buf := make([]uint16, capacidadRutaCorta)
	n, err := windows.GetShortPathName(largo, &buf[0], capacidadRutaCorta)
	if err != nil || n == 0 || n >= capacidadRutaCorta {
		t.Skipf("el volumen no ofrece nombres 8.3: %v", err)
	}
	return windows.UTF16ToString(buf[:n])
}

func TestRelToUnificaRutaWindowsCortaYLarga(t *testing.T) {
	raiz := t.TempDir()
	archivo := filepath.Join(raiz, "subdirectorio-largo", "archivo.go")
	if err := os.MkdirAll(filepath.Dir(archivo), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivo, []byte("package demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	corta := nombreCortoWindows(t, archivo)
	if strings.EqualFold(corta, archivo) {
		t.Skip("el volumen no generó una forma 8.3 distinta")
	}
	if got := relTo(raiz, corta); got != "subdirectorio-largo/archivo.go" {
		t.Fatalf("ruta corta %q bajo raíz larga quedó como %q", corta, got)
	}
	if got, ok := relExistentePorIdentidad(raiz, corta); !ok || got != "subdirectorio-largo/archivo.go" {
		t.Fatalf("la identidad no unificó ruta corta y larga: got=%q ok=%v", got, ok)
	}
}
