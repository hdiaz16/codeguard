package fsutil

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestEstaDentroDe(t *testing.T) {
	base := t.TempDir()
	sep := string(filepath.Separator)

	casos := []struct {
		nombre string
		base   string
		ruta   string
		want   bool
	}{
		{"dentro directo", base, filepath.Join(base, "a.go"), true},
		{"anidado", base, filepath.Join(base, "sub", "dir", "a.go"), true},
		{"la propia base", base, base, true},
		{"traversal simple", base, filepath.Join(base, "..", "fuera.go"), false},
		{"traversal profundo", base, filepath.Join(base, "sub", "..", "..", "fuera.go"), false},
		{"traversal que vuelve dentro", base, filepath.Join(base, "..", filepath.Base(base), "a.go"), true},
		{"prefijo parecido no es contención", base, base + "2" + sep + "a.go", false},
		{"base vacía", "", "x", false},
		{"ruta vacía", base, "", false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := EstaDentroDe(c.base, c.ruta); got != c.want {
				t.Fatalf("EstaDentroDe(%q, %q) = %v, want %v", c.base, c.ruta, got, c.want)
			}
		})
	}
}

func TestSanitizarRutas(t *testing.T) {
	base := t.TempDir()
	dentro := filepath.Join(base, "ok.go")
	anidado := filepath.Join(base, "sub", "ok2.go")

	got := SanitizarRutas(base, []string{
		dentro,
		"",                                   // vacía: descartada
		filepath.Join(base, "..", "evil.go"), // traversal: descartado
		"/etc/passwd",                        // absoluta fuera: descartada
		anidado,
		dentro,                            // duplicado: descartado
		filepath.Join(base, ".", "ok.go"), // limpia a dentro: duplicado
	})
	want := []string{dentro, anidado}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SanitizarRutas = %v, want %v", got, want)
	}
}

func TestComoArgumentosCLI(t *testing.T) {
	got := ComoArgumentosCLI([]string{"-rf", "a.go"})
	want := []string{"--", "-rf", "a.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ComoArgumentosCLI = %v, want %v", got, want)
	}
	if got := ComoArgumentosCLI(nil); len(got) != 1 || got[0] != "--" {
		t.Fatalf("lista vacía debe producir solo [--], got %v", got)
	}
}
