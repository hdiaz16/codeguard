package fsutil

import (
	"os"
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
		{"ruta UNC rechazada", base, `\\server\share\file.go`, false},
		{"namespace NT rechazado", base, `\\?\C:\evil\file.go`, false},
		{"alternate data stream rechazado", base, filepath.Join(base, "file.go:secret"), false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := EstaDentroDe(c.base, c.ruta); got != c.want {
				t.Fatalf("EstaDentroDe(%q, %q) = %v, want %v", c.base, c.ruta, got, c.want)
			}
		})
	}
}

func TestEstaDentroDe_Symlinks(t *testing.T) {
	dir := t.TempDir()
	raiz := filepath.Join(dir, "repo")
	fuera := filepath.Join(dir, "fuera")

	_ = os.MkdirAll(raiz, 0o755)
	_ = os.MkdirAll(fuera, 0o755)

	archivoFuera := filepath.Join(fuera, "secreto.txt")
	_ = os.WriteFile(archivoFuera, []byte("secreto"), 0o600)

	// Crear symlink dentro del repo apuntando hacia afuera
	linkFuera := filepath.Join(raiz, "link_hacia_fuera")
	if err := os.Symlink(fuera, linkFuera); err == nil {
		// Debe rechazar porque el symlink apunta fuera de raiz
		if EstaDentroDe(raiz, filepath.Join(linkFuera, "secreto.txt")) {
			t.Errorf("EstaDentroDe permitió resolver un symlink que apunta fuera del repo")
		}
	}

	// Crear symlink dentro del repo apuntando a un directorio dentro del repo
	subDentro := filepath.Join(raiz, "sub")
	_ = os.MkdirAll(subDentro, 0o755)
	archivoDentro := filepath.Join(subDentro, "ok.go")
	_ = os.WriteFile(archivoDentro, []byte("package ok"), 0o600)

	linkDentro := filepath.Join(raiz, "link_hacia_dentro")
	if err := os.Symlink(subDentro, linkDentro); err == nil {
		if !EstaDentroDe(raiz, filepath.Join(linkDentro, "ok.go")) {
			t.Errorf("EstaDentroDe rechazó un symlink legítimo que apunta dentro del repo")
		}
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
		`\\server\share\file.go`,             // UNC: descartada
		filepath.Join(base, "file.go:ads"),   // ADS: descartada
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
