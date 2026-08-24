package linters

import (
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// El monorepo corporativo típico no tiene tsconfig.json en la raíz sino en
// frontend/ — y la versión anterior de Applies solo miraba la raíz, así que
// la compuerta de tipos (§7: BLOQUEA) llevaba enrolada sin correr jamás.
func TestProyectosEncuentraElTsconfigMasCercano(t *testing.T) {
	root := t.TempDir()
	escribir := func(rel string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("frontend/tsconfig.json")
	escribir("frontend/src/app.ts")
	escribir("admin/tsconfig.json")
	escribir("admin/panel.tsx")
	escribir("suelto/nota.ts") // sin tsconfig alcanzable: no hay proyecto que compilar

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "frontend/src/app.ts", Status: "M"},
		{Path: "admin/panel.tsx", Status: "A"},
		{Path: "suelto/nota.ts", Status: "M"},
		{Path: "backend/main.go", Status: "M"},
	}}
	got := Tsc{}.proyectos(in)
	if len(got) != 2 || got[0] != "admin" || got[1] != "frontend" {
		t.Fatalf("proyectos = %v, esperaba [admin frontend] (el .ts sin tsconfig no compila en ningún proyecto)", got)
	}
	if !(Tsc{}).Applies(in) {
		t.Fatal("con dos proyectos TS, Applies debe ser verdadero")
	}
}

func TestTsconfigEnLaRaizSigueFuncionando(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"tsconfig.json", "src/main.ts"} {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(abs), 0o755)
		if err := os.WriteFile(abs, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{{Path: "src/main.ts", Status: "M"}}}
	got := Tsc{}.proyectos(in)
	if len(got) != 1 || got[0] != "." {
		t.Fatalf("proyectos = %v, esperaba [.]", got)
	}
}
