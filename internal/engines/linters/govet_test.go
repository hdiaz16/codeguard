package linters

// Un fallo de CARGA no puede parecerse a un repo limpio.
//
// `go vet` sale distinto de cero por dos motivos que no tienen nada que ver:
// porque encontró algo (lo normal, y por eso runTool descarta el código de
// salida) y porque no pudo cargar los paquetes. En el segundo caso NO analiza
// nada —ni siquiera los paquetes que sí compilaban— y el motor devolvía cero
// hallazgos: el informe daba la capa por revisada.
//
// Se descubrió midiendo un repo real: `go vet ./...` señalaba un Sprintf mal
// formado y el agente decía «govet: 0 hallazgos», porque otro directorio del
// diff tenía dos paquetes distintos en la misma carpeta. staticcheck, ante
// exactamente el mismo repo, sí se declaraba degradado.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

func repoGo(t *testing.T) (string, func(rel, contenido string)) {
	t.Helper()
	root := t.TempDir()
	escribir := func(rel, contenido string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("go.mod", "module prueba\n\ngo 1.21\n")
	return root, escribir
}

func TestGoVetNoDaLimpioCuandoNoPudoCargar(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay nada que cargar")
	}
	root, escribir := repoGo(t)

	// Dos paquetes distintos en el MISMO directorio: go los rechaza al cargar.
	// Es el caso real que lo destapó — un directorio con fixtures de varios
	// paquetes dentro del diff.
	escribir("roto/uno.go", "package uno\n\nfunc Uno() int { return 1 }\n")
	escribir("roto/dos.go", "package dos\n\nfunc Dos() int { return 2 }\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "roto/uno.go", Status: "M"},
		{Path: "roto/dos.go", Status: "M"},
	}}

	fs, err := (GoVet{}).Run(context.Background(), in)
	if err == nil {
		t.Errorf("go vet no pudo cargar los paquetes y el motor devolvió %d hallazgos SIN error.\n"+
			"Eso llega al informe como una capa revisada y limpia, que es la peor mentira "+
			"posible: el usuario commitea creyendo que pasó por govet.", len(fs))
	} else if !strings.Contains(err.Error(), "no pudo analizar") {
		t.Errorf("el error no explica que no se pudo analizar: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("con un fallo de carga no puede haber hallazgos, y devolvió %d", len(fs))
	}
}

// Y la otra mitad: cuando SÍ carga, los hallazgos salen. Sin esto, el arreglo
// de arriba se podría "conseguir" devolviendo siempre error.
func TestGoVetSigueCazandoLoQueDebe(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay nada que analizar")
	}
	root, escribir := repoGo(t)
	escribir("app/mal.go", "package app\n\nimport \"fmt\"\n\n"+
		"func Mal() string {\n\treturn fmt.Sprintf(\"%d %d\", 1)\n}\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "app/mal.go", Status: "M"},
	}}

	fs, err := (GoVet{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("un paquete que carga bien no debe dar error: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("go vet no reportó el Sprintf con menos argumentos que verbos: " +
			"el motor no está cazando lo suyo")
	}
	if !strings.Contains(fs[0].File, "mal.go") {
		t.Errorf("el hallazgo apunta a %q y debería ser app/mal.go", fs[0].File)
	}
	if !fs[0].Blocking {
		t.Error("govet es una compuerta que BLOQUEA (§7: lint de severidad error)")
	}
}
