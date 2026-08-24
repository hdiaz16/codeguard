package linters

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// EL MOTOR DE VERDAD, SOBRE UN MÓDULO CON PAQUETE DE TEST EXTERNO.
//
// El test de al lado (TestVetJSONEsUnFlujoDeObjetosYNoUnoSolo) le da el informe
// ya escrito al parseador. Éste ejecuta `go vet` de verdad, porque el fallo no
// estaba en cómo se lee el informe sino en QUÉ FORMA TIENE, y esa sólo la dice
// la herramienta.
//
// La forma depende de algo que no es evidente: un paquete con test EXTERNO
// (`package toy_test`) hace que vet emita DOS objetos JSON pegados. Un módulo
// con sólo tests internos emite uno, y ahí el fallo no se ve — que es por lo
// que la medición original, hecha sobre un paquete pequeño, lo dio por bueno.
// Medido en este árbol: cmd/codeguard emite 2 e internal/pipeline emite 3.
func TestGoVetSobreUnModuloConPaqueteDeTestExterno(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go no está en PATH")
	}
	raiz := t.TempDir()
	escribirArchivo := func(nombre, cuerpo string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(raiz, nombre), []byte(cuerpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribirArchivo("go.mod", "module toy\n\ngo 1.21\n")
	escribirArchivo("a.go", "package toy\n\nfunc Saluda() string { return \"hola\" }\n")
	escribirArchivo("a_test.go", "package toy\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { _ = Saluda() }\n")
	// ESTE es el que hace que vet emita dos objetos.
	escribirArchivo("b_test.go", "package toy_test\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) { _ = 1 }\n")

	// El control del fixture: si vet no emitiera más de un objeto, este test
	// pasaría sin ejercitar el fallo y sería decorativo.
	cmd := exec.Command("go", "vet", "-json", "./.")
	cmd.Dir = raiz
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOCACHE="+t.TempDir())
	salida, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("go no encontrado en PATH")
		} else if !errors.As(err, &ee) {
			t.Fatalf("ejecución de go vet falló: %v\n%s", err, salida)
		}
	}
	if n := strings.Count(string(salida), "{"); n < 2 {
		t.Skipf("este toolchain no emite un flujo aquí (%d objeto(s)): el test no probaría nada", n)
	}

	in := engines.Input{
		RepoRoot: raiz,
		Files:    []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}},
	}
	fs, err := GoVet{}.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("go vet analizó un módulo limpio y el motor lo dio por AVERIADO: %v\n\n"+
			"Con esto, govet queda degradado en cualquier repo con un paquete de test "+
			"externo —o sea en casi todos— y deja de mirar sin que nadie lo note.", err)
	}
	if len(fs) != 0 {
		t.Fatalf("el módulo está limpio y salieron %d hallazgo(s): %+v", len(fs), fs)
	}
}
