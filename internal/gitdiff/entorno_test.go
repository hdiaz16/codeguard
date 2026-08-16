//go:build windows

package gitdiff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// git es el hijo que más veces lanza el producto —cada commit pasa por aquí— y
// hasta ahora heredaba el entorno ENTERO del proceso, con la clave del modelo
// dentro. Ni el hook ni el daemon tienen motivo para enseñársela: `git diff` y
// `git ls-files` son operaciones locales que no hablan con ningún servicio.
//
// La prueba pone un git FALSO delante en el PATH y le hace volcar lo que
// realmente recibe. Comprobar la lista que le pasamos no valdría: lo que
// importa es lo que llega al otro lado.
func TestElGitQueLanzamosNoRecibeLaClaveDelModelo(t *testing.T) {
	dir := t.TempDir()
	volcado := filepath.Join(dir, "entorno-visto.txt")
	falso := "@echo off\r\nset > \"" + volcado + "\"\r\n"
	if err := os.WriteFile(filepath.Join(dir, "git.cmd"), []byte(falso), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FOUNDRY_API_KEY", "clave-que-git-no-necesita")
	// La cara opuesta: git SÍ necesita saber qué índice está mirando. Con
	// `git commit -a` esto apunta a un índice temporal, y perderlo significaría
	// analizar un conjunto de cambios distinto del que se commitea.
	t.Setenv("GIT_INDEX_FILE", "indice-temporal-de-prueba")

	// El resultado da igual: sólo se quiere el efecto secundario del volcado.
	_, _ = run(dir, "rev-parse", "--show-toplevel")

	raw, err := os.ReadFile(volcado)
	if err != nil {
		t.Fatalf("el git falso no llegó a correr: %v", err)
	}
	visto := string(raw)
	if strings.Contains(visto, "clave-que-git-no-necesita") {
		t.Error("git recibió la API key del modelo: cualquier hook, alias o " +
			"credential helper del usuario la tiene a un paso")
	}
	if !strings.Contains(visto, "indice-temporal-de-prueba") {
		t.Error("git no recibió GIT_INDEX_FILE: analizaríamos el índice equivocado " +
			"en cada `git commit -a`, y en silencio")
	}
	if !strings.Contains(strings.ToUpper(visto), "PATH=") {
		t.Error("git se quedó sin PATH: no encontraría ni sus propios subcomandos")
	}
}
