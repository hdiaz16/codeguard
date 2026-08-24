package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Un archivo con acento en el nombre no puede tumbar el análisis.
//
// Git, por defecto (core.quotePath), entrecomilla y escapa en octal cualquier
// ruta con bytes no ASCII: `Plan - Remediación.md` sale de `git diff
// --name-status` como  "Plan - Remediaci\303\263n.md"  —comillas incluidas—, y
// esa cadena literal viajaba hasta los motores como si fuera una ruta.
//
// semgrep respondía `Invalid scanning root` y moría, y con él se caía el
// análisis ENTERO del commit: no el archivo con acento, todos. El commit
// pasaba con una línea de "capas no revisadas: semgrep:error" y las 119 reglas
// de la casa sin aplicar. Ocurrió de verdad en este repo, al añadir un
// documento llamado "Plan - Remediación y cobertura.md".
//
// En un equipo que escribe en español esto no es un caso extremo. Y falla de
// la peor forma: apaga la compuerta para todo lo demás, en silencio salvo por
// un aviso que nadie lee.
func TestRutaConAcentoNoLlegaEscapada(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("sin git no hay nada que leer")
	}
	repo := t.TempDir()
	for _, orden := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "prueba@ejemplo.local"},
		{"config", "user.name", "Prueba"},
		// Explícito: es el valor por defecto de git, y es justo el que rompía.
		// Ponerlo evita que la prueba pase de casualidad en una máquina donde
		// alguien lo haya desactivado a mano.
		{"config", "core.quotePath", "true"},
	} {
		cmd := exec.Command("git", orden...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(orden, " "), err, out)
		}
	}

	const nombre = "Plan - Remediación y ñandú.md"
	if err := os.WriteFile(filepath.Join(repo, nombre), []byte("contenido\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	add := exec.Command("git", "add", nombre)
	add.Dir = repo
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}

	d, err := Staged(repo)
	if err != nil {
		t.Fatalf("Staged: %v", err)
	}
	if len(d.Files) != 1 {
		t.Fatalf("esperaba 1 archivo, hubo %d: %+v", len(d.Files), d.Files)
	}
	got := d.Files[0].Path

	if strings.Contains(got, `\3`) || strings.Contains(got, `"`) {
		t.Fatalf("la ruta llegó escapada por git y así no la abre nadie: %q", got)
	}
	if got != nombre {
		t.Fatalf("ruta = %q, esperaba %q", got, nombre)
	}
	// Y tiene que poder abrirse de verdad: una ruta que parece bien pero no
	// existe deja al motor sin nada que leer, que es la misma avería con otra
	// cara — el archivo se reporta como analizado y no se analizó.
	if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(got))); err != nil {
		t.Fatalf("la ruta devuelta no abre el archivo: %v", err)
	}
	// El hash del contenido también depende de poder abrirlo: si sale vacío, el
	// archivo deja de ser cacheable y nadie se entera.
	if d.Files[0].SHA256 == "" {
		t.Error("sin SHA256: no se pudo leer el archivo por su ruta")
	}
}
