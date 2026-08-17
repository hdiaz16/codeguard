package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// La lista de repos a precalentar tampoco puede acabar dentro de un repo.
//
// Misma avería que la del registro de proyectos y la de la BD de runs:
// `warmListPath` resolvía `%LOCALAPPDATA%` con la guarda `base == ""`, que deja
// pasar el valor en blanco y el relativo, y `filepath.Join` no falla con ellos —
// devuelve una ruta RELATIVA, que se resuelve contra el directorio de trabajo.
//
// Aquí el daño es menor que en los otros dos casos y conviene decirlo con
// precisión: `RememberRepo` lo llama el daemon, cuyo directorio de trabajo no es
// el repositorio que se analiza, así que el archivo no aterriza en el árbol del
// usuario sino donde se lanzara el daemon. Se arregla igual por dos razones: es
// la misma clase de bug y ya nos ha costado cuatro hallazgos, y "el CWD del
// daemon nunca será un repo" es justo el tipo de suposición que deja de ser
// cierta el día que alguien lance el daemon desde otro sitio.
func TestLaListaDePrecalentamientoNuncaSeEscribeEnElDirectorioDeTrabajo(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
	}{
		{"variable ausente", ""},
		{"variable en blanco", "   "},
		{"valor relativo", filepath.Join("datos", "local")},
		{"punto", "."},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			trabajo := t.TempDir()
			t.Chdir(trabajo)
			t.Setenv("LOCALAPPDATA", c.localappdata)

			RememberRepo(filepath.Join(trabajo, "un-repo"))

			entradas, err := os.ReadDir(trabajo)
			if err != nil {
				t.Fatal(err)
			}
			if len(entradas) > 0 {
				var nombres []string
				for _, e := range entradas {
					nombres = append(nombres, e.Name())
				}
				t.Errorf("la lista de precalentamiento se escribió en el directorio de "+
					"trabajo: %v", nombres)
			}
		})
	}
}

// Y la contraparte: con un LOCALAPPDATA legítimo el precalentamiento tiene que
// seguir recordando lo que se le dice, o el arreglo sería apagarlo.
func TestConLocalappdataValidoElPrecalentamientoRecuerda(t *testing.T) {
	trabajo := t.TempDir()
	datos := t.TempDir()
	t.Chdir(trabajo)
	t.Setenv("LOCALAPPDATA", datos)

	repo := filepath.Join(trabajo, "un-repo")
	RememberRepo(repo)

	lista := filepath.Join(datos, "codeguard", "warm-repos.txt")
	raw, err := os.ReadFile(lista)
	if err != nil {
		t.Fatalf("la lista no está en %s: %v", lista, err)
	}
	if len(raw) == 0 {
		t.Error("la lista quedó vacía: el repo no se recordó")
	}
}
