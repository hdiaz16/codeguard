package gitleaks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
)

// EL RESQUICIO QUE EL REPORTE NO CERRABA, Y QUE ES PEOR QUE EL FALLO ORIGINAL.
//
// El primer arreglo hizo que un código 0 sin reporte fuera avería. Cerraba al
// impostor que no escribe nada… y dejaba abierto el caso en que gitleaks CORRE,
// escribe su reporte con `[]` dentro, sale con 0 — y no ha mirado nada.
//
// Lo encontró el validador con el `.git/index` corrupto: el `git diff` que
// gitleaks lanza por dentro falla, gitleaks lo apunta en su registro y termina
// diciendo "no leaks found". Reproducido aquí sobre un repo cuyo índice, con git
// sano, daba código 9 y un reporte de 529 bytes con el secreto dentro.
//
// El secreto del fixture va partido en dos literales por la misma razón que en
// internal/pipeline: si estuviera entero, el gitleaks de ESTE repo lo encontraría
// al commitear su propio código fuente y bloquearía el commit.
const patDePrueba = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

// repoConSecreto deja un repo git con el secreto EN EL ÍNDICE, que es lo que mira
// el modo "staged" del gancho.
func repoConSecreto(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks no está en PATH")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git no está en PATH")
	}
	repo := t.TempDir()
	for _, args := range [][]string{
		{"init"}, {"config", "user.email", "a@b.c"}, {"config", "user.name", "a"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("no pude preparar el repo (%v): %s", err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "config.yaml"),
		[]byte("token: "+patDePrueba+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	añadir := exec.Command("git", "add", "-A")
	añadir.Dir = repo
	if out, err := añadir.CombinedOutput(); err != nil {
		t.Skipf("git add falló (%v): %s", err, out)
	}
	return repo
}

// EL CONTROL, y va primero porque sin él el resto no prueba nada: con el repo
// sano, ese secreto TIENE que salir. Si no saliera, los tests de abajo estarían
// midiendo un gitleaks que no encuentra nada por su cuenta.
//
// (Se aprendió midiendo: mi primer fixture usaba la clave de ejemplo de AWS, que
// gitleaks trae en su lista de permitidos, así que el repo "con secreto" salía
// limpio y el control lo delató.)
func TestElControlUnRepoSanoConSecretoBloquea(t *testing.T) {
	repo := repoConSecreto(t)

	hallazgos, err := (&Engine{Mode: "staged"}).Run(context.Background(),
		engines.Input{RepoRoot: repo})
	if err != nil {
		t.Fatalf("un repo sano con un secreto en el índice se escanea sin problemas: %v", err)
	}
	if len(hallazgos) != 1 {
		t.Fatalf("se esperaba 1 secreto y salieron %d: %+v", len(hallazgos), hallazgos)
	}
	if !hallazgos[0].Blocking {
		t.Error("un secreto en el diff bloquea, o la etapa 1 no es una compuerta")
	}
}

// Y AHORA EL CASO: el mismo repo, el mismo secreto, el índice roto.
func TestConElIndiceCorruptoLaCompuertaBloqueaEnVezDeDecirLimpio(t *testing.T) {
	repo := repoConSecreto(t)
	// Un índice que git no puede leer. No hace falta inventar nada raro: pasa con
	// un disco lleno a media escritura, con un `git` matado, o con dos procesos
	// escribiendo el índice a la vez.
	if err := os.WriteFile(filepath.Join(repo, ".git", "index"), []byte("BASURA"), 0o644); err != nil {
		t.Fatal(err)
	}

	hallazgos, err := (&Engine{Mode: "staged"}).Run(context.Background(),
		engines.Input{RepoRoot: repo})

	if err == nil {
		t.Fatalf("gitleaks no pudo leer el índice y la compuerta dijo LIMPIO (%d hallazgos).\n\n"+
			"Ese mismo índice, con git sano, tiene un secreto que gitleaks encuentra. "+
			"Un «sin secretos» de una corrida que falló deja salir la credencial y encima "+
			"lo anuncia en verde.", len(hallazgos))
	}
	// Fail-closed (§14): sin ErrUnavailable el gancho NO bloquea, sólo pinta la
	// capa de naranja, y el commit sale igual. Eso sería medio arreglo.
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("sin ErrUnavailable la compuerta no bloquea y el secreto sale: %v", err)
	}
	if len(hallazgos) != 0 {
		t.Errorf("no puede inventar hallazgos cuando no pudo escanear: %d", len(hallazgos))
	}
}

// EL OTRO CONTROL, el que más importa en el día a día: un repo sano y limpio NO
// puede bloquear. La compuerta es fail-closed, así que un falso «no pude
// escanear» no degrada una capa: BLOQUEA TODOS LOS COMMITS del repo.
func TestUnRepoSanoYLimpioNoBloquea(t *testing.T) {
	repo := repoConSecreto(t)
	// Se quita el secreto y se deja sólo contenido inocente.
	if err := os.WriteFile(filepath.Join(repo, "config.yaml"), []byte("modo: produccion\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	añadir := exec.Command("git", "add", "-A")
	añadir.Dir = repo
	if out, err := añadir.CombinedOutput(); err != nil {
		t.Skipf("git add falló (%v): %s", err, out)
	}

	hallazgos, err := (&Engine{Mode: "staged"}).Run(context.Background(),
		engines.Input{RepoRoot: repo})
	if err != nil {
		t.Fatalf("repo sano y sin secretos: esto NO puede fallar, porque la compuerta es "+
			"fail-closed y bloquearía cada commit del repositorio: %v", err)
	}
	if len(hallazgos) != 0 {
		t.Errorf("no hay secretos que encontrar, y encontró %d: %+v", len(hallazgos), hallazgos)
	}
}

// El registro de gitleaks se lee por NIVEL, y la diferencia entre dos niveles es
// la diferencia entre bloquear con razón y bloquear siempre.
func TestElRegistroSeLeePorNivelYNoPorSubcadena(t *testing.T) {
	casos := []struct {
		nombre string
		stderr string
		quiere int
	}{
		{
			// El camino con hallazgos. Si WRN contara como fallo, TODO commit con
			// un secreto de verdad se reportaría como «no pude escanear» en vez de
			// como el hallazgo que es.
			"leaks found es WRN y NO es un fallo",
			"9:56PM INF 0 commits scanned.\n9:56PM WRN leaks found: 1\n", 0,
		},
		{
			"el registro de una corrida limpia no tiene fallos",
			"9:56PM INF 0 commits scanned.\n9:56PM INF no leaks found\n", 0,
		},
		{
			// Medido con el índice corrupto, con los colores tal como los escribe.
			"ERR envuelto en colores de consola sí cuenta",
			"\x1b[90m9:56PM\x1b[0m \x1b[31mERR\x1b[0m [git] fatal: index file corrupt\n" +
				"\x1b[90m9:56PM\x1b[0m \x1b[31mERR\x1b[0m error=\"stderr is not empty\"\n" +
				"\x1b[90m9:56PM\x1b[0m \x1b[32mINF\x1b[0m no leaks found\n", 2,
		},
		{
			"FTL cuenta igual que ERR",
			"9:56PM FTL could not create Git diff cmd\n", 1,
		},
		{
			// Un nombre de archivo con esas letras dentro no es un nivel. Buscar la
			// subcadena "ERR" bloquearía este repo entero, para siempre.
			"ERR dentro de una palabra no es un nivel",
			"9:56PM INF scanned ~85 bytes in src/ERRORES.md\n" +
				"9:56PM INF no leaks found\n", 0,
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			fallos := erroresDeGitleaks([]byte(c.stderr))
			if len(fallos) != c.quiere {
				t.Errorf("se esperaban %d fallos y salieron %d: %v", c.quiere, len(fallos), fallos)
			}
			for _, f := range fallos {
				if strings.Contains(f, "\x1b") {
					t.Errorf("el motivo llega con códigos de color y va al panel y al log: %q", f)
				}
			}
		})
	}
}
