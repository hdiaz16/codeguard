package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/gitdiff"
)

// La compuerta de secretos es la ÚNICA bloqueante del producto (§14). Todo lo
// que corra antes que ella y pueda cortar el camino tiene que fallar cerrado:
// si el hook se rinde antes de llegar a la compuerta, el commit entra sin que
// nadie haya mirado el diff, y encima en silencio.

const (
	varHijoHook = "CODEGUARD_TEST_HOOK_HIJO"
	varRepoHook = "CODEGUARD_TEST_HOOK_REPO"
)

func escribirEnRepo(t *testing.T, ruta, contenido string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repoEnrolado deja un repo git con config de CodeGuard: sin ella el hook sale
// en la etapa 0 y no llega a ninguna compuerta.
func repoEnrolado(t *testing.T) (repo string, git func(args ...string)) {
	t.Helper()
	repo = t.TempDir()
	git = func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q", ".")
	git("config", "user.email", "prueba@codeguard.local")
	git("config", "user.name", "prueba")
	escribirEnRepo(t, filepath.Join(repo, ".codeguard", "config.yaml"),
		"version: 1\nrulepack: \"2026.08.3\"\n")
	// El rulepack se VENDOREA y se deja COMMITEADO, y las dos cosas importan.
	// Vendoreado: en el runner del CI no hay rulepack instalado, así que sin
	// esto semgrep salía con rulepack-ausente y el veredicto legítimo era
	// PARCIAL — mientras en la máquina del dev el rulepack instalado tapaba el
	// agujero y el mismo test veía el ✓ (medido: rojo solo en CI, corrida
	// 32612569133). Un fixture que describe repos DISTINTOS según la máquina
	// no fija ningún contrato. Commiteado: queda en la base y no en el diff,
	// que es donde lo tiene un repo real — y un `git add .` de una prueba ya
	// no arrastra cientos de YAML del pack a su análisis.
	vendorearRulepack(t, repo)
	git("add", "-A")
	git("commit", "-qm", "repo enrolado (fixture)")
	return repo, git
}

// vendorearRulepack copia el rulepack del árbol del producto al repo de
// prueba, como copiarRulepackComo en internal/pipeline y por lo mismo.
func vendorearRulepack(t *testing.T, repo string) {
	t.Helper()
	origen := filepath.Join("..", "..", "rulepacks", "2026.08.3", "semgrep")
	if _, err := os.Stat(origen); err != nil {
		t.Skipf("no encuentro el rulepack en el árbol: %v", err)
	}
	destino := filepath.Join(repo, "rulepacks", "2026.08.3", "semgrep")
	if err := os.RemoveAll(destino); err != nil {
		t.Fatalf("no se pudo limpiar el destino del rulepack: %v", err)
	}
	if err := os.CopyFS(destino, os.DirFS(origen)); err != nil {
		t.Fatalf("no se pudo vendorear el rulepack: %v", err)
	}
}

// correrHookEnHijo ejecuta runPreCommit de verdad en otro proceso, porque el
// hook decide con os.Exit y ese código de salida ES la respuesta que git lee:
// 0 permite el commit, distinto de 0 lo detiene. Mirar el valor de retorno de
// la función no probaría nada — probaría que la función devolvió algo.
func correrHookEnHijo(t *testing.T, repo string) (codigo int, salida string) {
	t.Helper()
	hijo := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout=120s")
	hijo.Env = append(os.Environ(), varHijoHook+"=1", varRepoHook+"="+repo)
	out, err := hijo.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		codigo = 0
	case errors.As(err, &ee):
		codigo = ee.ExitCode()
	default:
		t.Fatalf("no se pudo lanzar el hook hijo: %v\n%s", err, out)
	}
	return codigo, string(out)
}

// soyElHijo corre el hook en el repo que preparó el padre. Si runPreCommit
// vuelve, es que dejó pasar el commit: eso sale como 0, igual que lo vería git.
func soyElHijo() bool { return os.Getenv(varHijoHook) == "1" }

func hacerDeHook() {
	if err := os.Chdir(os.Getenv(varRepoHook)); err != nil {
		os.Exit(97) // no es un veredicto: es que la prueba no se pudo montar
	}
	_ = runPreCommit()
	os.Exit(0)
}

// H041: si git no puede decir QUÉ está preparado, el hook se rendía con
// `return nil` y el commit entraba sin pasar por la compuerta de secretos.
//
// El fallo se induce con un índice corrupto de verdad y no con un doble: es lo
// que dejan un corte de luz a media escritura, un antivirus o un disco con
// errores. Se eligió porque `git rev-parse` SIGUE contestando —así que el hook
// entra con normalidad y cree estar en un repo sano— y es `git diff --cached`
// el que muere. Justo la grieta del hallazgo.
func TestElHookNoPermiteElCommitSiNoPuedeLeerLoPreparado(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}

	repo, git := repoEnrolado(t)
	// Contenido preparado y con un secreto dentro: exactamente lo que la
	// compuerta tendría que ver y rechazar.
	escribirEnRepo(t, filepath.Join(repo, "config.py"),
		"AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n")
	git("add", ".")
	// Y ahora el índice deja de poder leerse.
	escribirEnRepo(t, filepath.Join(repo, ".git", "index"), "esto-no-es-un-indice-de-git")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo == 97 {
		t.Fatal("el hijo no pudo entrar al repo de prueba")
	}

	if codigo == 0 {
		t.Errorf("FAIL-OPEN: git no pudo decir qué estaba preparado y el hook PERMITIÓ el commit (exit 0).\n"+
			"Un secreto quedó preparado y la compuerta nunca llegó a mirarlo: un fallo de\n"+
			"infraestructura convertido en un «adelante» silencioso.\nsalida del hook:\n%s", salida)
	}
	if strings.Contains(salida, "secretos ✓") {
		t.Errorf("el hook firmó «secretos ✓» sin haber podido leer el diff:\n%s", salida)
	}
}

// La otra mitad del hallazgo, y la que impide «arreglarlo» bloqueando de más:
// no tener NADA preparado es un caso legítimo y cotidiano (`git commit --amend`
// sin cambios nuevos, por ejemplo). Ahí el commit tiene que seguir pasando.
func TestElHookPermiteElCommitCuandoNoHayNadaPreparado(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}

	repo, git := repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, "a.txt"), "contenido\n")
	git("add", ".")
	git("commit", "-qm", "primero")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo != 0 {
		t.Errorf("el hook detuvo un commit legítimo sin nada preparado (exit %d).\n"+
			"Confundir «no hay nada que revisar» con «no pude averiguar qué revisar»\n"+
			"bloquearía commits en cada máquina, que es peor que el fallo original.\nsalida:\n%s",
			codigo, salida)
	}
}

// La distinción en la que se apoya el fix, comprobada contra git de verdad:
// TODO estado legítimo sale con éxito (aunque la lista venga vacía), y sólo un
// fallo real da error. Sin esta separación no se puede fallar cerrado sin
// romper a todo el mundo.
func TestSoloUnFalloDeVerdadDeGitDaError(t *testing.T) {
	t.Run("sin nada preparado", func(t *testing.T) {
		repo, git := repoEnrolado(t)
		escribirEnRepo(t, filepath.Join(repo, "a.txt"), "x\n")
		git("add", ".")
		git("commit", "-qm", "primero")
		d, err := gitdiff.Staged(repo)
		if err != nil {
			t.Fatalf("un repo limpio no puede dar error: %v", err)
		}
		if len(d.Files) != 0 {
			t.Errorf("no había nada preparado y salieron %d archivo(s)", len(d.Files))
		}
	})

	// El primer commit de un repo recién creado: no hay HEAD todavía. Es el
	// caso que más fácil se rompería al fallar cerrado, y no se rompe.
	t.Run("repo sin ningun commit todavia", func(t *testing.T) {
		repo, git := repoEnrolado(t)
		escribirEnRepo(t, filepath.Join(repo, "a.txt"), "x\n")
		git("add", ".")
		d, err := gitdiff.Staged(repo)
		if err != nil {
			t.Fatalf("el primer commit de un repo no puede dar error: %v", err)
		}
		if len(d.Files) == 0 {
			t.Error("había contenido preparado y no salió ningún archivo")
		}
	})

	t.Run("indice ilegible", func(t *testing.T) {
		repo, git := repoEnrolado(t)
		escribirEnRepo(t, filepath.Join(repo, "a.txt"), "x\n")
		git("add", ".")
		escribirEnRepo(t, filepath.Join(repo, ".git", "index"), "esto-no-es-un-indice-de-git")
		if _, err := gitdiff.Staged(repo); err == nil {
			t.Error("un índice corrupto tiene que dar error; si saliera vacío y sin error, " +
				"el hook no podría distinguirlo de «no hay nada que revisar»")
		}
	})
}
