package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializarIndiceIgnoraElWorktree(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "preparado.txt", "versión DEL ÍNDICE\n")
	escribir(t, repo, "borrado.txt", "no debe sobrevivir\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-m", "base")

	escribir(t, repo, "preparado.txt", "segunda versión PREPARADA\n")
	escribir(t, repo, "nuevo/áé.txt", "sólo en el índice\n")
	if err := os.Remove(filepath.Join(repo, "borrado.txt")); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "-A")

	// El disco se separa después del add y además recibe un archivo no rastreado.
	escribir(t, repo, "preparado.txt", "versión SUCIA DEL DISCO\n")
	escribir(t, repo, "no-preparado.txt", "no debe entrar\n")

	inst, err := MaterializarIndice(repo)
	if err != nil {
		t.Fatal(err)
	}
	raiz := inst.Root
	t.Cleanup(func() { _ = inst.Cerrar() })

	assertContenido := func(rel, esperado string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(raiz, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("leer %s: %v", rel, err)
		}
		if string(raw) != esperado {
			t.Fatalf("%s no salió del índice: %q", rel, raw)
		}
	}
	assertContenido("preparado.txt", "segunda versión PREPARADA\n")
	assertContenido("nuevo/áé.txt", "sólo en el índice\n")

	for _, rel := range []string{"borrado.txt", "no-preparado.txt"} {
		if _, err := os.Stat(filepath.Join(raiz, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s no pertenece al índice y apareció en la instantánea (err=%v)", rel, err)
		}
	}

	// Congelada significa congelada: el worktree puede seguir cambiando.
	escribir(t, repo, "preparado.txt", "tercera versión\n")
	assertContenido("preparado.txt", "segunda versión PREPARADA\n")
}

func TestCerrarInstantaneaEliminaElArbol(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "a.txt", "a\n")
	git(t, repo, "add", "-A")
	inst, err := MaterializarIndice(repo)
	if err != nil {
		t.Fatal(err)
	}
	raiz := inst.Root
	if err := inst.Cerrar(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(raiz); !os.IsNotExist(err) {
		t.Fatalf("la instantánea no se eliminó: %v", err)
	}
	if err := inst.Cerrar(); err != nil {
		t.Fatalf("Cerrar debe tolerar una segunda llamada: %v", err)
	}
}

func TestMaterializarIndiceRespetaGitIndexFile(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "a.txt", "índice real\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-m", "base")

	indiceTemporal := filepath.Join(t.TempDir(), "index-temporal")
	gitConIndice := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+indiceTemporal)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s con índice temporal: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	gitConIndice("read-tree", "HEAD")
	escribir(t, repo, "a.txt", "contenido del ÍNDICE TEMPORAL\n")
	gitConIndice("add", "a.txt")
	escribir(t, repo, "a.txt", "worktree que no debe leerse\n")

	t.Setenv("GIT_INDEX_FILE", indiceTemporal)
	inst, err := MaterializarIndice(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Cerrar() })
	raw, err := os.ReadFile(filepath.Join(inst.Root, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "contenido del ÍNDICE TEMPORAL\n" {
		t.Fatalf("se materializó el índice real o el worktree, no GIT_INDEX_FILE: %q", raw)
	}
}
