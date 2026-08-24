package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
)

// romperElBaseline deja .codeguard/baseline.txt como DIRECTORIO: el pipeline
// corre entero y la escritura atómica del baseline falla al final, que es
// exactamente el punto en el que el enrolamiento quedaba a medias.
func romperElBaseline(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repo, filepath.FromSlash(baseline.RelPath)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func commitDePrueba(t *testing.T, repo string) {
	t.Helper()
	escribirEnRepo(t, filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "semilla"}} {
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
}

// UN ENROLAMIENTO O SE COMPLETA O SE DESHACE.
//
// Si el baseline falla, dejar config y ganchos puestos es el peor estado que
// conoce este producto: el siguiente commit bloquea con TODA la deuda
// preexistente. Antes el error lo DESCRIBÍA y lo dejaba así; ahora lo revierte.
func TestSiFallaElBaselineElInitNoDejaElRepoAMedias(t *testing.T) {
	repo := repoConHooksPath(t, "")
	commitDePrueba(t, repo)
	romperElBaseline(t, repo)

	_, err := capturarStdout(t, func() error {
		c := initCmd()
		c.SetArgs(nil)
		return c.RunE(c, nil)
	})
	if err == nil {
		t.Fatal("el init tendría que fallar: el baseline no se puede escribir")
	}
	if !strings.Contains(err.Error(), "falló el baseline") {
		t.Errorf("el error no dice qué falló: %v", err)
	}
	if !strings.Contains(err.Error(), "queda como estaba") {
		t.Errorf("el error no dice que se deshizo el enrolamiento: %v", err)
	}
	// Los ganchos quedan desarmados: sin core.hooksPath, git no ejecuta nada
	// nuestro y el repo está como antes del init.
	if v := hooksPathDe(t, repo); v != "" {
		t.Errorf("los ganchos siguen armados en %q: el próximo commit bloquearía con "+
			"toda la deuda preexistente y sin baseline que lo explique", v)
	}
	// Y la config que creó ESTE init se va con él: si se quedara, un reintento
	// chocaría con el os.Stat que exige --force.
	if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(config.RelPath))); err == nil {
		t.Error("la config del init fallido sigue ahí: el reintento pediría --force")
	}
}

// La config del USUARIO no se toca: con --force este init pisó una que ya
// existía, y ésa no se puede reponer, así que borrarla sería destruir trabajo.
func TestElDeshacerNoBorraLaConfigQueYaExistia(t *testing.T) {
	repo := repoConHooksPath(t, "")
	commitDePrueba(t, repo)
	cfg := filepath.Join(repo, filepath.FromSlash(config.RelPath))
	escribirEnRepo(t, cfg, "languages: [go]\n# esto lo escribió el usuario\n")
	romperElBaseline(t, repo)

	_, err := capturarStdout(t, func() error {
		c := initCmd()
		if err := c.Flags().Set("force", "true"); err != nil {
			return err
		}
		return c.RunE(c, nil)
	})
	if err == nil {
		t.Fatal("el init tendría que fallar")
	}
	if _, statErr := os.Stat(cfg); statErr != nil {
		t.Errorf("se borró una config que ya existía antes del init: %v", statErr)
	}
}
