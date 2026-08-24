package main

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// [31] del plan: init = RECONCILIACIÓN. Sin --force sobre un repo enrolado ya
// no es un error — verifica; sano = NO-OP exitoso QUE LO DICE (la idempotencia
// es de ACCIÓN: si reescribiera algo aunque todo esté bien, el crash-injection
// no podría distinguir «reparó» de «reescribió» — turno 89); cableado roto =
// se repara SOLO lo nuestro; config.yaml y baseline JAMÁS se tocan por aquí.

func shaDe(t *testing.T, ruta string) string {
	t.Helper()
	raw, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return string(h[:])
}

func enrolarDeVerdad(t *testing.T) string {
	t.Helper()
	repo := repoConHooksPath(t, "") // sin gestor ajeno
	escribirEnRepo(t, filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
	add := exec.Command("git", "add", "-A")
	add.Dir = repo
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	t.Setenv("CODEGUARD_PIPE", `\\.\pipe\codeguard-test-inexistente-reconcilia`)
	aprovisionarPostcondicionesDeInit(t, repo)
	cmd := initCmd()
	if salida, err := capturarStdout(t, func() error { return cmd.RunE(cmd, nil) }); err != nil {
		t.Fatalf("el enrolamiento base falló: %v\n%s", err, salida)
	}
	return repo
}

func TestInitSobreRepoSanoEsNoOpExitosoQueLoDice(t *testing.T) {
	repo := enrolarDeVerdad(t)
	cfg := filepath.Join(repo, ".codeguard", "config.yaml")
	base := filepath.Join(repo, ".codeguard", "baseline.txt")
	cfgAntes, baseAntes := shaDe(t, cfg), shaDe(t, base)

	cmd := initCmd()
	salida, err := capturarStdout(t, func() error { return cmd.RunE(cmd, nil) })
	if err != nil {
		t.Fatalf("init sobre un repo sano tiene que ser éxito, no error: %v\n%s", err, salida)
	}
	if !strings.Contains(salida, "ya enrolado y sano") {
		t.Errorf("el NO-OP no se declaró:\n%s", salida)
	}
	if shaDe(t, cfg) != cfgAntes {
		t.Error("la reconciliación tocó config.yaml: su contenido es decisión del usuario")
	}
	if shaDe(t, base) != baseAntes {
		t.Error("la reconciliación tocó la baseline: re-aceptar deuda exige --rebaseline explícito")
	}
}

func TestInitReparaElCableadoRotoSinTocarLosDatos(t *testing.T) {
	repo := enrolarDeVerdad(t)
	cfg := filepath.Join(repo, ".codeguard", "config.yaml")
	base := filepath.Join(repo, ".codeguard", "baseline.txt")
	cfgAntes, baseAntes := shaDe(t, cfg), shaDe(t, base)

	// El crash-injection de la aceptación, en su forma mínima: un hook
	// desaparece (instalación a medias, borrado accidental).
	if err := os.Remove(filepath.Join(repo, ".githooks", "pre-commit")); err != nil {
		t.Fatal(err)
	}

	cmd := initCmd()
	salida, err := capturarStdout(t, func() error { return cmd.RunE(cmd, nil) })
	if err != nil {
		t.Fatalf("la reconciliación del cableado falló: %v\n%s", err, salida)
	}
	if !strings.Contains(salida, "reconciliando el cableado") {
		t.Errorf("no declaró qué reparaba:\n%s", salida)
	}
	if _, err := os.Stat(filepath.Join(repo, ".githooks", "pre-commit")); err != nil {
		t.Error("el hook borrado no se reparó: la segunda corrida no convergió")
	}
	if shaDe(t, cfg) != cfgAntes || shaDe(t, base) != baseAntes {
		t.Error("reparar el cableado tocó config o baseline: eso no es reconciliar, es regenerar")
	}
}
