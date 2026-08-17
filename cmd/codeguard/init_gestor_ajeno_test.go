package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `init` enrola el repo y AL FINAL instala los ganchos, así que hereda el
// conflicto de `install` en el peor momento posible: con la config ya escrita.
//
// Medido antes de este arreglo: en un repo con husky, `init` imprimía "config
// generada", luego la negativa de `install` —que dice "No he tocado nada"— y
// salía en error. Las dos cosas a la vez son mentira y basura en el árbol: queda
// un .codeguard/config.yaml sin baseline, sin ganchos y sin proyecto registrado,
// o sea un repo a medio enrolar que aparenta estarlo.
//
// Por eso la comprobación va en `init` TAMBIÉN, y antes de la primera escritura.
// No es duplicar la de `install`: es el mismo detector llamado en el único
// momento en que negarse todavía deja el repo intacto.
func TestInitNoEscribeNadaSiOtroGestorManda(t *testing.T) {
	repo := repoConHooksPath(t, ".husky")
	escribirEnRepo(t, filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
	add := exec.Command("git", "add", "-A")
	add.Dir = repo
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}

	cmd := initCmd()
	salida, err := capturarStdout(t, func() error { return cmd.RunE(cmd, nil) })

	if err == nil {
		t.Fatalf("init enroló un repo con husky sin decir nada:\n%s", salida)
	}
	msg := err.Error()

	// Lo que importa: el repo quedó como estaba.
	for _, rastro := range []string{".codeguard", ".githooks", ".gitattributes"} {
		if _, serr := os.Stat(filepath.Join(repo, rastro)); serr == nil {
			t.Errorf("init se negó pero dejó %s en el repo. Un enrolamiento a medias "+
				"—config sin ganchos ni baseline— parece un repo enrolado y no lo está", rastro)
		}
	}
	if v := hooksPathDe(t, repo); v != ".husky" {
		t.Errorf("core.hooksPath quedó en %q: init pisó los ganchos de husky", v)
	}

	// Y manda al comando que el usuario está usando. `init` remitiendo a
	// `install --sustituir-hooks` deja el repo sin config: no es el arreglo.
	if !strings.Contains(msg, "codeguard init --"+banderaSustituir) {
		t.Errorf("el mensaje de init no ofrece `codeguard init --%s`, que es lo que "+
			"resuelve SU caso:\n%s", banderaSustituir, msg)
	}
	if strings.Contains(msg, "codeguard install --"+banderaSustituir) {
		t.Errorf("init manda a `codeguard install --%s`, que enrola a medias "+
			"(ganchos sin config):\n%s", banderaSustituir, msg)
	}
}

// La bandera de `init` tiene que LLEGAR hasta `install`, que es quien escribe.
//
// Son dos puertas seguidas y sólo una lee la bandera: sin reenviarla, `init
// --sustituir-hooks` pasaba la primera y se estrellaba contra la segunda, que no
// se había enterado. El usuario ya había decidido, escribió la bandera que le
// pedimos, y el producto le repetía la misma negativa — la salida que ofrecemos
// no existiría.
//
// Es el camino completo a propósito: enrola de verdad, con su baseline. Lo que
// esta prueba defiende es que la decisión no se pierda por el camino, y eso sólo
// se ve corriendo el camino.
func TestInitConLaBanderaLlegaHastaLaEscritura(t *testing.T) {
	repo := repoConHooksPath(t, ".husky")
	escribirEnRepo(t, filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
	add := exec.Command("git", "add", "-A")
	add.Dir = repo
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	// Sin daemon: el enrolamiento avisa al agente y aquí no hay ninguno. Con un
	// canal que no existe, la prueba recorre siempre la misma rama.
	t.Setenv("CODEGUARD_PIPE", `\\.\pipe\codeguard-test-inexistente-init`)

	cmd := initCmd()
	if err := cmd.Flags().Set(banderaSustituir, "true"); err != nil {
		t.Fatalf("`init` no tiene la bandera --%s: la salida que ofrece su propio mensaje no existe: %v",
			banderaSustituir, err)
	}
	salida, err := capturarStdout(t, func() error { return cmd.RunE(cmd, nil) })
	if err != nil {
		t.Fatalf("init --%s falló: %v\n%s", banderaSustituir, err, salida)
	}

	if v := hooksPathDe(t, repo); v != ".githooks" {
		t.Errorf("core.hooksPath quedó en %q: la bandera de init no llegó a quien escribe", v)
	}
	if !strings.Contains(salida, "husky") {
		t.Errorf("sustituyó los ganchos de husky sin nombrarlo por ningún lado:\n%s", salida)
	}
}
