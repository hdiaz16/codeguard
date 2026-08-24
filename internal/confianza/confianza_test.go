package confianza

import (
	"os"
	"path/filepath"
	"testing"
)

func repoConEslintJS(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "eslint.config.js"),
		[]byte("module.exports = [];\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "app.js"), []byte("const x=1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

// El corazón del cierre (W4, Q3): un repo con eslint.config.js EJECUTABLE
// degrada eslint POR DEFECTO, y sólo tras confiar deja de degradarlo. El
// registro vive en LOCALAPPDATA (aislado por t.Setenv), jamás en el repo.
func TestConfigEjecutableSeDegradaHastaQueSeConfia(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	repo := repoConEslintJS(t)
	motores := []string{"gitleaks", "eslint", "semgrep", "tsc"}

	// Por defecto: eslint y tsc (ejecutan config/binario del repo) se degradan;
	// gitleaks y semgrep (leen datos) no.
	arts, degradados := MotoresDegradados(repo, motores)
	if len(arts) == 0 {
		t.Fatal("no se detectó el eslint.config.js ejecutable")
	}
	if !contiene(degradados, "eslint") || !contiene(degradados, "tsc") {
		t.Fatalf("eslint y tsc debían degradarse por defecto, got: %v", degradados)
	}
	if contiene(degradados, "gitleaks") || contiene(degradados, "semgrep") {
		t.Fatalf("los motores que leen datos NO se degradan: %v", degradados)
	}

	// Tras confiar: nada se degrada.
	if err := Registrar(repo, Digest(arts), "2026-08-23T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, degradados := MotoresDegradados(repo, motores); len(degradados) > 0 {
		t.Fatalf("tras confiar no debía degradarse nada: %v", degradados)
	}

	// Si la config CAMBIA, la confianza caduca (TOFU sobre el contenido).
	if err := os.WriteFile(filepath.Join(repo, "eslint.config.js"),
		[]byte("require('child_process').execSync('calc');\nmodule.exports = [];\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, degradados := MotoresDegradados(repo, motores); !contiene(degradados, "eslint") {
		t.Fatal("una config-ejecutable EDITADA debía volver a degradar: el digest no siguió el contenido")
	}

	// Revocar vuelve a degradar aunque el contenido sea el confiado.
	arts, _ = MotoresDegradados(repo, motores)
	_ = Registrar(repo, Digest(arts), "2026-08-23T00:00:00Z")
	if err := Revocar(repo); err != nil {
		t.Fatal(err)
	}
	if _, degradados := MotoresDegradados(repo, motores); !contiene(degradados, "eslint") {
		t.Fatal("tras revocar, eslint debía degradarse de nuevo")
	}
}

// Un repo SIN config-ejecutable (Go puro) no degrada nada: no hay nada que
// confiar y el guardián no molesta.
func TestRepoSinConfigEjecutableNoSeToca(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	repo := t.TempDir()
	_ = os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n"), 0o644)
	arts, degradados := MotoresDegradados(repo, []string{"gofmt", "eslint", "mypy"})
	if len(arts) != 0 || len(degradados) != 0 {
		t.Fatalf("un repo Go puro no tiene config-ejecutable: arts=%v degradados=%v", arts, degradados)
	}
}

// Un eslintrc de DATOS (.json/.yaml) NO es config-ejecutable: no requiere
// confianza (no ejecuta nada). Sólo los .js/.cjs/.mjs.
func TestEslintrcDeDatosNoRequiereConfianza(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	repo := t.TempDir()
	_ = os.WriteFile(filepath.Join(repo, ".eslintrc.json"), []byte("{}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repo, "app.js"), []byte("const x=1;\n"), 0o644)
	if arts := Detectar(repo); len(arts) != 0 {
		t.Fatalf(".eslintrc.json es datos, no código: no debía detectarse (%v)", arts)
	}
}

// El fail-closed del registro: sin LOCALAPPDATA nada está confiado (el default
// seguro no depende de poder leer/escribir el registro).
func TestSinLocalAppDataNadaSeConfia(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	repo := repoConEslintJS(t)
	arts, degradados := MotoresDegradados(repo, []string{"eslint"})
	if len(arts) == 0 || !contiene(degradados, "eslint") {
		t.Fatal("sin LOCALAPPDATA el default seguro debía seguir degradando eslint")
	}
}

func contiene(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
