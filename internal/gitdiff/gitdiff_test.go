package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoDePrueba fabrica un repo git real con un commit base. Los tests de este
// paquete no se pueden simular: el contrato ES lo que git devuelve.
func repoDePrueba(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.email", "test@codeguard.local")
	git("config", "user.name", "test")
	git("config", "commit.gpgsign", "false")
	escribir(t, dir, "base.go", "package p\n\nfunc Base() int { return 1 }\n")
	escribir(t, dir, "borrar.go", "package p\n\nfunc Borrar() int { return 2 }\n")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	return dir
}

func escribir(t *testing.T, dir, rel, contenido string) {
	t.Helper()
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestStagedDetectaAltasModificacionesYBajas(t *testing.T) {
	dir := repoDePrueba(t)
	escribir(t, dir, "nuevo.go", "package p\n\nfunc Nuevo() {}\n")
	escribir(t, dir, "base.go", "package p\n\nfunc Base() int { return 99 }\n")
	git(t, dir, "add", "nuevo.go", "base.go")
	git(t, dir, "rm", "-q", "borrar.go")

	d, err := Staged(dir)
	if err != nil {
		t.Fatal(err)
	}
	estados := map[string]string{}
	for _, f := range d.Files {
		estados[f.Path] = f.Status
	}
	if estados["nuevo.go"] != "A" {
		t.Errorf("nuevo.go debía ser A, fue %q", estados["nuevo.go"])
	}
	if estados["base.go"] != "M" {
		t.Errorf("base.go debía ser M, fue %q", estados["base.go"])
	}
	if estados["borrar.go"] != "D" {
		t.Errorf("borrar.go debía ser D, fue %q", estados["borrar.go"])
	}
	// Un archivo borrado no tiene contenido que hashear.
	for _, f := range d.Files {
		if f.Status == "D" && f.SHA256 != "" {
			t.Errorf("%s está borrado y trae hash %q", f.Path, f.SHA256)
		}
		if f.Status != "D" && f.SHA256 == "" {
			t.Errorf("%s existe y no trae hash", f.Path)
		}
	}
	if d.Lines == 0 {
		t.Error("el conteo de líneas del diff quedó en cero")
	}
	if !strings.Contains(d.Unified, "func Nuevo()") {
		t.Error("el diff unificado no contiene el cambio nuevo")
	}
}

// El corazón de la paridad (§4.1): el hash del contenido se calcula sobre LF,
// así que la MISMA edición debe dar el MISMO hash aunque una máquina escriba
// CRLF y otra LF. Sin esto, el ci_parity se rompe entre Windows y el runner.
func TestElHashNoDependeDeLosFinalesDeLinea(t *testing.T) {
	dirLF := repoDePrueba(t)
	dirCRLF := repoDePrueba(t)

	escribir(t, dirLF, "igual.go", "package p\n\nfunc Igual() int { return 7 }\n")
	escribir(t, dirCRLF, "igual.go", "package p\r\n\r\nfunc Igual() int { return 7 }\r\n")
	git(t, dirLF, "add", "igual.go")
	git(t, dirCRLF, "add", "igual.go")

	dLF, err := Staged(dirLF)
	if err != nil {
		t.Fatal(err)
	}
	dCRLF, err := Staged(dirCRLF)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(d *Diff) string {
		for _, f := range d.Files {
			if f.Path == "igual.go" {
				return f.SHA256
			}
		}
		return ""
	}
	hLF, hCRLF := hash(dLF), hash(dCRLF)
	if hLF == "" || hCRLF == "" {
		t.Fatal("falta el hash de igual.go en alguno de los repos")
	}
	if hLF != hCRLF {
		t.Errorf("el mismo contenido con finales distintos dio hashes distintos:\n  LF:   %s\n  CRLF: %s", hLF, hCRLF)
	}
}

// git reporta un rename como "R100\tviejo\tnuevo": el destino es el último
// campo. Confundirse aquí haría analizar un archivo que ya no existe.
func TestRenameUsaLaRutaDestino(t *testing.T) {
	dir := repoDePrueba(t)
	git(t, dir, "mv", "base.go", "renombrado.go")

	d, err := Staged(dir)
	if err != nil {
		t.Fatal(err)
	}
	var visto *ChangedFile
	for i := range d.Files {
		if d.Files[i].Status == "R" {
			visto = &d.Files[i]
		}
	}
	if visto == nil {
		t.Fatal("no se reportó ningún rename")
	}
	if visto.Path != "renombrado.go" {
		t.Errorf("el rename debe apuntar al destino, apuntó a %q", visto.Path)
	}
	if visto.SHA256 == "" {
		t.Error("el destino del rename existe y debe llevar hash")
	}
}

func TestSinCambiosDevuelveDiffVacio(t *testing.T) {
	dir := repoDePrueba(t)
	d, err := Staged(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 0 || d.Lines != 0 {
		t.Errorf("sin nada staged: %d archivos, %d líneas", len(d.Files), d.Lines)
	}
}

func TestRepoRoot(t *testing.T) {
	dir := repoDePrueba(t)
	sub := filepath.Join(dir, "internal", "hondo")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := RepoRoot(sub)
	if err != nil {
		t.Fatal(err)
	}
	// git devuelve la ruta con /; se compara normalizado y sin distinguir
	// mayúsculas (TempDir puede venir como C:\Users\HECTOR~1 vs c:/users/...).
	quiero, _ := filepath.EvalSymlinks(dir)
	tengo, _ := filepath.EvalSymlinks(filepath.FromSlash(root))
	if !strings.EqualFold(tengo, quiero) {
		t.Errorf("RepoRoot devolvió %q, se esperaba %q", tengo, quiero)
	}

	if _, err := RepoRoot(t.TempDir()); err == nil {
		t.Error("fuera de un repo git debe fallar, no inventarse una raíz")
	}
}
