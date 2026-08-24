package linters

// El veredicto de ruff sobre un archivo NO es función de (config, contenido).
//
// ruff selecciona reglas por patrón de RUTA: per-file-ignores, exclude,
// extend-exclude. El mismo texto en tests/dup.py y en src/dup.py puede salir
// limpio en uno y con hallazgo en el otro, y eso es exactamente lo que la
// configuración del repo pide que pase.
//
// La clave del caché era "ruff:<config>:<sha del contenido>": colapsaba en una
// sola entrada dos casos que ruff distingue. El fallo no es ruido, es silencio
// — el hallazgo del archivo estricto desaparece porque su gemelo permisivo
// pasó primero por el caché.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// ruffFalso deja en disco un ruff de mentira: apunta cada invocación en un
// registro y, cuando le piden `check`, devuelve siempre el mismo F841 sobre
// src/dup.py. Sirve para distinguir "lo analizó" de "se lo sirvió el caché",
// que a ojos del llamador se parecen demasiado.
func ruffFalso(t *testing.T) (bin string, veces func() int) {
	t.Helper()
	dir := t.TempDir()
	registro := filepath.Join(dir, "invocaciones.txt")
	bin = filepath.Join(dir, "ruff.cmd")

	const diag = `[{"code":"F841","message":"Local variable 'x' is assigned to but never used",` +
		`"filename":"src/dup.py","location":{"row":2},"fix":null}]`
	guion := "@echo off\r\n" +
		">>\"" + registro + "\" echo %1\r\n" +
		"if not \"%1\"==\"check\" exit /b 0\r\n" +
		"echo " + diag + "\r\n" +
		"exit /b 0\r\n"
	if err := os.WriteFile(bin, []byte(guion), 0o755); err != nil {
		t.Fatal(err)
	}

	return bin, func() int {
		raw, err := os.ReadFile(registro)
		if err != nil {
			return 0
		}
		return len(strings.Fields(string(raw)))
	}
}

func TestRuffCacheNoCruzaRutas(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("el ruff de mentira es un .cmd")
	}
	root := t.TempDir()
	escribir := func(rel, contenido string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// La config perdona F841 en tests/ y no en src/: dos veredictos distintos
	// para el mismo texto, por decisión explícita del repo.
	escribir("pyproject.toml", "[tool.ruff.lint.per-file-ignores]\n\"tests/**\" = [\"F841\"]\n")
	const codigo = "def f():\n    x = 1\n"
	escribir("src/dup.py", codigo)
	escribir("tests/dup.py", codigo)

	suma := sha256.Sum256([]byte(codigo))
	sha := hex.EncodeToString(suma[:])

	bin, veces := ruffFalso(t)

	// El caché ya vio tests/dup.py y lo anotó limpio —lo está—, bajo la clave
	// de sólo-contenido que usaba el motor.
	cache := &cacheDeMemoria{datos: map[string][]finding.Finding{
		"ruff:" + huellaConfigRuff(root, []gitdiff.ChangedFile{{Path: "src/dup.py", Status: "M", SHA256: sha}}) + ":" + sha: {},
	}}

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/dup.py", Status: "M", SHA256: sha},
	}}

	fs, err := (Ruff{Binary: bin, Cache: cache}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("el motor no llegó a correr: %v", err)
	}
	if veces() == 0 {
		t.Fatal("no se invocó a ruff: el veredicto de tests/dup.py se sirvió para " +
			"src/dup.py. Son rutas distintas y la config les aplica reglas distintas; " +
			"el F841 de src/dup.py desaparece del informe sin dejar rastro")
	}
	if len(fs) != 1 || fs[0].RuleKey != "F841" {
		t.Fatalf("esperaba el F841 de src/dup.py, obtuve %+v", fs)
	}
	if fs[0].File != "src/dup.py" {
		t.Errorf("el hallazgo apunta a %q", fs[0].File)
	}

	// Y la otra mitad: el caché tiene que seguir acertando sobre el MISMO
	// archivo, o el arreglo sería apagarlo.
	antes := veces()
	fs2, err := (Ruff{Binary: bin, Cache: cache}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("segunda corrida: %v", err)
	}
	if veces() != antes {
		t.Errorf("la segunda corrida sobre el mismo archivo volvió a invocar a ruff: "+
			"el caché dejó de acertar (%d invocaciones nuevas)", veces()-antes)
	}
	if len(fs2) != 1 || fs2[0].RuleKey != "F841" || fs2[0].File != "src/dup.py" {
		t.Errorf("el acierto de caché debe reproducir el hallazgo tal cual: %+v", fs2)
	}
}

// La misma verdad dicha sobre la clave: dos rutas con contenido idéntico y la
// misma config no pueden compartir entrada.
func TestClaveDeRuffLlevaLaRuta(t *testing.T) {
	fs := []finding.Finding{}
	archivos := []gitdiff.ChangedFile{
		{Path: "src/dup.py", SHA256: "elmismosha"},
		{Path: "tests/dup.py", SHA256: "elmismosha"},
	}
	claves := porArchivoRuff(fs, archivos, "cfg", t.TempDir())
	if len(claves) != 2 {
		t.Fatalf("dos archivos, dos entradas; se guardaron %d: %v", len(claves), claves)
	}
	for _, e := range claves {
		if e.Vigente == nil {
			t.Errorf("toda entrada lleva su prueba de vigencia (bug #8): %s no la trae", e.Clave)
		}
	}
}
