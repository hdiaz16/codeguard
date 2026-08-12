package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// El rulepack se resuelve en cuatro sitios y el orden importa: lo vendoreado
// en el repo manda sobre lo instalado (un repo puede fijar SUS reglas), y la
// instalación estándar del usuario es el último recurso.
//
// Los dos sitios de en medio son la lección: el binario instalado vive en
// CodeGuard\bin, pero cualquier otro binario —una compilación de desarrollo,
// una copia portable— no tiene rulepacks al lado, y entonces todo repo que no
// los vendoree perdía las 119 reglas de la casa EN SILENCIO (semgrep "corría"
// en 0 ms con 0 hallazgos). Se reprodujo en un repo de prueba antes de existir
// este test.
func TestRulepackDirPrefiereLoVendoreado(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)

	crear := func(base, version string) string {
		t.Helper()
		dir := filepath.Join(base, "rulepacks", version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	// Sólo la instalación estándar lo tiene: ahí debe encontrarlo.
	esperado := crear(filepath.Join(instalacion, "CodeGuard"), "2026.08.2")
	if got := RulepackDir(repo, "2026.08.2"); got != esperado {
		t.Errorf("con el pack sólo en la instalación estándar:\n  got  %s\n  want %s", got, esperado)
	}

	// Vendoreado en el repo: gana sobre todo lo demás.
	vendoreado := crear(repo, "2026.08.2")
	if got := RulepackDir(repo, "2026.08.2"); got != vendoreado {
		t.Errorf("lo vendoreado en el repo debe ganar:\n  got  %s\n  want %s", got, vendoreado)
	}

	// Una versión que no está en ningún sitio devuelve la ruta del repo, para
	// que el mensaje de error hable de donde el dev PODRÍA vendorearla.
	quiere := filepath.Join(repo, "rulepacks", "2099.01.1")
	if got := RulepackDir(repo, "2099.01.1"); got != quiere {
		t.Errorf("sin candidatos debe devolver la ruta del repo:\n  got  %s\n  want %s", got, quiere)
	}
}

// RulepacksInstalados no puede contradecir a RulepackDir: si la resolución
// mira cuatro sitios, el listado que se le enseña al dev ("instaladas: ...")
// mira los mismos cuatro.
func TestRulepacksInstaladosVeLaInstalacionEstandar(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)
	for _, v := range []string{"2026.08.2", "2026.09.1"} {
		if err := os.MkdirAll(filepath.Join(instalacion, "CodeGuard", "rulepacks", v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := RulepacksInstalados(repo)
	// Orden: de más nueva a más vieja.
	if len(got) != 2 || got[0] != "2026.09.1" || got[1] != "2026.08.2" {
		t.Fatalf("instaladas = %v, esperaba [2026.09.1 2026.08.2]", got)
	}
}
