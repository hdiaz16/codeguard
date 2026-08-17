package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// El rulepack se resuelve en cuatro sitios y el orden importa. Lo vendoreado en
// el repo es el RESPALDO, no la preferencia: se usa cuando esa versión no está
// instalada, y pierde contra ella cuando lo está.
//
// Este test decía lo contrario, y el contrario era explotable: mientras el repo
// analizado ganaba, bastaba traer un `rulepacks/<la versión que pinnea>/` con
// reglas de relleno para que las de la casa no llegaran a mirar el código.
// Medido con el mismo archivo y una inyección SQL de manual: BLOQUEADO con el
// rulepack instalado, "formato/lint/tipos/reglas/migraciones ✓  listo — commit
// permitido" con el del repo. Sin carrera y sin atacante sofisticado: basta
// clonar el repositorio.
//
// Lo que el respaldo sigue resolviendo, y por eso no desaparece: el binario
// instalado vive en CodeGuard\bin, pero cualquier otro —una compilación de
// desarrollo, una copia portable— no tiene rulepacks al lado, y sin esta cadena
// todo repo perdía las 119 reglas de la casa EN SILENCIO (semgrep "corría" en
// 0 ms con 0 hallazgos).
func TestRulepackDirPrefiereLoInstaladoSobreLoVendoreado(t *testing.T) {
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
	instalado := crear(filepath.Join(instalacion, "CodeGuard"), "2026.08.2")
	if got := RulepackDir(repo, "2026.08.2"); got != instalado {
		t.Errorf("con el pack sólo en la instalación estándar:\n  got  %s\n  want %s", got, instalado)
	}

	// Y ahora el repo trae el SUYO con el mismo número. El mismo número
	// nombrando dos artefactos distintos es una colisión, y en una colisión gana
	// el de la organización: la versión es una promesa de paridad con el CI, y
	// quien analiza no puede dejar que el analizado elija con qué se le mide.
	vendoreado := crear(repo, "2026.08.2")
	if got := RulepackDir(repo, "2026.08.2"); got != instalado {
		t.Errorf("el repo analizado NO puede imponer sus reglas sobre las instaladas:\n"+
			"  got  %s\n  want %s", got, instalado)
	}
	// Con una versión que sólo está vendoreada, el respaldo entra: es el caso
	// que justificó la cadena y no puede romperse.
	soloEnElRepo := crear(repo, "2026.09.9")
	if got := RulepackDir(repo, "2026.09.9"); got != soloEnElRepo {
		t.Errorf("una versión que sólo está vendoreada tiene que usarse igual:\n  got  %s\n  want %s", got, soloEnElRepo)
	}
	// …y se puede DECIR, que es la otra mitad: el hook avisaba a gritos cuando
	// el rulepack falta y callaba cuando lo sustituyen.
	if !RulepackEsDelRepo(repo, "2026.09.9") {
		t.Error("una versión que sale del repo tiene que poder anunciarse como tal")
	}
	if RulepackEsDelRepo(repo, "2026.08.2") {
		t.Errorf("se anunció como vendoreado un pack que salió de la instalación: %s", vendoreado)
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
