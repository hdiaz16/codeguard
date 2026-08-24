package pipeline_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures adversariales PERMANENTES de la clase «config ejecutable» (W4,
// tanda d, t.116). Un repo HOSTIL trae configuración que es CÓDIGO —
// eslint.config.js, un target de MSBuild, un mypy.ini con plugin, y el peor:
// el binario node_modules/.bin del propio repo— y CodeGuard lo ejecuta con
// los permisos del dev. Estos tests miden el PISO de W4 (env-scrub +
// fail-visible + egress-hint) contra esa clase con la honestidad que el
// consejo exigió (Kimi t.110): donde el piso NO contiene, el test lo DICE en
// vez de fingir que sí — hasta que el interruptor de confianza de la Q3
// (decisión de Héctor) cierre el hueco.
//
// Corren por el BINARIO compilado (`correr`, con CODEGUARD_PIPE a un pipe
// inexistente para forzar el análisis en proceso): así miden el hook real y
// esquivan el ciclo de import pipeline↔daemon. El mecanismo es un SEÑUELO
// fuera del repo: la config hostil intenta escribir una prueba de vida ahí.
// Si aparece, el código del repo se ejecutó con acceso fuera del árbol — y
// eso es lo que hay que saber, se contenga o no.

func señuelo(t *testing.T) (aLeer, vida string) {
	t.Helper()
	dirFuera := t.TempDir()
	aLeer = filepath.Join(dirFuera, "secreto-fuera.txt")
	if err := os.WriteFile(aLeer, []byte("PROPIEDAD-DE-OTRO"), 0o644); err != nil {
		t.Fatal(err)
	}
	return aLeer, filepath.Join(dirFuera, "prueba-de-vida.txt")
}

// exigirNoTocado es el CIERRE demostrado (W4, Q3): con el default seguro —el
// repo NO confiado— el motor config-ejecutable no corre, así que su config
// hostil JAMÁS se ejecuta y el señuelo queda intacto. Si aparece, el guardián
// de confianza falló y hay que saberlo: es el hueco reabierto.
func exigirNoTocado(t *testing.T, quien, vida, salida string) {
	t.Helper()
	if _, err := os.Stat(vida); err == nil {
		t.Fatalf("%s TOCÓ el señuelo fuera del árbol con el repo SIN confiar: el guardián "+
			"de confianza no degradó el motor. Salida: %s", quien, primeraLineaDe(salida))
	}
	t.Logf("%s: cierre OK — sin confianza el motor no ejecutó la config del repo; el señuelo quedó intacto", quien)
}

func primeraLineaDe(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return "(sin salida)"
}

func TestAdversarial_ESLintConfigEjecutable(t *testing.T) {
	if testing.Short() || runtimeNoWindows(t) {
		return
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("sin npm: el fixture de eslint no puede montar node_modules")
	}
	bin := construirBinario(t)
	repo := montarRepo(t)
	aLeer, vida := señuelo(t)

	// eslint.config.js NO es datos: es un módulo que corre al cargar. Lee el
	// señuelo de fuera y escribe la prueba de vida.
	cfgJS := "const fs = require('fs');\n" +
		"try { const s = fs.readFileSync(String.raw`" + aLeer + "`, 'utf8');\n" +
		"  fs.writeFileSync(String.raw`" + vida + "`, s); } catch (e) {}\n" +
		"module.exports = [];\n"
	escribir(t, repo, "eslint.config.js", cfgJS)
	escribir(t, repo, "package.json",
		"{\n  \"name\": \"hostil\",\n  \"private\": true,\n"+
			"  \"devDependencies\": { \"eslint\": \"9.9.0\" }\n}\n")
	escribir(t, repo, "app.js", "const x = 1;\n")
	c := exec.Command("npm", "install", "--silent", "--no-audit", "--no-fund")
	c.Dir = repo
	c.Env = sinGOROOT(os.Environ())
	if out, err := c.CombinedOutput(); err != nil {
		t.Skipf("npm install falló (¿sin red?): %v\n%s", err, out)
	}
	git(t, repo, "add", "-A")

	salida, _ := correr(t, bin, repo, "hook", "pre-commit")
	exigirNoTocado(t, "eslint.config.js", vida, salida)
}

func TestAdversarial_MSBuildTargetEjecutable(t *testing.T) {
	if testing.Short() || runtimeNoWindows(t) {
		return
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		t.Skip("sin dotnet: el fixture de MSBuild no aplica")
	}
	bin := construirBinario(t)
	repo := montarRepo(t)
	aLeer, vida := señuelo(t)

	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <Target Name="Hostil" BeforeTargets="Build">
    <ReadLinesFromFile File="` + aLeer + `"><Output TaskParameter="Lines" ItemName="Robado"/></ReadLinesFromFile>
    <WriteLinesToFile File="` + vida + `" Lines="@(Robado)" Overwrite="true"/>
  </Target>
</Project>
`
	escribir(t, repo, "app.csproj", csproj)
	escribir(t, repo, "Program.cs", "class P { static void Main() {} }\n")
	git(t, repo, "add", "-A")

	salida, _ := correr(t, bin, repo, "hook", "pre-commit")
	exigirNoTocado(t, "target MSBuild", vida, salida)
}

func TestAdversarial_MypyPluginEjecutable(t *testing.T) {
	if testing.Short() || runtimeNoWindows(t) {
		return
	}
	if _, err := exec.LookPath("mypy"); err != nil {
		t.Skip("sin mypy: el fixture de plugin no aplica")
	}
	bin := construirBinario(t)
	repo := montarRepo(t)
	aLeer, vida := señuelo(t)

	plugin := "import os\n" +
		"try:\n" +
		"    data = open(r'''" + aLeer + "''').read()\n" +
		"    open(r'''" + vida + "''', 'w').write(data)\n" +
		"except Exception: pass\n" +
		"def plugin(version):\n    from mypy.plugin import Plugin\n    return Plugin\n"
	escribir(t, repo, "cg_plugin.py", plugin)
	escribir(t, repo, "mypy.ini", "[mypy]\nplugins = cg_plugin\n")
	escribir(t, repo, "m.py", "x: int = 1\n")
	git(t, repo, "add", "-A")

	salida, _ := correr(t, bin, repo, "hook", "pre-commit")
	exigirNoTocado(t, "plugin de mypy.ini", vida, salida)
}

func runtimeNoWindows(t *testing.T) bool {
	t.Helper()
	if os.PathSeparator != '\\' {
		t.Skip("CodeGuard solo se distribuye para Windows; el fixture usa rutas y motores de Windows")
		return true
	}
	return false
}
