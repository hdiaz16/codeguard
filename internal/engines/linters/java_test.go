package linters

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// Pruebas de las piezas que comparten javafmt y javalint. Si el descubrimiento
// de proyectos se rompe, los dos motores se rompen a la vez y de la misma
// forma: por eso vive y se prueba en un solo sitio.

func archivosJava(rutas ...string) []gitdiff.ChangedFile {
	out := make([]gitdiff.ChangedFile, 0, len(rutas))
	for _, r := range rutas {
		out = append(out, gitdiff.ChangedFile{Path: r, Status: "M", SHA256: "sha-" + r})
	}
	return out
}

func escribir(t *testing.T, raiz, rel, contenido string) {
	t.Helper()
	abs := filepath.Join(raiz, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}

// El caso que motiva todo el descubrimiento: el monorepo corporativo, con el
// pom.xml en backend/ y NADA en la raíz. Mirar sólo la raíz dejaría los dos
// motores enrolados sin correr jamás.
func TestProyectosJavaEncuentraElManifiestoEnUnMonorepo(t *testing.T) {
	raiz := t.TempDir()
	escribir(t, raiz, "backend/pom.xml", "<project/>")
	escribir(t, raiz, "backend/src/main/java/com/ejemplo/A.java", "class A {}")
	escribir(t, raiz, "frontend/src/B.java", "class B {}")

	proys := proyectosJava(engines.Input{
		RepoRoot: raiz,
		Files: archivosJava(
			"backend/src/main/java/com/ejemplo/A.java",
			"frontend/src/B.java",
		),
	})
	if len(proys) != 2 {
		t.Fatalf("esperaba 2 proyectos (backend y la raíz), obtuve %d: %+v", len(proys), proys)
	}
	// Orden estable y alfabético: "." antes que "backend".
	if proys[0].dir != "." || proys[1].dir != "backend" {
		t.Fatalf("dirs = %q y %q; esperaba \".\" y \"backend\"", proys[0].dir, proys[1].dir)
	}
	if len(proys[0].archivos) != 1 || proys[0].archivos[0].Path != "frontend/src/B.java" {
		t.Errorf("el archivo sin manifiesto encima debe caer a la raíz: %+v", proys[0].archivos)
	}
	if len(proys[1].archivos) != 1 {
		t.Errorf("backend debe llevarse su archivo: %+v", proys[1].archivos)
	}
}

// Gradle cuenta igual que Maven, y también su variante Kotlin: un repo que sólo
// tiene build.gradle.kts no puede quedarse sin compuerta.
func TestProyectosJavaReconoceGradle(t *testing.T) {
	for _, manifiesto := range []string{"build.gradle", "build.gradle.kts"} {
		raiz := t.TempDir()
		escribir(t, raiz, "app/"+manifiesto, "plugins { id 'java' }")
		escribir(t, raiz, "app/src/main/java/A.java", "class A {}")

		proys := proyectosJava(engines.Input{RepoRoot: raiz, Files: archivosJava("app/src/main/java/A.java")})
		if len(proys) != 1 || proys[0].dir != "app" {
			t.Errorf("%s: esperaba el proyecto en app/, obtuve %+v", manifiesto, proys)
		}
	}
}

// Sin ningún manifiesto el archivo NO queda fuera: cae a la raíz. Es la
// diferencia deliberada con eslint, que sí exige configuración del repo.
func TestProyectosJavaSinManifiestoCaeALaRaiz(t *testing.T) {
	raiz := t.TempDir()
	escribir(t, raiz, "src/A.java", "class A {}")

	proys := proyectosJava(engines.Input{RepoRoot: raiz, Files: archivosJava("src/A.java")})
	if len(proys) != 1 || proys[0].dir != "." {
		t.Fatalf("esperaba un proyecto en la raíz, obtuve %+v", proys)
	}
}

func TestProyectosJavaIgnoraBorradosYNoJava(t *testing.T) {
	raiz := t.TempDir()
	files := []gitdiff.ChangedFile{
		{Path: "src/Borrado.java", Status: "D"},
		{Path: "src/App.kt", Status: "M"},
		{Path: "README.md", Status: "A"},
	}
	if proys := proyectosJava(engines.Input{RepoRoot: raiz, Files: files}); len(proys) != 0 {
		t.Fatalf("sin .java vivos no debe haber proyectos, hubo %+v", proys)
	}
}

// La salida de compilación no es código del equipo: bloquear un commit porque
// un generador no formatea como google-java-format sería pedirle al dev que
// arregle algo que no escribió. Pero un PAQUETE llamado build sí es suyo.
func TestEsJavaGeneradoDistingueSalidaDePaquete(t *testing.T) {
	casos := map[string]bool{
		"backend/target/generated-sources/jaxb/com/x/Tipo.java":    true,
		"app/build/generated/source/buildConfig/Config.java":       true,
		"modulo/out/production/clases/A.java":                      true,
		"backend/src/main/java/com/ejemplo/build/Constructor.java": false,
		"backend/src/main/java/com/ejemplo/target/Objetivo.java":   false,
		"src/main/java/A.java":                                     false,
	}
	for ruta, esperado := range casos {
		if got := esJavaGenerado(ruta); got != esperado {
			t.Errorf("esJavaGenerado(%q) = %v, esperaba %v", ruta, got, esperado)
		}
	}
}

// Comparar versiones como texto daría 1.9.0 > 1.36.1, y durante una
// actualización —cuando conviven dos— eso elegiría la vieja y las claves de
// caché apuntarían a la herramienta equivocada.
func TestMasNuevaJavaComparaNumerosNoTexto(t *testing.T) {
	casos := []struct {
		a, b string
		mas  bool
	}{
		{"1.36.1", "1.9.0", true},
		{"1.9.0", "1.36.1", false},
		{"7.26.0", "7.7.0", true},
		{"7.26.0", "7.26.0", false},
		{"7.26.1", "7.26.0", true},
		{"8.0", "7.26.0", true},
	}
	for _, c := range casos {
		if got := masNuevaJava(c.a, c.b); got != c.mas {
			t.Errorf("masNuevaJava(%q, %q) = %v, esperaba %v", c.a, c.b, got, c.mas)
		}
	}
}

func TestHerramientaJavaEligeLaVersionMasNueva(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	dir := filepath.Join(base, "CodeGuard", "engines")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.9.0", "1.36.1"} {
		if err := os.WriteFile(filepath.Join(dir, "google-java-format-"+v+"-all-deps.jar"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ruta, version, err := herramientaJava(jarGJFPatron, jarGJFPrefijo, jarGJFSufijo)
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.36.1" {
		t.Errorf("version = %q, esperaba 1.36.1 (la más nueva, no la última alfabéticamente)", version)
	}
	if filepath.Base(ruta) != "google-java-format-1.36.1-all-deps.jar" {
		t.Errorf("ruta = %q", ruta)
	}
}

// Una herramienta sin instalar es CONFIGURACIÓN, no una avería del análisis: el
// error tiene que llevar fs.ErrNotExist dentro para que pipeline.isMissingBinary
// lo etiquete "falta: pmd" y no pinte de naranja un commit sano.
func TestHerramientaJavaAusenteEsMotorAusente(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	_, _, err := herramientaJava(pmdHomePatron, pmdHomePrefijo, pmdHomeSufijo)
	if err == nil {
		t.Fatal("sin instalar debe devolver error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("el error debe envolver fs.ErrNotExist para que el orquestador diga \"falta:\"; es %v", err)
	}
}

func TestRutaRepoJavaNormalizaRelativasYAbsolutas(t *testing.T) {
	raiz := `C:\repos\demo`
	casos := []struct {
		dir, entrada, esperado string
	}{
		// El caso normal: las dos herramientas devuelven la ruta tal como se la
		// dieron, pero con la barra invertida de Windows.
		{"backend", `src\main\java\A.java`, "backend/src/main/java/A.java"},
		{".", `src\A.java`, "src/A.java"},
		// Rama defensiva: absoluta dentro del repo, comparando sin distinguir
		// mayúsculas como comparan los paths de Windows.
		{"backend", `C:\REPOS\demo\backend\src\A.java`, "backend/src/A.java"},
		// Fuera del repo: mejor la ruta cruda que una mentira.
		{".", `D:\otro\A.java`, "D:/otro/A.java"},
		{".", "", ""},
	}
	for _, c := range casos {
		if got := rutaRepoJava(raiz, c.dir, c.entrada); got != c.esperado {
			t.Errorf("rutaRepoJava(%q, %q) = %q, esperaba %q", c.dir, c.entrada, got, c.esperado)
		}
	}
}

// Textos REALES del lanzador de Java (JDK 21.0.12, medidos): son los que hay
// que separar del "salí con 1 porque encontré algo".
func TestJErrorDeJVMSeparaElLanzadorDeLosDiagnosticos(t *testing.T) {
	lanzador := []string{
		"Error: Unable to access jarfile C:/Users/x/noexiste.jar\n",
		"Error: Could not find or load main class NoExisteClase\nCaused by: java.lang.ClassNotFoundException: NoExisteClase\n",
		"Error: Invalid or corrupt jarfile C:/Users/x/malo.jar\n",
		"Exception in thread \"main\" java.lang.OutOfMemoryError: Java heap space\n",
	}
	for _, s := range lanzador {
		if jErrorDeJVM([]byte(s)) == "" {
			t.Errorf("debía reconocerse como fallo de la JVM: %q", s)
		}
	}
	// Diagnósticos por archivo de las dos herramientas: NO son fallos de la JVM.
	// Confundirlos degradaría el motor entero por un archivo con un paréntesis
	// de más.
	porArchivo := []string{
		"Roto.java:4:17: error: illegal start of type\n  public int x( {\n                ^\n",
		"NoExiste.java: could not read file: NoExiste.java\n",
		"[main] ERROR net.sourceforge.pmd.cli - No such file NoExiste.java\n",
		"[main] WARN net.sourceforge.pmd.cli - This analysis could be faster\n",
		"",
	}
	for _, s := range porArchivo {
		if got := jErrorDeJVM([]byte(s)); got != "" {
			t.Errorf("no es fallo de la JVM y se reconoció como tal (%q): %q", got, s)
		}
	}
}
