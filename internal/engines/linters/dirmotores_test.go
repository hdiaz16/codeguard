package linters

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
)

// N001: el repositorio que se está analizando NO puede elegir el binario que
// ejecutamos.
//
// dirMotores componía la ruta con filepath.Join sobre LOCALAPPDATA sin
// comprobar nada. Con esa variable vacía el Join no falla: devuelve
// `CodeGuard\engines`, que es RELATIVA, y relativa significa relativa al
// directorio de trabajo — que durante un commit es el repo que se analiza.
//
// A partir de ahí la cadena está toda escrita y funciona sola: herramientaJava
// hace filepath.Glob sobre ese directorio, se queda con la versión MÁS ALTA
// (masNuevaJava), y javafmt.go se la pasa a `java -jar`. Basta con que el repo
// traiga un jar con una versión absurda para ganar siempre.
const jarPlantadoPorElRepo = "google-java-format-99.0.0-all-deps.jar"

// repoConMotorPlantado deja un repo con el directorio de motores DENTRO, que es
// exactamente donde aterriza la ruta relativa, y con un .java que hace que el
// motor se active.
func repoConMotorPlantado(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	escribir(t, repo, "CodeGuard/engines/"+jarPlantadoPorElRepo, "esto no es un jar, pero el Glob no lo sabe")
	escribir(t, repo, "src/A.java", fuenteJavaLimpio)
	return repo
}

// Lo que se afirma aquí: la ruta que devuelve herramientaJava es EXACTAMENTE la
// que se le pasa a `java -jar` en javafmt.go. Si la eligió el repo analizado,
// el repo analizado decide qué código ejecutamos.
func TestUnRepoAjenoNoPuedeElegirElJarQueEjecutamos(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	repo := repoConMotorPlantado(t)
	t.Chdir(repo)

	jar, version, err := herramientaJava(jarGJFPatron, jarGJFPrefijo, jarGJFSufijo)
	if err == nil {
		abs, _ := filepath.Abs(jar)
		t.Fatalf("el repo analizado eligió el binario que vamos a ejecutar:\n"+
			"  java -jar %s\n  (versión que se cree instalada: %s)", abs, version)
	}
	if jar != "" {
		t.Errorf("con error no puede salir además una ruta: %q", jar)
	}
	// Sin directorio de motores resoluble la verdad es "la herramienta no está
	// instalada", y ese camino ya existe y está bien hecho: el orquestador lo
	// etiqueta "falta:" en vez de tratarlo como análisis degradado.
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("el error debía ser reconocible como herramienta ausente, y fue: %v", err)
	}
}

// PMD por el mismo camino, y peor: no se ejecuta un jar suelto sino que el
// directorio del repo entero entra en el classpath (`java -cp <home>\lib\*`).
func TestUnRepoAjenoNoPuedeElegirElClasspathDePMD(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	repo := t.TempDir()
	escribir(t, repo, "CodeGuard/engines/pmd-bin-99.0.0/lib/plantado.jar", "x")
	t.Chdir(repo)

	home, _, err := herramientaJava(pmdHomePatron, pmdHomePrefijo, pmdHomeSufijo)
	if err == nil {
		abs, _ := filepath.Abs(home)
		t.Fatalf("el repo analizado eligió el classpath de PMD:\n  java -cp %s ...",
			filepath.Join(abs, "lib", "*"))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("el error debía ser reconocible como herramienta ausente, y fue: %v", err)
	}
}

// La variante que sobrevive a un arreglo a medias, y por eso está aquí: si sólo
// se corrige dirMotores para que devuelva "", filepath.Join("", patrón) NO da
// una ruta vacía — deja el patrón suelto, y Glob lo resuelve igual contra el
// directorio de trabajo. Al repo le basta con plantar el jar en su RAÍZ en vez
// de en CodeGuard\engines. Quien busca tiene que negarse a buscar sin un
// directorio absoluto; no vale con que se lo den vacío.
func TestUnRepoAjenoTampocoPlantandoElJarEnSuRaiz(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	repo := t.TempDir()
	escribir(t, repo, jarPlantadoPorElRepo, "esto no es un jar, pero el Glob no lo sabe")
	t.Chdir(repo)

	jar, _, err := herramientaJava(jarGJFPatron, jarGJFPrefijo, jarGJFSufijo)
	if err == nil {
		abs, _ := filepath.Abs(jar)
		t.Fatalf("el repo colocó el binario en su raíz y lo elegimos igual:\n  java -jar %s", abs)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("el error debía ser reconocible como herramienta ausente, y fue: %v", err)
	}
}

// El directorio de motores es absoluto o no es. Una ruta relativa apunta a
// donde sea que esté el directorio de trabajo, y de ahí sale un binario.
func TestDirMotoresNuncaEsRelativo(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
		quieroVacio  bool
	}{
		{"variable ausente", "", true},
		{"variable en blanco", "   ", true},
		{"valor relativo puesto a mano", `datos\local`, true},
		{"valor absoluto normal", `C:\Users\quien\AppData\Local`, false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", c.localappdata)
			got := dirMotores()
			if c.quieroVacio {
				if got != "" {
					t.Errorf("LOCALAPPDATA=%q debía dar \"\" y dio %q", c.localappdata, got)
				}
				return
			}
			if !filepath.IsAbs(got) {
				t.Errorf("dirMotores devolvió una ruta relativa: %q", got)
			}
		})
	}
}

// ── la prueba de que se EJECUTA, no de que se elige ──────────────────────────

// fuenteJavaFalso es un `java` de mentira que apunta con qué argumentos lo
// llamaron y sale con 0. Escribe junto a su propio ejecutable y no por una
// variable de entorno a propósito: el entorno de los motores va filtrado por
// lista blanca (proc.Entorno), así que una variable de prueba no llegaría.
const fuenteJavaFalso = `package main

import (
	"os"
	"path/filepath"
	"strings"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(3)
	}
	_ = os.WriteFile(filepath.Join(filepath.Dir(exe), "argv.txt"),
		[]byte(strings.Join(os.Args[1:], "\n")), 0o644)
}
`

// javaFalsoEnElPath compila el java de mentira, lo pone PRIMERO en el PATH y
// devuelve la ruta del archivo donde dejará sus argumentos.
func javaFalsoEnElPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	escribir(t, dir, "go.mod", "module javafalso\n\ngo 1.21\n")
	escribir(t, dir, "main.go", fuenteJavaFalso)

	exe := filepath.Join(dir, "java.exe")
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo compilar el java falso: %v\n%s", err, out)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return filepath.Join(dir, "argv.txt")
}

// La prueba que cierra el hallazgo: no que el jar del repo se ELIJA, sino que
// llegue de verdad a la línea de órdenes de java.
func TestUnRepoAjenoNoLlegaAEjecutarSuJar(t *testing.T) {
	argv := javaFalsoEnElPath(t)
	t.Setenv("LOCALAPPDATA", "")
	repo := repoConMotorPlantado(t)
	t.Chdir(repo)

	_, err := JavaFmt{}.Run(context.Background(),
		engines.Input{RepoRoot: repo, Files: archivosJava("src/A.java")})

	registrado, errLectura := os.ReadFile(argv)
	if errLectura == nil && strings.Contains(string(registrado), jarPlantadoPorElRepo) {
		t.Fatalf("SE EJECUTÓ el binario que puso el repo analizado.\n"+
			"java recibió:\n%s", registrado)
	}
	if errLectura == nil {
		t.Errorf("se ejecutó java sin que hubiera herramienta instalada; recibió:\n%s", registrado)
	}
	// Y el motor tiene que decir la verdad: la herramienta no está.
	if err == nil {
		t.Error("sin motores resolubles el motor no puede devolver 'todo limpio'")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("el error debía ser reconocible como herramienta ausente, y fue: %v", err)
	}
}
