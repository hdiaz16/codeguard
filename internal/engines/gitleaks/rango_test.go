package gitleaks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
)

// El stub graba su línea de comandos: es la única forma de ver QUÉ argumentos
// recibiría gitleaks de verdad, porque la inyección vive en la construcción de
// la línea de comandos y no en el análisis de la salida.
//
// Y ADEMÁS escribe el --report-path, que es lo que hace gitleaks de verdad
// —también cuando no encuentra nada, medido con 8.30.1 sobre un índice limpio:
// código 0 y `[]` dentro—. Este stub nació sin escribirlo, o sea siendo el
// impostor «sale con 0 y calla» que el motor tomaba por «limpio»; mientras fue
// así, los tres tests del rango legítimo pasaban con el motor sin mirar nada, y
// eso los volvía decorativos precisamente en lo que decían comprobar.
//
// El modo se lee de un archivo junto al ejecutable y NO del entorno: el motor no
// le pasa el entorno heredado (proc.Entorno lo sanea a propósito, que fue el
// arreglo para que la clave del modelo no viajara a procesos de terceros).
const fuenteDelStub = `package main

import (
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		os.Exit(2)
	}
	// Un argumento por línea: ninguno de los que arma el motor lleva saltos.
	if err := os.WriteFile(dir+string(os.PathSeparator)+"argv.txt",
		[]byte(strings.Join(os.Args[1:], "\n")), 0o644); err != nil {
		os.Exit(2)
	}

	modo := "limpio"
	if exe, err := os.Executable(); err == nil {
		if raw, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "modo.txt")); err == nil {
			modo = strings.TrimSpace(string(raw))
		}
	}

	args := os.Args[1:]
	reporte := ""
	for i, a := range args {
		if a == "--report-path" && i+1 < len(args) {
			reporte = args[i+1]
		}
	}

	switch modo {
	case "mudo":
		// La herramienta EQUIVOCADA que cree haber terminado bien: sale con 0 y
		// no escribe reporte. Para el motor tiene que ser una avería, no un
		// "limpio".
		os.Exit(0)
	case "hallazgo":
		if reporte != "" {
			_ = os.WriteFile(reporte, []byte("[{\"RuleID\":\"generic-api-key\","+
				"\"Description\":\"Generic API Key\",\"File\":\"config/prod.yaml\","+
				"\"StartLine\":12,\"EndLine\":12,\"Match\":\"api_key = REDACTED\"}]"), 0o644)
		}
		os.Exit(9)
	default:
		if reporte != "" {
			_ = os.WriteFile(reporte, []byte("[]"), 0o644)
		}
	}
}
`

// stubGitleaks compila el impostor honesto (escanea y no encuentra nada) y
// devuelve su ruta. Se compila de verdad porque en Windows os/exec no puede
// lanzar un .cmd ni un .bat: CreateProcess exige un ejecutable.
func stubGitleaks(t *testing.T) string {
	t.Helper()
	return stubGitleaksModo(t, "limpio")
}

// stubGitleaksModo compila el stub con uno de los tres comportamientos:
// "limpio" (código 0 y reporte `[]`), "mudo" (código 0 y NADA escrito) y
// "hallazgo" (código 9 y un secreto en el reporte).
func stubGitleaksModo(t *testing.T, modo string) string {
	t.Helper()
	dir := t.TempDir()
	escribir := func(nombre, cuerpo string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, nombre), []byte(cuerpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("main.go", fuenteDelStub)
	escribir("go.mod", "module stubgitleaks\n\ngo 1.21\n")
	escribir("modo.txt", modo)

	bin := filepath.Join(dir, "gitleaks-de-mentira.exe")
	c := exec.Command("go", "build", "-o", bin, ".")
	c.Dir = dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo compilar el stub de gitleaks: %v\n%s", err, out)
	}
	return bin
}

// argvRecibido devuelve los argumentos que el stub grabó, y si llegó a correr.
func argvRecibido(t *testing.T, repo string) ([]string, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo, "argv.txt"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(raw), "\n"), true
}

func logOpts(argv []string) string {
	for i, a := range argv {
		if a == "--log-opts" && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// H009: --base y --head llegan de los flags de la CLI (o del workflow de CI) y
// se pegaban tal cual en --log-opts. gitleaks parte ese valor POR ESPACIOS y
// entrega cada trozo a `git log`, así que un base como "--output=..." o
// "main --all" no viaja como el nombre de un commit sino como opciones de git.
// Con eso se puede alterar el rango que se escanea —o desviar la salida— y
// pasar por la etapa 1, que es la única compuerta bloqueante del producto.
func TestRangoNoDejaInyectarOpcionesAGit(t *testing.T) {
	repo := t.TempDir()
	trampa := "--output=" + filepath.Join(t.TempDir(), "desviado.txt")

	e := &Engine{Binary: stubGitleaks(t), Mode: "range", Base: trampa, Head: "HEAD"}
	_, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})

	if argv, corrio := argvRecibido(t, repo); corrio {
		if strings.Contains(logOpts(argv), trampa) {
			t.Errorf("la opción inyectada llegó a git log en --log-opts: %q", logOpts(argv))
		}
	}
	if err == nil {
		t.Fatal("un rango con una opción inyectada debe rechazarse, no escanearse")
	}
	// Fail-closed: la etapa de secretos bloquea sólo por ErrUnavailable (§14),
	// así que un rango inválido tiene que llegar envuelto en él o el pipeline
	// lo trataría como un error cualquiera.
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("el rechazo debe envolver ErrUnavailable para que la compuerta bloquee: %v", err)
	}
}

// El mismo agujero por el lado del head: validar sólo la base dejaría la mitad
// de la puerta abierta.
func TestHeadTampocoPuedeInyectar(t *testing.T) {
	repo := t.TempDir()

	e := &Engine{Binary: stubGitleaks(t), Mode: "range", Base: "main", Head: "HEAD --all"}
	_, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})

	if argv, corrio := argvRecibido(t, repo); corrio {
		if strings.Contains(logOpts(argv), "--all") {
			t.Errorf("la opción inyectada por el head llegó a git log: %q", logOpts(argv))
		}
	}
	if err == nil {
		t.Fatal("un head con espacios y opciones debe rechazarse")
	}
}

// La contraparte imprescindible: el flujo normal tiene que seguir llegando a
// gitleaks con su rango intacto. Sin esta prueba, un motor que rechazara TODO
// dejaría pasar las dos de arriba sin escanear nada.
func TestRangoLegitimoLlegaAGitleaks(t *testing.T) {
	bin := stubGitleaks(t)
	casos := []struct{ base, head string }{
		{"main", "HEAD"},
		{"9f2c1ab", "3e7d5c9f2c1ab4d6e8a0b2c4d6e8f0a2b4c6d8e0"},
		{"release/2026.08", "feature/H009-inyeccion"},
		// Con acento: el primer arreglo bloqueaba el commit aquí sin ejecutar
		// un solo motor, y gitleaks 8.30.0 escanea este rango sin problema.
		{"main", "corrección-h009"},
		{"release/2026.08", "feature/validación"},
	}
	for _, c := range casos {
		repo := t.TempDir()
		e := &Engine{Binary: bin, Mode: "range", Base: c.base, Head: c.head}
		if _, err := e.Run(context.Background(), engines.Input{RepoRoot: repo}); err != nil {
			t.Fatalf("el rango legítimo %s..%s debió correr: %v", c.base, c.head, err)
		}
		argv, corrio := argvRecibido(t, repo)
		if !corrio {
			t.Fatalf("gitleaks no se invocó para el rango legítimo %s..%s", c.base, c.head)
		}
		if got, want := logOpts(argv), c.base+".."+c.head; got != want {
			t.Errorf("--log-opts = %q, se esperaba %q", got, want)
		}
	}
}

// La tabla de qué referencias valen y cuáles no vive en internal/gitref, que es
// donde está el criterio y donde lo comparten este motor y gitdiff. Aquí se
// prueba lo que es de este paquete: que el rechazo llegue envuelto en
// ErrUnavailable —sin eso el pipeline no bloquea— y que la línea de comandos
// que se le arma a gitleaks sea la que debe ser.
func TestElRechazoLlegaEnvueltoEnErrUnavailable(t *testing.T) {
	e := &Engine{Mode: "range", Base: "--output=/tmp/x", Head: "HEAD"}
	_, err := e.rango()
	if err == nil {
		t.Fatal("una base inyectada debe rechazarse")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("sin ErrUnavailable la compuerta no bloquea (§14): %v", err)
	}
	// Y el motivo de gitref tiene que sobrevivir al envoltorio: si se pierde,
	// el usuario lee "gitleaks no disponible" y no sabe que el culpable es su
	// propio flag.
	if !strings.Contains(err.Error(), "--base") {
		t.Errorf("el envoltorio se comió el motivo: %v", err)
	}
}

// Con el gitleaks de verdad: el rango de los dos últimos commits de este mismo
// repo tiene que escanearse sin error. El stub prueba QUÉ argumentos se arman;
// esto prueba que gitleaks los acepta — que la validación no rompió el modo ci.
func TestRangoRealContraEsteRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: ejecuta el gitleaks real")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks no está en PATH")
	}
	raiz, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("no se encuentra la raíz del repo: %v", err)
	}
	repo := strings.TrimSpace(string(raiz))
	base, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD~1").Output()
	if err != nil {
		t.Skipf("no hay historial suficiente: %v", err)
	}

	e := &Engine{Mode: "range", Base: strings.TrimSpace(string(base)), Head: "HEAD"}
	if _, err := e.Run(context.Background(), engines.Input{RepoRoot: repo}); err != nil {
		t.Fatalf("el modo ci debe seguir corriendo con refs legítimas: %v", err)
	}
}
