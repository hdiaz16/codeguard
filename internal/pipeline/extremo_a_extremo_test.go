package pipeline_test

// Verificación de extremo a extremo del sistema completo.
//
// Responde a "¿está todo cableado de verdad?", y la única respuesta honesta a
// esa pregunta se obtiene EJECUTANDO. Este proyecto lleva un mes encontrando
// compuertas que existían, compilaban, tenían comentarios y no revisaban nada:
// la auditoría de la cadena firmando "limpio" con el subcomando equivocado de
// trivy, tsc enrolado sin correr jamás en monorepos, PMD escribiendo files:[]
// ante un archivo inexistente, el informe declarando COMPLETADO con las reglas
// de la casa sin aplicar. Ninguna se ve leyendo el código; todas se ven
// midiendo.
//
// Monta un repositorio de verdad con una violación DELIBERADA por motor, corre
// el BINARIO REAL —el gancho y el informe, como los corre una persona— y
// comprueba motor por motor que cada uno vio lo suyo.
//
// POR QUÉ EL BINARIO Y NO EL PIPELINE EN PROCESO. La primera versión de este
// archivo llamaba a pipeline.Run() directamente y dio TRES falsos negativos que
// el binario real no tiene: govet y staticcheck fallaban con «version
// "go1.26.5" does not match go tool version "go1.26.3"» porque `go test` impone
// variables de entorno que heredaban los motores, y gitleaks no veía el secreto
// porque el repo de prueba no tenía commit inicial y el modo `staged` compara
// contra HEAD. Tres motores marcados como rotos, y los tres sanos.
//
// Un arnés que produce falsos negativos es peor que no tenerlo: enseña a
// desconfiar de la alarma. Así que el arnés también hay que verificarlo, y la
// forma de hacerlo es conducir exactamente lo que conduce una persona.
//
// Cuatro estados, porque confundirlos ES el fallo que persigue:
//
//	CAZÓ        corrió y encontró lo que debía
//	NO APLICA   decidió no correr, con motivo (sin JDK, sin config del repo)
//	NO CAZÓ     corrió y NO encontró su violación  ← el peligroso
//	DEGRADADO   falló o no cupo en el plazo

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// violacion es qué se le pone delante a un motor y qué debe responder.
type violacion struct {
	motor     string // el nombre con el que el motor se anuncia en el log
	archivo   string
	contenido string
	porQue    string // para que un fallo diga algo útil, no "esperaba 1, hubo 0"
	// requiere: dependencia externa. Si falta, el motor NO APLICA — y eso no es
	// un fallo, pero se reporta. Nunca se calla.
	requiere string
}

// elSecreto va aparte: bloquea la etapa 1 y con él dentro no corre nada más,
// así que se prueba en su propia fase.
const elSecreto = "# fixture de verificación — token inventado, no es una credencial real\n" +
	"GITHUB_TOKEN = \"ghp_0Nn8Qk2Xv7Lm4Rt9Yb3Wc6Zd1Ae5Gf7Hj0K\"\n"

func violaciones() []violacion {
	return []violacion{
		{
			motor:   "semgrep",
			archivo: "app/inseguro.py",
			contenido: "import subprocess\n\n\n" +
				"def ejecutar(orden):\n" +
				"    return subprocess.run(orden, shell=True)\n",
			porQue: "reglas de la casa: subprocess con shell=True (CWE-78)",
		},
		{
			motor:   "gofmt",
			archivo: "malformato.go",
			contenido: "package fixture\n\nfunc Mal( ) int {\n" +
				"\t\t\tx :=1\n  return x\n}\n",
			porQue: "formato de Go deliberadamente roto",
		},
		{
			motor:   "govet",
			archivo: "vet.go",
			contenido: "package fixture\n\nimport \"fmt\"\n\n" +
				"func Vet() string {\n\treturn fmt.Sprintf(\"%d %d\", 1)\n}\n",
			porQue: "govet: Sprintf con menos argumentos que verbos",
		},
		{
			motor:   "staticcheck",
			archivo: "muerto.go",
			contenido: "package fixture\n\nimport \"strings\"\n\n" +
				"func Muerto(s string) string {\n" +
				"\treturn strings.Replace(s, \"a\", \"b\", -1)\n}\n",
			porQue: "staticcheck: strings.Replace con -1 debe ser ReplaceAll",
		},
		{
			motor:     "ruff",
			archivo:   "app/estilo.py",
			contenido: "import os\nimport sys\n\n\ndef sin_usar():\n    x = 1\n    return 2\n",
			porQue:    "ruff: imports y variable sin usar",
		},
		{
			motor:     "squawk",
			archivo:   "migrations/001_riesgosa.sql",
			contenido: "ALTER TABLE usuarios ADD COLUMN correo text NOT NULL;\n",
			porQue:    "squawk: NOT NULL sin default bloquea la tabla",
		},
		{
			motor:   "google-java-format",
			archivo: "src/Malformato.java",
			contenido: "public class Malformato {\n" +
				"public static void main(String[] args){\n" +
				"System.out.println(   \"hola\"   );\n}\n}\n",
			porQue:   "google-java-format: llaves y sangría fuera de estilo",
			requiere: "JDK + google-java-format instalados",
		},
		{
			motor:   "pmd",
			archivo: "src/Calidad.java",
			contenido: "public class Calidad {\n    public void m() {\n" +
				"        int noSeUsa = 5;\n    }\n}\n",
			porQue:   "PMD: variable local asignada y nunca usada",
			requiere: "JDK + PMD instalados",
		},
		{
			motor:   "mypy",
			archivo: "app/tipos.py",
			contenido: "def suma(a: int, b: int) -> int:\n" +
				"    return a + b\n\n\n" +
				"resultado: str = suma(1, 2)\n",
			porQue:   "mypy: int asignado a str, con mypy.ini presente en el repo",
			requiere: "mypy instalado Y configurado por el repo",
		},
		{
			motor:     "dotnet-format",
			archivo:   "src/Malformato.cs",
			contenido: "public class Malformato{\npublic void M(){\nint x=1;\n}\n}\n",
			porQue:    "dotnet format: estilo deliberadamente roto",
			// Medido: el SDK está instalado y aun así no aplica. `dotnet format`
			// necesita un proyecto o solución — no analiza .cs sueltos. La
			// etiqueta decía "requiere SDK de .NET" y era inexacta: mandaba a
			// instalar algo que ya estaba.
			requiere: "un .csproj (dotnet format no analiza .cs sueltos)",
		},
	}
}

// Los motores que el arnés todavía no sabe provocar. Se nombran a propósito:
// un motor que nadie prueba y que además nadie MENCIONA desaparece del informe,
// y entonces "todo verde" significa menos de lo que parece.
var sinPruebaTodavia = map[string]string{
	"trivy":        "necesita un manifiesto con dependencias vulnerables reales",
	"govulncheck":  "necesita un go.sum con una vulnerabilidad alcanzable",
	"tsc":          "necesita un proyecto TypeScript con tsconfig",
	"eslint":       "sólo aplica si el repo configura eslint o biome",
	"dotnet-build": "necesita un .csproj restaurable",
	"dotnet-vuln":  "necesita packages.lock.json con un CVE",
}

var (
	reLinea     = regexp.MustCompile(`([a-z0-9\-]+): (\d+) hallazgo\(s\)`)
	reDegradado = regexp.MustCompile(`([a-z0-9\-]+) (?:degradado|no cupo en el plazo)`)
)

func TestElSistemaCompletoEstaCableado(t *testing.T) {
	if testing.Short() {
		t.Skip("compila el binario y corre todos los motores contra un repo real")
	}
	if runtime.GOOS != "windows" {
		t.Skip("CodeGuard sólo se distribuye para Windows")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("sin git no hay nada que analizar")
	}

	bin := construirBinario(t)
	repo := montarRepo(t)

	// ── Fase 1: la compuerta de secretos, la única fail-closed ───────────
	escribir(t, repo, "secreto.py", elSecreto)
	git(t, repo, "add", "-A")

	salida, codigo := correr(t, bin, repo, "hook", "pre-commit")
	if codigo == 0 {
		t.Errorf("el gancho DEJÓ PASAR un commit con un secreto dentro.\n%s", salida)
	}
	if !strings.Contains(salida, "secreto") {
		t.Errorf("bloqueó, pero no por el secreto — el motivo importa:\n%s", salida)
	} else {
		t.Log("  ✓ etapa 1 (secretos, fail-closed): bloquea y dice por qué")
	}
	if !strings.Contains(salida, "NADA salió a la red") {
		t.Error("el bloqueo por secreto no confirma que nada salió a la red")
	}

	// ── Fase 2: el resto de motores, ya sin el secreto delante ───────────
	if err := os.Remove(filepath.Join(repo, "secreto.py")); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "-A")

	salida, _ = correr(t, bin, repo, "report", "--avisos")
	informe(t, salida)
}

func informe(t *testing.T, salida string) {
	t.Helper()

	hallazgos := map[string]int{}
	for _, m := range reLinea.FindAllStringSubmatch(salida, -1) {
		n, _ := strconv.Atoi(m[2])
		hallazgos[m[1]] += n
	}
	degradados := map[string]bool{}
	for _, m := range reDegradado.FindAllStringSubmatch(salida, -1) {
		degradados[m[1]] = true
	}
	if len(hallazgos) == 0 && len(degradados) == 0 {
		t.Fatalf("ningún motor se anunció en la salida: el arnés no mide nada.\n%s", salida)
	}

	esperados := map[string]violacion{}
	var nombres []string
	for _, v := range violaciones() {
		esperados[v.motor] = v
		nombres = append(nombres, v.motor)
	}
	for n := range sinPruebaTodavia {
		nombres = append(nombres, n)
	}
	sort.Strings(nombres)

	var noCazaron []string
	t.Log("")
	t.Log("  MOTOR                ESTADO      HALLAZGOS  DETALLE")
	t.Log("  -------------------- ----------- ---------  ------------------------------------")
	for _, n := range nombres {
		v, esperado := esperados[n]
		switch {
		case degradados[n]:
			t.Logf("  %-20s DEGRADADO   %9d  no llegó a revisar", n, hallazgos[n])
		case !esperado:
			t.Logf("  %-20s SIN PRUEBA  %9d  %s", n, hallazgos[n], sinPruebaTodavia[n])
		case hallazgos[n] > 0:
			t.Logf("  %-20s CAZÓ        %9d  %s", n, hallazgos[n], v.porQue)
		case v.requiere != "":
			t.Logf("  %-20s NO APLICA   %9d  requiere: %s", n, hallazgos[n], v.requiere)
		default:
			t.Logf("  %-20s ¡NO CAZÓ!   %9d  %s", n, hallazgos[n], v.porQue)
			noCazaron = append(noCazaron, n)
		}
	}
	t.Log("")

	if len(noCazaron) > 0 {
		t.Errorf("estos motores corrieron sin ver la violación que tenían delante: %v.\n"+
			"Un motor que no ve lo que se le pone delante es indistinguible de uno sano "+
			"mientras el repositorio esté limpio, que es el 99%% del tiempo.", noCazaron)
	}
}

// ── andamiaje ────────────────────────────────────────────────────────────

func construirBinario(t *testing.T) string {
	t.Helper()
	// Se llama codeguard.exe y no codeguard-e2e.exe a propósito: `codeguard
	// install` deja en .githooks shims que resuelven el binario como
	// <codeguard.binpath>\codeguard.exe. Con otro nombre, los ganchos
	// instalados apuntan a un archivo que no existe y el commit falla con un
	// "No such file or directory" que no tiene nada que ver con lo que se
	// estaba probando.
	bin := filepath.Join(t.TempDir(), "codeguard.exe")
	c := exec.Command("go", "build", "-o", bin, "./cmd/codeguard")
	c.Dir = raizDelRepo(t)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo construir el binario: %v\n%s", err, out)
	}
	return bin
}

func raizDelRepo(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("no se encuentra la raíz del repo de CodeGuard: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// montarRepo deja un repo CON HISTORIA y las violaciones en el índice.
//
// El commit inicial no es un detalle: el modo `staged` de gitleaks compara
// contra HEAD, y sin HEAD no hay nada que comparar. La primera versión de este
// arnés no lo tenía y concluyó que la compuerta de secretos estaba rota.
func montarRepo(t *testing.T) string {
	t.Helper()
	repo := repoBase(t)
	for _, v := range violaciones() {
		escribir(t, repo, v.archivo, v.contenido)
	}
	git(t, repo, "add", "-A")
	return repo
}

// repoBase deja un repo enrolado, con historia y SIN violaciones. Lo comparten
// el arnés de motores y las pruebas de invariantes, que necesitan el mismo
// punto de partida pero cargan cosas distintas encima.
func repoBase(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	for _, o := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "e2e@ejemplo.local"},
		{"config", "user.name", "Verificación"},
		{"config", "commit.gpgsign", "false"},
	} {
		git(t, repo, o...)
	}
	escribir(t, repo, "LEEME.md", "repositorio de verificación\n")
	escribir(t, repo, "go.mod", "module fixture\n\ngo 1.24\n")
	// mypy sólo aplica si el REPO lo configuró: es la regla del motor, y sin
	// este archivo la casilla saldría "no aplica" sin haber probado nada.
	escribir(t, repo, "mypy.ini", "[mypy]\nwarn_unused_ignores = True\n")
	escribir(t, repo, ".codeguard/config.yaml",
		"version: 1\nrulepack: \"2026.08.2\"\nmax_diff_lines: 5000\n"+
			"paths:\n  migrations: [\"migrations/*.sql\"]\n  migrations_dialect: postgres\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "base", "--no-verify")
	return repo
}

func escribir(t *testing.T, repo, rel, contenido string) {
	t.Helper()
	ruta := filepath.Join(repo, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, repo string, args ...string) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = repo
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// correr invoca el binario tal cual lo invoca una persona, y devuelve TODO lo
// que escribió: el informe por motor viaja por stderr.
//
// El entorno se limpia de GOROOT, y eso NO es cosmético. Medido: dentro de `go
// test` el proceso tiene GOROOT apuntando al toolchain del module cache
// (`...\pkg\mod\golang.org\toolchain@v0.0.1-go1.26.5...`), mientras que la
// shell de una persona no tiene NINGUNA variable GO*. proc.Entorno() permite
// GOROOT —hace falta en máquinas donde el toolchain no está en el PATH—, así
// que se la pasaba a los motores, y govet devolvía 0 hallazgos y staticcheck
// se degradaba con «version "go1.26.5" does not match go tool version
// "go1.26.3"». Dos motores sanos marcados como rotos por el entorno del que
// mide.
//
// Vale la pena dejar dicho lo que esto implica FUERA de la prueba: un
// desarrollador con un GOROOT viejo exportado tendría el mismo síntoma en
// silencio. No se cambia el permitido —quitarlo rompería a quien lo necesita—
// pero está anotado en el plan como algo a vigilar.
func correr(t *testing.T, bin, repo string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Dir = repo
	// CODEGUARD_PIPE apuntando a un pipe que no existe fuerza al gancho a
	// analizar EN ESTE PROCESO en vez de delegar en el daemon.
	//
	// Sin esto, `hook pre-commit` hablaba por IPC con el daemon INSTALADO en la
	// máquina —un binario de otra versión— y la prueba creía estar midiendo el
	// que acababa de compilar. Se descubrió persiguiendo un fallo de baseline
	// que resultó ser código viejo respondiendo. Medir el binario equivocado y
	// no enterarse es la peor variante del problema que este arnés persigue:
	// no es que la compuerta no revise, es que revisa OTRA COSA.
	c.Env = append(sinGOROOT(os.Environ()),
		`CODEGUARD_PIPE=\\.\pipe\codeguard-verificacion-sin-daemon`)
	out, err := c.CombinedOutput()
	codigo := 0
	if ee, ok := err.(*exec.ExitError); ok {
		codigo = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("no se pudo ejecutar %s %v: %v", bin, args, err)
	}
	return string(out), codigo
}

// sinGOROOT deja el entorno como el de una terminal recién abierta.
func sinGOROOT(entorno []string) []string {
	out := make([]string, 0, len(entorno))
	for _, e := range entorno {
		if strings.HasPrefix(strings.ToUpper(e), "GOROOT=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// correrCon es `correr` con el directorio de datos aislado: la base local, el
// caché y todo lo que CodeGuard guarda por máquina van a un sitio de la prueba
// en vez de a la base real de quien la ejecuta.
func correrCon(t *testing.T, bin, repo, datos string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Dir = repo
	c.Env = entornoAislado(t, datos)
	out, err := c.CombinedOutput()
	codigo := 0
	if ee, ok := err.(*exec.ExitError); ok {
		codigo = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("no se pudo ejecutar %s %v: %v", bin, args, err)
	}
	return string(out), codigo
}
