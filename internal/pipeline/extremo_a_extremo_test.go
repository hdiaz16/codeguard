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
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// violacion es qué se le pone delante a un motor y qué debe responder.
type violacion struct {
	motor     string // el nombre con el que el motor se anuncia en el log
	archivo   string
	contenido string
	porQue    string // para que un fallo diga algo útil, no "esperaba 1, hubo 0"
	// requiere: dependencia externa, en prosa, para que el informe la nombre. Si
	// falta, el motor NO APLICA — y eso no es un fallo, pero se reporta. Nunca se
	// calla.
	requiere string
	// presente responde si esa dependencia está DE VERDAD en esta máquina.
	//
	// Existe porque `requiere` sola no sirve para decidir: es prosa, y el arnés
	// la usaba como si fuera una comprobación —"declara que necesita el SDK de
	// .NET, luego lo absuelvo"—. Con el SDK instalado y el motor roto, 0
	// hallazgos salía como NO APLICA en vez de ¡NO CAZÓ!. La dependencia hay que
	// mirarla, no creérsela.
	//
	// nil = sin dependencia externa: el motor tiene que correr siempre.
	presente func(repo string) bool
}

// El módulo con una dependencia vulnerable FIJADA, y el código que la llama.
//
// yaml.v2 v2.2.2 se elige por vieja y con CVE público: una vulnerabilidad
// reciente puede desaparecer del feed o cambiar de severidad, y dejaría la
// prueba en rojo por algo que no es nuestro.
//
// Los dos archivos van juntos porque prueban cosas distintas del mismo hecho:
// trivy dice "el CVE está en tu manifiesto"; govulncheck demuestra que tu
// código LLAMA al símbolo vulnerable. Un fixture que sólo declarara la
// dependencia haría pasar a govulncheck sin ejercitar la alcanzabilidad, que es
// exactamente lo único que aporta sobre trivy.
const (
	modConDependenciaVulnerable = "module fixture\n\ngo 1.21\n\n" +
		"require gopkg.in/yaml.v2 v2.2.2\n"

	usaSimboloVulnerable = "package fixture\n\nimport \"gopkg.in/yaml.v2\"\n\n" +
		"func Cargar(datos []byte) (map[string]any, error) {\n" +
		"\tvar m map[string]any\n" +
		"\terr := yaml.Unmarshal(datos, &m)\n" +
		"\treturn m, err\n}\n"
)

// El proyecto de C# del fixture: declara una dependencia con aviso conocido y
// pide el lockfile.
//
// RestorePackagesWithLockFile no es un detalle. Sin packages.lock.json,
// `dotnet list package --vulnerable` no encuentra NADA en un .csproj —lo dice
// el propio motor en su cabecera, y es el hueco que trivy no cubre—, así que la
// casilla habría quedado verde sin analizar.
//
// System.Net.Http 4.3.0 se elige por vieja y con aviso publicado
// (GHSA-7jgj-8wvc-jh57), por el mismo motivo que yaml.v2 en Go: un aviso
// reciente puede moverse y dejar la prueba roja por algo ajeno.
const csprojConDependenciaVulnerable = "<Project Sdk=\"Microsoft.NET.Sdk\">\n" +
	"  <PropertyGroup>\n" +
	"    <TargetFramework>net10.0</TargetFramework>\n" +
	"    <Nullable>disable</Nullable>\n" +
	"    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n" +
	"  </PropertyGroup>\n  <ItemGroup>\n" +
	"    <PackageReference Include=\"System.Net.Http\" Version=\"4.3.0\" />\n" +
	"  </ItemGroup>\n</Project>\n"

// elSecreto va aparte: bloquea la etapa 1 y con él dentro no corre nada más,
// así que se prueba en su propia fase.
const elSecreto = "# fixture de verificación — token inventado, no es una credencial real\n" +
	"GITHUB_TOKEN = \"ghp_" + "0Nn8Qk2Xv7Lm4Rt9Yb3Wc6Zd1Ae5Gf7Hj0K\"\n"

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
			porQue: "google-java-format: llaves y sangría fuera de estilo",
			// Dice "que pueda ejecutar" y no "instalado" porque en esta máquina las
			// dos cosas están instaladas y AUN ASÍ el motor no puede correr: el jar
			// de la 1.36.1 es class file 65 (JDK 21) y el JDK es 17 (61). Un
			// informe que dijera "falta google-java-format" mandaría a instalar lo
			// que ya está.
			requiere: "un JDK capaz de EJECUTAR el jar de google-java-format (el 1.36.1 exige JDK 21)",
			presente: conJava("google-java-format"),
		},
		{
			motor:   "pmd",
			archivo: "src/Calidad.java",
			contenido: "public class Calidad {\n    public void m() {\n" +
				"        int noSeUsa = 5;\n    }\n}\n",
			porQue:   "PMD: variable local asignada y nunca usada",
			requiere: "JDK + PMD instalados",
			presente: conJava("pmd"),
		},
		{
			motor:   "mypy",
			archivo: "app/tipos.py",
			contenido: "def suma(a: int, b: int) -> int:\n" +
				"    return a + b\n\n\n" +
				"resultado: str = suma(1, 2)\n",
			porQue:   "mypy: int asignado a str, con mypy.ini presente en el repo",
			requiere: "mypy instalado Y configurado por el repo",
			presente: enElPath("mypy"),
		},
		{
			// El manifiesto con una dependencia vulnerable fijada. yaml.v2
			// v2.2.2 se elige por vieja y con CVE publico: una vulnerabilidad
			// reciente puede desaparecer del feed y dejar la prueba en rojo por
			// algo que no es nuestro.
			motor:     "trivy",
			archivo:   "go.mod",
			contenido: modConDependenciaVulnerable,
			porQue:    "trivy: dependencia con CVE declarada en el manifiesto",
			requiere:  "red la primera vez (descargar el módulo)",
			presente:  conModuloResuelto,
		},
		{
			// Y el MISMO módulo, pero llamando al símbolo vulnerable.
			//
			// Es la diferencia entre los dos motores y hay que probarla así:
			// trivy dice "el CVE está en tu go.sum"; govulncheck demuestra que
			// tu código lo LLAMA. Un fixture que sólo declarara la dependencia
			// haría pasar a govulncheck sin ejercitar la alcanzabilidad, que es
			// justo lo único que aporta sobre trivy.
			motor:     "govulncheck",
			archivo:   "usayaml.go",
			contenido: usaSimboloVulnerable,
			porQue:    "govulncheck: llama a yaml.Unmarshal, símbolo vulnerable alcanzable",
			requiere:  "red la primera vez (descargar el módulo)",
			presente:  conModuloResuelto,
		},
		{
			// Se prueba con BIOME, no con eslint, y es una decisión medida: el
			// motor corre "el que el repo haya configurado", y biome es un solo
			// paquete npm mientras que un eslint de verdad arrastra su
			// configuración y sus plugins. Lo que hay que verificar es el
			// cableado del motor —que detecta la configuración del repo, corre
			// la herramienta y traduce su salida—, y biome lo ejercita entero
			// por una fracción del coste.
			//
			// El nombre del motor en el log es "eslint" aunque corra biome;
			// dentro del hallazgo viaja la herramienta real.
			motor:   "eslint",
			archivo: "malo.ts",
			contenido: "export function malo(a: number) {\n" +
				"  const sinUsar = 1;\n  if (a == 2) {\n    return 1;\n  }\n  return 0;\n}\n",
			porQue:   "biome: variable sin usar y comparación con ==",
			requiere: "biome instalado en el repo (npm install)",
			presente: enElRepo("biome.cmd"),
		},
		{
			motor:   "tsc",
			archivo: "tipos.ts",
			contenido: "export function suma(a: number, b: number): number {\n" +
				"  return a + b;\n}\n\nconst r: string = suma(1, 2);\n",
			porQue:   "tsc: number asignado a string (TS2322)",
			requiere: "typescript instalado en el repo (npm install)",
			presente: enElRepo("tsc.cmd"),
		},
		{
			// El hueco que trivy NO cubre: sin packages.lock.json no encuentra
			// nada en un .csproj. La "violación" vive en el propio proyecto —la
			// dependencia declarada— y este .cs sólo existe para que el motor
			// tenga un archivo de C# tocado por el que aplicar.
			motor:     "dotnet-vuln",
			archivo:   "src/Vulnerable.cs",
			contenido: "public class Vulnerable { public void M() { } }\n",
			porQue:    "dotnet-vuln: System.Net.Http 4.3.0, aviso de severidad alta",
			requiere:  "SDK de .NET y red la primera vez",
			presente:  conDotnetRestaurado,
		},
		{
			motor:     "dotnet-format",
			archivo:   "src/Malformato.cs",
			contenido: "public class Malformato{\npublic void M(){\nint x=1;\n}\n}\n",
			porQue:    "dotnet format: estilo deliberadamente roto",
			requiere:  "SDK de .NET",
			presente:  conDotnetRestaurado,
		},
		{
			// La compuerta que le faltaba a C#: hasta que se integró, un
			// `; expected` en un .cs llegaba entero al CI, porque dotnet format
			// sólo mira el formato y nadie compilaba.
			motor:   "dotnet-build",
			archivo: "src/NoCompila.cs",
			contenido: "public class NoCompila {\n    public int M() {\n" +
				"        return \"texto\";\n    }\n}\n",
			porQue:   "dotnet build: string devuelto donde se declara int (CS0029)",
			requiere: "SDK de .NET",
			presente: conDotnetRestaurado,
		},
	}
}

// Los motores que el arnés todavía no sabe provocar. Se nombran a propósito:
// un motor que nadie prueba y que además nadie MENCIONA desaparece del informe,
// y entonces "todo verde" significa menos de lo que parece.
// Los motores que el arnés todavía no sabe provocar.
//
// Está VACÍO, y esa es la meta de la fase 4: al empezar tenía seis entradas
// —trivy, govulncheck, tsc, eslint, dotnet-build y dotnet-vuln—, cada una
// nombrando lo que le faltaba. Se deja el mapa en vez de borrarlo porque el
// día que se añada un motor nuevo, su casilla tiene que poder decir "sin
// probar" en lugar de desaparecer de la tabla.
var sinPruebaTodavia = map[string]string{}

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
	confiarEnRepo(t, bin, repo)

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

	// El código de salida NO se descarta. `report` no es una compuerta —quien
	// bloquea es el gancho, y eso es la fase 1 de arriba—, y reportcmd.go no tiene
	// ni un os.Exit ni devuelve error por encontrar hallazgos: sale con 0 siempre
	// que la corrida sea válida. Así que un código distinto de cero significa que
	// la corrida falló, y entonces su salida PARCIAL no se puede pasar a informe():
	// los motores que no llegaron a anunciarse saldrían como «¡NO CAZÓ!», o peor,
	// como «NO APLICA» si además falta su dependencia, y un fallo del producto se
	// leería como un veredicto del arnés.
	salida, codigo = correr(t, bin, repo, "report", "--avisos")
	if codigo != 0 {
		t.Fatalf("report --avisos salió con código %d: la corrida falló, así que su "+
			"salida parcial no es evaluable.\n%s", codigo, salida)
	}
	informe(t, repo, salida)
}

func informe(t *testing.T, repo, salida string) {
	t.Helper()

	filas, err := revisarInforme(repo, salida)
	if err != nil {
		t.Fatalf("%v\n%s", err, salida)
	}

	t.Log("")
	t.Log("  MOTOR                ESTADO      HALLAZGOS  DETALLE")
	t.Log("  -------------------- ----------- ---------  ------------------------------------")
	var fallaron []string
	for _, f := range filas {
		t.Logf("  %s %s %9d  %s", rellenar(f.motor, 20), rellenar(f.estado, 11), f.hallazgos, f.detalle)
		if f.falla {
			fallaron = append(fallaron, f.motor)
		}
	}
	t.Log("")

	if len(fallaron) > 0 {
		t.Errorf("estos motores corrieron sin ver la violación que tenían delante: %v.\n"+
			"Un motor que no ve lo que se le pone delante es indistinguible de uno sano "+
			"mientras el repositorio esté limpio, que es el 99%% del tiempo.", fallaron)
		// La salida COMPLETA del producto, no solo la tabla: el fallo de un
		// motor en un entorno ajeno (el runner del CI) no se puede diagnosticar
		// desde lejos con un contador en cero — hacen falta sus tiempos, sus
		// avisos de reglas rotas y sus degradaciones, que viajan aquí.
		t.Logf("salida completa del producto, para diagnóstico:\n%s", salida)
	}
}

// fila es una casilla de la tabla del arnés ya resuelta: qué le pasó al motor y
// si eso tiene que poner la prueba en rojo.
type fila struct {
	motor     string
	estado    string
	hallazgos int
	detalle   string
	falla     bool
}

// revisarInforme traduce lo que imprimió el producto a la tabla del arnés.
//
// Va aparte de informe —que sólo pinta y falla— porque es la parte que DECIDE, y
// una decisión que no se puede probar sin levantar el repo entero, compilar el
// binario y correr once motores es una decisión que nadie prueba. Con esto, cada
// regla de clasificación se ejercita en una tabla y en milisegundos.
func revisarInforme(repo, salida string) ([]fila, error) {
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
		return nil, errors.New("ningún motor se anunció en la salida: el arnés no mide nada.")
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

	filas := make([]fila, 0, len(nombres))
	for _, n := range nombres {
		v, esperado := esperados[n]
		f := fila{motor: n, hallazgos: hallazgos[n]}

		// La pregunta que decide las dos absoluciones del arnés, hecha UNA vez y
		// COMPROBADA. Antes cada una se resolvía por su cuenta y ninguna miraba:
		// el degradado se absolvía siempre, y el 0-hallazgos se absolvía por que
		// el motor DECLARARA una dependencia.
		falta := esperado && faltaLaDependencia(v, repo)

		switch {
		case !esperado:
			f.estado, f.detalle = "SIN PRUEBA", sinPruebaTodavia[n]
		case degradados[n] && falta:
			f.estado, f.detalle = "DEGRADADO", "no llegó a revisar; falta "+v.requiere
		case degradados[n]:
			f.estado, f.falla = "DEGRADADO", true
			f.detalle = "no llegó a revisar Y SU DEPENDENCIA ESTÁ: es una regresión"
		case hallazgos[n] > 0:
			f.estado, f.detalle = "CAZÓ", v.porQue
		case falta:
			f.estado, f.detalle = "NO APLICA", "requiere: "+v.requiere
		default:
			f.estado, f.detalle, f.falla = "¡NO CAZÓ!", v.porQue, true
		}
		filas = append(filas, f)
	}
	return filas, nil
}

// ── comprobación de dependencias ─────────────────────────────────────────────
//
// Cada una responde "¿está esto en la máquina donde corre el arnés?". Son las
// mismas que necesita el producto para poder correr el motor: si mienten, el
// arnés acusa a un motor sano o absuelve a uno roto.

// faltaLaDependencia responde la pregunta de la que cuelgan las DOS absoluciones
// del arnés: ¿este motor declara una dependencia externa que no está aquí?
//
// Es una variable, y no la expresión suelta que había dentro de revisarInforme,
// porque sin un punto de sustitución el guardián de arnes_test.go —el que existe
// para que el arnés no absuelva a un motor cuya dependencia SÍ está— no podía
// ejercitar NI UNO de sus diez motores, en ninguna máquina. Medido antes de
// tocar nada: «TOTAL EJERCITADOS: 0 de 10».
//
// Eran dos causas y ninguna se arregla instalando herramientas:
//
//   - Para trivy, govulncheck y los tres de dotnet, `presente` lee las variables
//     moduloResuelto y dotnetRestaurado, que rellena el fixture del e2e. Como
//     Go registra los tests por orden de ARCHIVO y arnes_test.go va antes que
//     extremo_a_extremo_test.go, cuando el guardián corre valen `false` siempre
//     — incluso pidiendo el e2e primero en la línea de comandos, comprobado.
//   - Para eslint y tsc, `presente` busca node_modules en el repo que le pasan,
//     y el guardián le pasa un t.TempDir() recién creado y vacío.
//
// Sustituyéndola, el guardián prueba lo que de verdad es suyo —la TABLA DE
// DECISIÓN de revisarInforme— de forma determinista, en cualquier máquina y
// para los diez motores. Que las comprobaciones de verdad estén cableadas lo
// cubren TestTodaDependenciaDeclaradaEsComprobable y
// TestElValorPorDefectoPreguntaALaComprobacionDeVerdad.
var faltaLaDependencia = func(v violacion, repo string) bool {
	return v.presente != nil && !v.presente(repo)
}

// enElPath es la dependencia más simple: la herramienta se resuelve por PATH.
func enElPath(bin string) func(string) bool {
	return func(string) bool {
		_, err := exec.LookPath(bin)
		return err == nil
	}
}

// conJava: los motores de Java necesitan el JDK Y su .jar descargado en el
// directorio de motores, que es de donde los saca el producto.
//
// Y necesitan una tercera cosa que esta comprobación daba por hecha: que ESE JDK
// pueda EJECUTAR ESE jar. Con java en el PATH y el jar en su sitio, este arnés
// declaraba la dependencia presente y acusaba al motor de regresión — cuando lo
// que pasa en esta máquina es que el jar de google-java-format 1.36.1 está
// compilado para JDK 21 (class file 65) y hay JDK 17 (61), así que la JVM muere
// con UnsupportedClassVersionError antes de mirar un solo archivo.
//
// La diferencia importa porque las dos frases mandan a sitios opuestos: «es una
// regresión» manda a buscar un fallo en el motor, que está bien; «la dependencia
// está pero tu JDK no puede con ella» manda a instalar un JDK 21, que es lo que
// de verdad hay que hacer. Y un arnés permanentemente rojo por una causa conocida
// enseña a ignorar el rojo, que es peor que no tenerlo.
//
// Se comprueba EJECUTÁNDOLO, no comparando versiones de class file: el lanzador
// de Java escribe su queja con el prefijo "Error: " y ese es el criterio que ya
// usa el motor de verdad (jErrorDeJVM en internal/engines/linters).
func conJava(prefijoJar string) func(string) bool {
	return func(string) bool {
		if _, err := exec.LookPath("java"); err != nil {
			return false
		}
		dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "CodeGuard", "engines")
		m, _ := filepath.Glob(filepath.Join(dir, prefijoJar+"*.jar"))
		if len(m) == 0 {
			return false
		}
		return jarEjecutable(m[0])
	}
}

// jarEjecutable dice si esta JVM puede cargar el jar. El plazo es corto porque
// arrancar una JVM para preguntarle la versión no debería tardar más.
func jarEjecutable(jar string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	salida, _ := exec.CommandContext(ctx, "java", "-jar", jar, "--version").CombinedOutput()
	// No se juzga el código de salida: hay herramientas que responden a --version
	// con uno distinto de cero. Lo que descalifica es que la JVM no llegara a
	// cargar la clase principal.
	for _, marca := range []string{
		"UnsupportedClassVersionError", "LinkageError",
		"Could not find or load main class", "NoClassDefFoundError",
	} {
		if strings.Contains(string(salida), marca) {
			return false
		}
	}
	return true
}

// enElRepo: biome y tsc los instala el propio repositorio con npm, así que la
// dependencia vive en el fixture y no en la máquina.
func enElRepo(lanzador string) func(string) bool {
	return func(repo string) bool {
		if repo == "" {
			return false
		}
		_, err := os.Stat(filepath.Join(repo, "node_modules", ".bin", lanzador))
		return err == nil
	}
}

// moduloResuelto recuerda si `go mod tidy` pudo bajar el módulo del fixture.
//
// El resultado se perdía en un t.Logf, y sin él el arnés no sabe distinguir
// "trivy no vio el CVE que tenía delante" —una regresión— de "no hubo red para
// bajar el módulo y no había CVE que ver" — el entorno. Absolvía siempre, así
// que la casilla de dependencias vulnerables nunca podía ponerse en rojo.
//
// CONTRATO de este flag y de dotnetRestaurado: los escribe el fixture del e2e y
// los leen las comprobaciones de dependencia, así que NINGÚN test de este paquete
// puede usar t.Parallel() (hoy no hay ni uno). Se auditó convertirlos a
// atomic.Bool y se descartó, porque no arregla la causa y además la esconde: lo
// que importa aquí no es la atomicidad de un bool sino el ORDEN —que el fixture
// haya escrito antes de que alguien lea—, y eso el atomic no lo da. Lo que sí
// haría es callar al detector de `go test -race`, que hoy es lo único que
// delataría el problema el día que alguien añada t.Parallel: en su lugar, el
// lector se llevaría un `false` silencioso y el motor saldría absuelto con un
// "NO APLICA" que nadie mira.
var moduloResuelto bool

func conModuloResuelto(string) bool { return moduloResuelto }

// dotnetRestaurado: lo mismo para C#. Y aquí "está el SDK" NO basta como
// comprobación, que fue la primera versión de esto y habría sido un rojo falso:
// en esta máquina `dotnet` está en el PATH pero el SDK es 8.0 y el fixture apunta
// a net10.0, así que el restore falla con NETSDK1045 y los motores de C# no
// tienen nada que analizar. Con el PATH como única prueba, el arnés habría
// acusado a tres motores sanos de no ver su violación.
//
// La dependencia real no es el binario: es que el proyecto se haya restaurado.
var dotnetRestaurado bool

func conDotnetRestaurado(string) bool { return dotnetRestaurado }

// rellenar alinea la columna contando RUNES y no bytes: los estados llevan
// acentos ("CAZÓ", "¡NO CAZÓ!") y con %-11s la tabla se descuadraba justo en las
// casillas que importa leer.
func rellenar(s string, n int) string {
	for utf8.RuneCountInString(s) < n {
		s += " "
	}
	return s
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
	t.Cleanup(func() {
		moduloResuelto = false
		dotnetRestaurado = false
	})
	repo := repoBase(t)
	// El rulepack va DENTRO del repo de juguete, igual que en la prueba de
	// paridad y por el mismo motivo: sin él, en una máquina sin rulepack
	// INSTALADO (el runner del CI, una instalación fresca) semgrep salía
	// «0 hallazgo(s) en 0ms» —ni corrió— y la tabla lo acusaba de no ver la
	// violación. En la máquina del desarrollador el rulepack instalado tapaba
	// el hueco y el fallo era invisible.
	copiarRulepack(t, repo)
	for _, v := range violaciones() {
		escribir(t, repo, v.archivo, v.contenido)
	}
	prepararProyectoTS(t, repo)
	// El módulo tiene que resolverse: sin go.sum, govulncheck y staticcheck no
	// pueden cargar los paquetes y las dos casillas saldrían sin probar por un
	// motivo que no es suyo.
	//
	// Va aquí y no en repoBase: el go.mod CON dependencia lo escribe esta
	// función. Estuvo un rato en repoBase y dejaba un go.sum sin commitear en
	// el árbol de trabajo de todas las demás pruebas, que sí lo notaron —la de
	// paridad y la del caché se pusieron rojas por eso, no por lo suyo.
	resolverModuloGo(t, repo)
	git(t, repo, "add", "-A")
	return repo
}

// resolverModuloGo genera el go.sum del fixture. La primera vez necesita red
// para bajar el módulo; después vive en la caché de módulos de la máquina.
//
// Si falla no se aborta: las casillas de trivy y govulncheck saldrán sin cazar
// y se verá en la tabla, que es mejor que un fallo con un motivo confuso.
func resolverModuloGo(t *testing.T, repo string) {
	t.Helper()
	c := exec.Command("go", "mod", "tidy")
	c.Dir = repo
	c.Env = append(sinGOROOT(os.Environ()), "GOFLAGS=-mod=mod")
	out, err := c.CombinedOutput()
	// El resultado se ANOTA, no sólo se cuenta. Perdido en el t.Logf, el arnés no
	// podía distinguir "trivy no vio el CVE" de "no hubo red", y absolvía las dos
	// cosas igual.
	moduloResuelto = err == nil
	if err != nil {
		t.Logf("go mod tidy falló (¿sin red?): las casillas de dependencias saldrán sin probar: %v\n%s", err, out)
	}
}

// restaurarProyectoDotnet deja el .csproj listo para compilar sin red. Si no
// hay SDK no es un fallo: las dos casillas de C# saldrán "no aplica" y lo
// dirán.
func restaurarProyectoDotnet(t *testing.T, repo string) {
	t.Helper()
	if _, err := exec.LookPath("dotnet"); err != nil {
		return
	}
	c := exec.Command("dotnet", "restore", filepath.Join("src", "App.csproj"))
	c.Dir = repo
	c.Env = sinGOROOT(os.Environ())
	out, err := c.CombinedOutput()
	// Se ANOTA, igual que con el módulo de Go: tener el SDK en el PATH no
	// significa que el proyecto se pueda restaurar, y sin restore los motores de
	// C# no tienen nada que analizar.
	dotnetRestaurado = err == nil
	if err != nil {
		t.Logf("dotnet restore falló (las casillas de C# saldrán sin probar): %v\n%s", err, out)
	}
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
	// Un proyecto de C# de verdad: `dotnet format` y `dotnet build` trabajan
	// sobre proyectos, no sobre .cs sueltos, así que sin esto las dos casillas
	// saldrían "no aplica" sin haber probado nada.
	escribir(t, repo, "src/App.csproj", csprojConDependenciaVulnerable)
	escribir(t, repo, ".codeguard/config.yaml",
		"version: 1\nrulepack: \"2026.08.2\"\nmax_diff_lines: 5000\n"+
			"paths:\n  migrations: [\"migrations/*.sql\"]\n  migrations_dialect: postgres\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "base", "--no-verify")

	// El restore va aquí, junto al .csproj que lo necesita, y no en montarRepo:
	// estaba en el otro sitio y la prueba de la doble compilación —que parte de
	// repoBase— se encontraba un proyecto sin restaurar y no veía el error ni
	// la primera vez.
	//
	// `dotnet build` se invoca con --no-restore a propósito: restaurar en el
	// camino del commit sería ir a la red. Un repo real se restaura al clonar.
	restaurarProyectoDotnet(t, repo)

	return repo
}

// confiarEnRepo reproduce el paso real del usuario —`codeguard confiar --si`—
// sobre el binario que se mide, para que los motores que ejecutan config del
// repo (eslint/tsc/mypy/dotnet) corran. Se hace con el COMANDO real y no
// registrando desde el proceso de test porque el hook y `confiar` resuelven
// la ruta del repo con git (canónica), y el t.TempDir crudo daba otra clave
// en Windows. El default seguro (SIN confiar) tiene su prueba en los fixtures
// adversariales y en internal/confianza.
func confiarEnRepo(t *testing.T, bin, repo string) {
	t.Helper()
	if salida, cod := correr(t, bin, repo, "confiar", "--si"); cod != 0 {
		t.Logf("no se pudo confiar en el fixture (los motores config-ejecutable saldrán degradados): %s", salida)
	}
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

// La trampa de MSBuild: la SEGUNDA compilación también tiene que ver el error.
//
// `dotnet build` sin más considera el proyecto "al día" si nada cambió desde la
// última compilación, no recompila, y sale sin errores. Un motor que se fiara
// de eso diría "limpio" en la segunda corrida sobre el MISMO código roto —y la
// segunda corrida es la normal: el desarrollador reintenta el commit—.
//
// Por eso el motor compila con -t:Rebuild. Estaba en el plan de la fase 4.1
// desde el principio: sin esta prueba, la casilla de dotnet-build se habría
// cerrado verificando sólo el caso fácil.
//
// LÍMITE DE ESTA PRUEBA, y conviene leerlo antes de fiarse de ella: lo que
// verifica es la GARANTÍA —la segunda corrida ve lo mismo que la primera—, no
// el mecanismo. Se hizo el control quitando -t:Rebuild y la prueba siguió
// verde, así que NO demuestra que esa bandera sea la que lo consigue. En este
// fixture MSBuild vuelve a compilar de todas formas.
//
// Se deja dicho en vez de callarlo: alguien podría quitar -t:Rebuild mañana,
// ver esto verde, y creer que lo ha comprobado. La garantía sí está medida; la
// atribución no. Reproducir la trampa del build "al día" pide un proyecto que
// MSBuild considere realmente actualizado, y eso es otra prueba.
func TestDotnetBuildVeElErrorTambienLaSegundaVez(t *testing.T) {
	if testing.Short() {
		t.Skip("compila un proyecto de C# dos veces")
	}
	if runtime.GOOS != "windows" {
		t.Skip("CodeGuard sólo se distribuye para Windows")
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		t.Skip("sin SDK de .NET no hay nada que compilar")
	}

	bin := construirBinario(t)
	repo := repoBase(t)
	escribir(t, repo, "src/NoCompila.cs",
		"public class NoCompila {\n    public int M() {\n        return \"texto\";\n    }\n}\n")
	git(t, repo, "add", "-A")

	// Con el directorio de datos aislado, para poder vaciar el caché entre las
	// dos corridas.
	//
	// Sin vaciarlo, la segunda corrida acierta en el caché y `dotnet build` ni
	// se invoca: la prueba mediría el caché y no Rebuild, y pasaba igual
	// quitando -t:Rebuild. Vaciándolo se fuerza una compilación de verdad con el
	// proyecto ya compilado en disco, que es exactamente el escenario del
	// desarrollador que ya compiló en su IDE.
	datos := t.TempDir()
	primera, _ := correrCon(t, bin, repo, datos, "report", "--avisos")
	vaciarCache(t, datos)
	segunda, _ := correrCon(t, bin, repo, datos, "report", "--avisos")

	n1 := cuentaDe(primera, "dotnet-build")
	n2 := cuentaDe(segunda, "dotnet-build")

	if n1 == 0 {
		t.Fatalf("dotnet-build no vio el error ni la primera vez: no hay nada que medir.\n%s", primera)
	}
	if n2 != n1 {
		t.Errorf("la SEGUNDA compilación vio %d errores y la primera %d.\n"+
			"MSBuild da el proyecto por 'al día' y no recompila, así que el motor diría "+
			"limpio sobre el mismo código roto — y la segunda corrida es la normal, "+
			"porque el desarrollador reintenta el commit.\n%s", n2, n1, segunda)
	} else {
		t.Logf("  ✓ las dos compilaciones ven los mismos %d aviso(s)", n1)
	}
}

// cuentaDe extrae cuántos hallazgos anunció un motor concreto en la salida.
func cuentaDe(salida, motor string) int {
	for _, m := range reLinea.FindAllStringSubmatch(salida, -1) {
		if m[1] == motor {
			n, _ := strconv.Atoi(m[2])
			return n
		}
	}
	return 0
}

// prepararProyectoTS deja un proyecto TypeScript con su typescript instalado.
//
// El motor invoca `npx --no-install tsc` a propósito: el camino del commit NO
// puede ir a la red. Eso significa que tsc sólo corre si el repo tiene
// typescript entre sus dependencias, que es exactamente como está cualquier
// repo de TypeScript de verdad — y por eso el fixture hace `npm install` en vez
// de dejar que npx lo descargue: si lo descargara, la prueba estaría
// verificando un camino que en producción está cerrado.
//
// Si npm no está o falla, la casilla sale sin cazar y se ve en la tabla.
func prepararProyectoTS(t *testing.T, repo string) {
	t.Helper()
	escribir(t, repo, "tsconfig.json",
		"{\n  \"compilerOptions\": { \"strict\": true, \"noEmit\": true, \"target\": \"ES2020\" }\n}\n")
	escribir(t, repo, "package.json",
		"{\n  \"name\": \"fixture\",\n  \"private\": true,\n"+
			"  \"devDependencies\": {\n"+
			"    \"typescript\": \"5.9.2\",\n"+
			"    \"@biomejs/biome\": \"2.3.14\"\n  }\n}\n")
	// La configuración de biome es lo que hace que el motor de JS/TS APLIQUE.
	//
	// Sin ella decide que el repo no eligió linter y no corre — que es su
	// comportamiento correcto, y también la razón de que la casilla llevara toda
	// la fase 4 sin probar: nadie le había puesto delante un repo que sí lo
	// configurara.
	escribir(t, repo, "biome.json", "{\n  \"linter\": { \"enabled\": true }\n}\n")
	escribir(t, repo, ".gitignore", "obj/\nbin/\nnode_modules/\n")

	if _, err := exec.LookPath("npm"); err != nil {
		t.Log("sin npm: la casilla de tsc saldrá sin probar")
		return
	}
	c := exec.Command("npm", "install", "--silent", "--no-audit", "--no-fund")
	c.Dir = repo
	c.Env = sinGOROOT(os.Environ())
	if out, err := c.CombinedOutput(); err != nil {
		t.Logf("npm install falló (¿sin red?): la casilla de tsc saldrá sin probar: %v\n%s", err, out)
	}
}
