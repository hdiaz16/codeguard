package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/engines/gitleaks"
	"codeguard/internal/gitdiff"
)

// EL CONTRATO QUE FALTABA, Y LA CLASE DE FALLO QUE RETIRA.
//
// `Run` devuelve `([]finding.Finding, error)`, y hasta hoy `(nil, nil)`
// significaba DOS cosas incompatibles: «miré y está limpio» y «no pude mirar y
// no supe decirlo». Un consumidor no puede distinguirlas, así que el pipeline
// contaba la segunda como la primera y el panel pintaba un ✓ verde sobre una
// capa que no había mirado nada.
//
// No es hipotético y no es un motor: es una CLASE.
//   - govet lo tuvo, y su arreglo es literalmente el último commit del repo:
//     "govet decía «limpio» cuando no había podido analizar nada".
//   - tsc lo tuvo hasta hoy. `npx --no-install tsc` resolvía a un paquete de
//     npm que no es TypeScript, imprimía un banner y salía con 1; el parser no
//     encontraba diagnósticos y el motor devolvía cero hallazgos. Medido en la
//     máquina de Héctor: un `return centavos` donde la función promete string
//     entró al repositorio con "formato/lint/tipos/reglas/migraciones ✓".
//
// Dos veces el mismo fallo en dos motores distintos, y el segundo DESPUÉS de
// arreglar el primero, significa que el contrato no estaba escrito en ninguna
// parte: cada motor decidía por su cuenta qué significaba su silencio. Arreglar
// motores de uno en uno no retira la clase; sólo espera al siguiente.
//
// EL CONTRATO: un motor devuelve hallazgos, o devuelve por qué no pudo. No
// existe la tercera opción. Este test lo impone sobre TODOS los motores a la
// vez, así que el que se añada mañana nace obligado.
func TestNingunMotorPuedeDecirLimpioSinHaberMirado(t *testing.T) {
	// Windows-only de verdad, y se dice: el sabotaje son .cmd por lotes que
	// exec.LookPath resuelve por PATHEXT. En Unix los señuelos no se
	// ejecutarían NUNCA —LookPath no mira PATHEXT y un .cmd no es ejecutable—,
	// así que cada motor encontraría la herramienta real o fallaría por su
	// cuenta, y la prueba pasaría sin haber ejercitado el contrato: un verde
	// falso, que es exactamente la enfermedad que este archivo existe para
	// retirar.
	//
	// Es t.Skip y no //go:build windows porque este archivo tiene OTROS dos
	// guardianes —TestElContratoNoDejaMotoresFuera y
	// TestCadaMotorDecideSiEstaExento— que son AST y lógica pura, corren bien
	// en Unix y su cobertura ahí es REAL. Etiquetar el archivo entero los
	// sacaría de Unix para proteger una mentira que no cometen.
	if runtime.GOOS != "windows" {
		t.Skip("los señuelos .cmd y la resolución por PATHEXT sólo existen en Windows")
	}
	raiz := fixturePoliglota(t)

	// Con config y no con nil: squawk sólo aplica si el repo declara sus
	// migraciones y el dialecto, así que sin esto su control fallaría y el
	// motor quedaría fuera del contrato sin que nadie lo notara — que es
	// exactamente la forma en que estas pruebas se vuelven decorativas.
	cfg := conLanguages("go", "python", "sql", "typescript", "csharp", "java")
	cfg.Paths.Migrations = []string{"migrations/*.sql", "migrations/**/*.sql"}
	cfg.Paths.MigrationsDialect = "postgres"

	for _, motor := range motoresBajoContrato(cfg, nil) {
		nombre := motor.Name()
		t.Run(nombre, func(t *testing.T) {
			if motivo, exento := exentosDelContrato[nombre]; exento {
				t.Skip("exento a propósito: " + motivo)
			}
			in := engines.Input{RepoRoot: raiz, Files: archivosDe(t, raiz)}

			// CONTROL. Sin esto la prueba pasaría por la razón equivocada: un
			// motor al que no le toca mirar nada devuelve (nil, nil) con toda
			// la razón del mundo, y eso no prueba nada sobre el contrato.
			if !motor.Applies(in) {
				t.Fatalf("el fixture no tiene material para %s, así que esta prueba no "+
					"está comprobando nada sobre él. Añádeselo a fixturePoliglota.", nombre)
			}

			// CUATRO sabotajes, y hacen falta los cuatro. Lo aprendí a base de
			// escribir dos versiones decorativas seguidas y, más tarde, de ver
			// sobrevivir una mutación con las tres primeras puestas.
			//
			// La primera usaba un plazo ya vencido: los 17 pasaban, y al
			// revertir el arreglo de tsc SEGUÍAN pasando. Un plazo vencido hace
			// que todos fallen temprano con un error de contexto, que no es el
			// modo de avería que produce el fallo.
			//
			// La segunda usaba un impostor que escupe basura y sale con 1. Cazó
			// a google-java-format… y a nadie más. Un agente midiendo en
			// paralelo, sin ver mi diseño, encontró OCHO violadores con dos
			// modos que yo no hacía. La lección: el sabotaje no es un detalle
			// del test, ES el test.
			for _, s := range sabotajes {
				t.Run(s.nombre, func(t *testing.T) {
					// La comprobación de identidad se memoriza por binario, y tiene
					// que hacerlo: el daemon vive días y no va a preguntarle la
					// versión a la misma herramienta en cada commit. Aquí hay que
					// olvidarla entre sabotajes, o un caso heredaría el veredicto
					// del anterior y pasaría por el motivo equivocado.
					contrato.OlvidarTodo()
					t.Setenv("PATH", señuelos(t, s)+string(os.PathListSeparator)+os.Getenv("PATH"))

					// Plazo por sabotaje, y hace falta: si el señuelo no cubre la
					// herramienta que el motor invoca —hoy `git` no está en la
					// lista de impostores—, se ejecuta la de verdad, y esa puede
					// tardar minutos o colgarse. Sin plazo el test se entera por
					// el timeout global de `go test`: diez minutos y un volcado
					// de pila que no dice qué motor se quedó colgado.
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					hallazgos, err := motor.Run(ctx, in)
					// Se lee ANTES de cancel(): cancel deja ctx.Err() en Canceled
					// y borraría la evidencia del plazo vencido.
					vencido := ctx.Err() == context.DeadlineExceeded
					cancel()

					// El plazo vencido es un fallo DEL MOTOR, y con su nombre: o
					// se colgó hasta que el contexto lo cortó, o se tragó el
					// DeadlineExceeded y devolvió otra cosa. Las dos dicen lo
					// mismo: no puede prometer que mira en un tiempo razonable.
					if vencido {
						t.Fatalf("%s no terminó en 2 minutos con el sabotaje que %s: "+
							"o invocó la herramienta real y se colgó, o ignoró la cancelación "+
							"del contexto. Un motor que no acota su tiempo deja el gancho "+
							"colgado igual que deja colgado a este test.", nombre, s.describe)
					}

					if err == nil && len(hallazgos) == 0 {
						t.Errorf("%s devolvió (nil, nil) con su herramienta sustituida por "+
							"un impostor que %s.\n\n"+
							"Eso es indistinguible de «miré y está limpio», así que el "+
							"pipeline lo cuenta como una capa que revisó y el panel pinta un "+
							"✓ verde sobre un cambio que nadie miró.\n\n"+
							"El contrato es: hallazgos, o el porqué. Devolver error NO "+
							"bloquea el commit (§P4): marca la capa como degradada, que es "+
							"exactamente lo que pasó.", nombre, s.describe)
					}
				})
			}
		})
	}
}

// motoresBajoContrato son TODOS los motores que miran un cambio, y no sólo los
// que devuelve Engines().
//
// La diferencia no es cosmética, y por poco se lleva por delante el arreglo más
// importante de la lista: gitleaks NO ESTÁ en Engines(). El pipeline lo recibe
// por un hueco aparte —Options.Secrets— porque es la etapa 1, bloqueante y
// fail-closed, y en el gancho corre antes que todo lo demás y en su mismo
// proceso (cmd/codeguard/hook.go). Así que este archivo decía «los 16 motores»
// y eran 16 de 17: el único que faltaba era justo la compuerta de secretos, que
// es la que más daño hace cuando calla.
//
// Un motor fuera del arnés no está «casi cubierto»: está sin cubrir, y encima
// con la apariencia contraria, que es peor que no tener arnés. Por eso no basta
// con sumarlo aquí a mano — lo vigila TestElContratoNoDejaMotoresFuera.
func motoresBajoContrato(cfg *config.Config, cache engines.Cache) []engines.Engine {
	// Mode "staged" es como lo construye el gancho, que es el camino que de
	// verdad decide si un secreto sale del portátil. No lleva caché: la etapa 1
	// no cachea NADA a propósito —un secreto no se da por revisado por haberlo
	// revisado antes— y por eso su constructor no tiene ese campo.
	return append(Engines(cfg, false, cache), &gitleaks.Engine{Mode: "staged"})
}

// TestElContratoNoDejaMotoresFuera es el guardián de la lista de arriba.
//
// Sumar gitleaks a mano arregla el agujero de hoy y no impide el de mañana: la
// forma en que se colaba era, precisamente, no estar en la lista que el arnés
// recorre. Así que este test no confía en ninguna lista: recorre el árbol,
// busca todo tipo que TENGA FORMA DE MOTOR (declara Name, Applies y Run) y
// exige que esté bajo contrato o exento, con el nombre del paquete en el error.
//
// No comprueba la interfaz con el compilador a propósito. Un tipo que implementa
// engines.Engine pero al que nadie construye no analiza nada, y uno construido a
// mano en otro paquete —el caso de gitleaks— no aparece en ninguna lista. La
// forma es lo que se puede ver sin ejecutar nada, y es lo que se le escapó.
func TestElContratoNoDejaMotoresFuera(t *testing.T) {
	cubiertos := map[string]bool{}
	for _, motor := range motoresBajoContrato(nil, nil) {
		ty := reflect.TypeOf(motor)
		for ty.Kind() == reflect.Pointer {
			ty = ty.Elem()
		}
		cubiertos[ty.PkgPath()+"."+ty.Name()] = true
	}

	for _, tipo := range tiposConFormaDeMotor(t) {
		if cubiertos[tipo] {
			continue
		}
		t.Errorf("%s tiene forma de motor (Name + Applies + Run) y NO pasa por el "+
			"contrato.\n\n"+
			"Mientras esté fuera, puede devolver (nil, nil) sin haber mirado y nadie "+
			"se enterará: es exactamente así como la compuerta de secretos se quedó "+
			"sin arnés mientras este archivo decía cubrir «los 16 motores».\n\n"+
			"Añádelo a motoresBajoContrato con la config que necesite para aplicar, o "+
			"a exentosDelContrato con el motivo escrito.", tipo)
	}
}

// tiposConFormaDeMotor recorre el módulo entero —no sólo internal/engines— y
// devuelve "rutaDeImportación.Tipo" de cada tipo que declara los tres métodos.
//
// El módulo entero porque la lección del día es que un motor puede vivir donde
// quiera y llegar al análisis por un camino propio. Se salta los _test.go: un
// doble de pruebas tiene forma de motor y no analiza nada de nadie.
func tiposConFormaDeMotor(t *testing.T) []string {
	t.Helper()
	raiz, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// Los tres métodos de engines.Engine, por tipo.
	metodos := map[string]map[string]bool{}
	fset := token.NewFileSet()

	err = filepath.Walk(raiz, func(ruta string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch nombre := info.Name(); {
			case ruta == raiz:
				return nil
			// vendor va en la lista aunque hoy no exista: un `go mod vendor` es
			// un comando de una línea, y un tipo de terceros con Name+Applies+Run
			// (nada exótico en librerías de análisis) haría fallar al guardián
			// señalando código que no es nuestro. El contrato obliga a los
			// motores que escribe este repo.
			case strings.HasPrefix(nombre, "."), nombre == "node_modules",
				nombre == "testdata", nombre == "dist", nombre == "sitio",
				nombre == "remediacion", nombre == "rulepacks",
				nombre == "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(ruta, ".go") || strings.HasSuffix(ruta, "_test.go") {
			return nil
		}
		archivo, err := parser.ParseFile(fset, ruta, nil, 0)
		if err != nil {
			// Un .go que no parsea es problema de otro test; aquí callar sería
			// dejar de vigilar el paquete entero sin decirlo.
			t.Errorf("no pude leer %s para vigilar el contrato: %v", ruta, err)
			return nil
		}
		rel, err := filepath.Rel(raiz, filepath.Dir(ruta))
		if err != nil {
			return err
		}
		paquete := "codeguard"
		if rel != "." {
			paquete += "/" + filepath.ToSlash(rel)
		}
		for _, decl := range archivo.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			switch fn.Name.Name {
			case "Name", "Applies", "Run":
			default:
				continue
			}
			receptor := fn.Recv.List[0].Type
			if estrella, ok := receptor.(*ast.StarExpr); ok {
				receptor = estrella.X
			}
			ident, ok := receptor.(*ast.Ident)
			if !ok {
				continue // genéricos y demás: no hay motores así
			}
			clave := paquete + "." + ident.Name
			if metodos[clave] == nil {
				metodos[clave] = map[string]bool{}
			}
			metodos[clave][fn.Name.Name] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var motores []string
	for clave, m := range metodos {
		if m["Name"] && m["Applies"] && m["Run"] {
			motores = append(motores, clave)
		}
	}
	// Ordenado para que el fallo sea siempre el mismo y no baile entre corridas.
	sort.Strings(motores)
	if len(motores) == 0 {
		t.Fatal("no encontré NI UN tipo con forma de motor en todo el módulo, así que " +
			"este guardián no está vigilando nada. Se habrá movido el árbol bajo sus pies.")
	}
	return motores
}

// señuelos crea un directorio con impostores de todas las herramientas que
// invocan los motores, y devuelve su ruta para ponerla ANTES en el PATH.
//
// Cada impostor reproduce el fallo que de verdad ocurrió: imprime algo que el
// parser no entiende y sale con 1. No es una avería inventada — es literalmente
// lo que hacía `npx --no-install tsc` en la máquina de Héctor, donde resolvía a
// un paquete de npm que no es TypeScript:
//
//	This is not the tsc command you are looking for
//
// La lista son los ejecutables que los motores pasan a exec, leídos uno por uno
// de su código. Si un motor invoca algo que no está aquí, encontrará el binario
// de verdad, correrá bien y la prueba pasará por la razón equivocada — por eso
// el control de arriba (Applies) y la mutación de abajo son obligatorios.
// sabotaje es una forma de que la herramienta esté rota. Son tres porque tres
// son los modos que se han visto de verdad, y cada uno caza motores distintos:
// el agente que midió en paralelo encontró 8 violadores, y NINGUNO cae con el
// primero.
type sabotaje struct {
	nombre   string
	describe string
	guion    string
}

var sabotajes = []sabotaje{
	{
		// El de tsc: `npx --no-install tsc` resolviendo a un paquete de npm que
		// no es TypeScript. Imprime un banner y sale con 1.
		"basura-y-error", "escribe algo que el parser no entiende y sale con 1",
		"@echo off\r\necho Esta no es la herramienta que buscas\r\nexit /b 1\r\n",
	},
	{
		// Código 1 sin una palabra. Para casi todos los linters el 1 significa
		// "encontré algo" — y entonces lo habrían escrito. Callar y salir con 1
		// sólo puede ser avería.
		"mudo-y-error", "sale con 1 sin escribir nada",
		"@echo off\r\nexit /b 1\r\n",
	},
	{
		// El más difícil y el más peligroso: la herramienta EQUIVOCADA que cree
		// haber terminado bien. Sale con 0 y calla, que para muchos motores es
		// la señal legítima de "está limpio". Aquí no sirve mirar el código de
		// salida: hay que comprobar que lo que corrió es lo que se pedía.
		"mudo-y-exito", "sale con 0 sin escribir nada, como si todo estuviera bien",
		"@echo off\r\nexit /b 0\r\n",
	},
	{
		// EL IMPOSTOR CON CREDENCIALES, y lo pidió una mutación que sobrevivió.
		//
		// Los tres de arriba no saben decir su nombre, así que a los motores que
		// comprueban la identidad les basta con preguntar. Eso hacía que la otra
		// mitad de su arreglo —la regla del código de salida— no la ejercitara
		// NADIE: quité la guarda del código 1 de mypy a propósito y los tres
		// sabotajes siguieron pasando.
		//
		// Y no es un hueco teórico: la herramienta que dice ser quien es y sale
		// con 1 sin escribir un diagnóstico es EL MYPY DE VERDAD averiado. Un
		// mypy real que anuncia errores y no los escribe pasa cualquier prueba de
		// identidad, porque ES mypy.
		//
		// Este impostor responde a cualquier pregunta que lleve "version" con su
		// propio nombre y un número —"mypy 9.9.9 (v9.9.9)"—, así que la identidad
		// le sale bien. Y para el análisis sale con 1 y calla. Sólo hay una forma
		// de cazarlo: la regla de que anunciar hallazgos y no escribirlos es
		// avería.
		"dice-su-nombre-y-error", "dice ser la herramienta correcta y luego sale con 1 sin escribir nada",
		"@echo off\r\n" +
			"echo %* | findstr /i \"version\" >nul\r\n" +
			"if not errorlevel 1 (\r\n" +
			"  echo %~n0 9.9.9 ^(v9.9.9^)\r\n" +
			"  exit /b 0\r\n" +
			")\r\n" +
			"exit /b 1\r\n",
	},
}

func señuelos(t *testing.T, s sabotaje) string {
	t.Helper()
	dir := t.TempDir()
	// El .cmd es lo que resuelve exec.LookPath en Windows por PATHEXT.
	guion := s.guion
	for _, bin := range []string{
		"npx", "node", // tsc y eslint
		"mypy", "ruff", "semgrep", "squawk", // python
		"go", "staticcheck", "govulncheck", // go
		"trivy", "gitleaks", // seguridad
		"dotnet",        // los tres de .NET
		"java", "javac", // google-java-format y pmd
		"tsc", "eslint",
	} {
		ruta := filepath.Join(dir, bin+".cmd")
		if err := os.WriteFile(ruta, []byte(guion), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// exentosDelContrato son los motores que PUEDEN devolver (nil, nil) sin mentir,
// con el motivo escrito.
//
// Es un mapa a mano y esa es su gracia: añadir un motor obliga a decidir si
// entra aquí, y a justificarlo por escrito. La deuda de mantenerlo la cobra
// TestCadaMotorDecideSiEstaExento, que se pone rojo si alguien añade un motor y
// no toma la decisión.
//
// La barra para entrar es alta: no basta con que el motor «parezca» que no
// lanza procesos. Tiene que ser imposible que falle en silencio.
var exentosDelContrato = map[string]string{
	"gofmt": "no lanza ningún proceso: formatea con go/format dentro de este mismo " +
		"binario (ver internal/engines/linters/gofmt.go). No hay herramienta externa que " +
		"pueda faltar, así que sustituirle nada en el PATH no cambia lo que hace, y estos " +
		"sabotajes no pueden decir nada sobre él.\n\n" +
		"Exento de ESTA prueba, no del contrato. Su forma de mentir no es «la herramienta " +
		"no corrió» sino «este archivo del cambio no lo miró nadie», y tenía dos: un " +
		"archivo ilegible y uno que no parsea como Go, los dos saltados con un `continue` " +
		"mudo. El primero ya devuelve el porqué (salvo si el archivo se borró entre el diff " +
		"y el análisis, que sí es silencio legítimo).\n\n" +
		"Lo que queda abierto a propósito: un .go que no parsea se sigue saltando en " +
		"silencio, porque el compilador y govet lo señalan con un mensaje mucho mejor que " +
		"«no pude formatearlo». El hueco es el repo SIN go.mod, donde govet no aplica y " +
		"nadie lo dice. Está anotado aquí y no arreglado: duplicar el error en cada repo " +
		"con go.mod para cubrir el que no lo tiene sale peor.",
}

// Añadir un motor a Engines() obliga a decidir si respeta el contrato o si está
// exento. Lo que no se puede es no decidir: un motor nuevo que se cuele sin
// pasar por aquí traería consigo la clase de fallo que este archivo retira.
func TestCadaMotorDecideSiEstaExento(t *testing.T) {
	vivos := map[string]bool{}
	for _, motor := range motoresBajoContrato(nil, nil) {
		vivos[motor.Name()] = true
	}
	for nombre := range exentosDelContrato {
		if !vivos[nombre] {
			t.Errorf("%q está exento del contrato y ya no existe en Engines(): "+
				"la exención sobra y hace creer que algo está decidido cuando no hay nada "+
				"que decidir", nombre)
		}
	}
	if len(exentosDelContrato) > 3 {
		t.Errorf("hay %d motores exentos del contrato. La exención es la puerta por la "+
			"que vuelve el fallo: si crece, deja de ser una excepción justificada y pasa a "+
			"ser el comportamiento por defecto con otro nombre.", len(exentosDelContrato))
	}
}

// fixturePoliglota es un repo con material de TODOS los motores.
//
// Uno solo y no uno por motor: el contrato es del conjunto, y con dieciséis
// fixtures separados sería fácil que uno se quedara viejo sin que nadie lo
// notara. Aquí, si a un motor le falta su material, el control de arriba lo
// dice por su nombre.
func fixturePoliglota(t *testing.T) string {
	t.Helper()
	raiz := t.TempDir()
	for rel, contenido := range map[string]string{
		// Go: gofmt, govet, staticcheck, govulncheck
		"go.mod":          "module fixture\n\ngo 1.26\n",
		"go.sum":          "",
		"cmd/api/main.go": "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hola\") }\n",
		// Python: ruff, mypy
		"mypy.ini":         "[mypy]\nstrict = True\n",
		"pyproject.toml":   "[tool.mypy]\nstrict = true\n",
		"worker/tarea.py":  "def f(n):\n    return n\n",
		"requirements.txt": "requests==2.31.0\n",
		// TypeScript/JS: tsc, eslint
		"web/tsconfig.json":    `{"compilerOptions":{"strict":true}}`,
		"web/package.json":     `{"name":"web","devDependencies":{"eslint":"^9","typescript":"^5"}}`,
		"web/eslint.config.js": "export default [];\n",
		"web/src/api.ts":       "export const x: number = 1;\n",
		// SQL: squawk
		"migrations/001_init.sql": "CREATE TABLE t (id int);\n",
		// C#: dotnet-format, dotnet-build, dotnet-vuln
		"src/App/App.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>" +
			"<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>\n",
		"src/App/Program.cs": "class Program { static void Main() { } }\n",
		// Java: google-java-format, pmd
		"java/src/App.java": "class App { public static void main(String[] a) {} }\n",
		"java/pom.xml":      "<project><modelVersion>4.0.0</modelVersion></project>\n",
		// Dependencias: trivy
		"package-lock.json": `{"lockfileVersion":3,"packages":{}}`,
	} {
		abs := filepath.Join(raiz, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return raiz
}

// archivosDe presenta el fixture como un cambio: todos modificados, que es lo
// que hace que a cada motor le toque mirar.
func archivosDe(t *testing.T, raiz string) []gitdiff.ChangedFile {
	t.Helper()
	var out []gitdiff.ChangedFile
	err := filepath.Walk(raiz, func(ruta string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(raiz, ruta)
		if err != nil {
			return err
		}
		out = append(out, gitdiff.ChangedFile{Path: filepath.ToSlash(rel), Status: "M"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
