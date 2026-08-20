package linters

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// Todas las capturas de este archivo son salida REAL de PMD 7.26.0 sobre el JDK
// 21.0.12 en Windows. La invocación exacta con la que se obtuvieron —la misma
// que arma correrPMD— es:
//
//	java -cp "<pmd-home>\lib\*" net.sourceforge.pmd.cli.PmdCli check -f json \
//	     -R rulesets/java/quickstart.xml --no-progress --no-cache -d <archivo>
//
// ejecutada con el directorio de trabajo en backend/ (de ahí que las rutas
// vuelvan RELATIVAS y con la barra invertida de Windows).

// Archivo de juguete que dispara las tres prioridades que importan: una regla de
// prioridad 1 (nombre de método), una de 2 (null check roto) y varias de 3.
const fuenteJavaConProblemas = `package com.ejemplo;

import java.util.ArrayList;
import java.util.List;

public class ConProblemas {

  public int contar(List<String> entradas) {
    int total = 0;
    for (int i = 0; i < entradas.size(); i++) {
      String s = entradas.get(i);
      if (s == null) {
        continue;
      }
      total = total + 1;
    }
    return total;
  }

  public void guardar(String ruta) {
    try {
      List<String> lista = new ArrayList<String>();
      lista.add(ruta);
    } catch (Exception e) {
      // se traga la excepcion a proposito
    }
  }

  public boolean esVacio(String s) {
    if (s == null || s.length() == 0) {
      return true;
    } else {
      return false;
    }
  }

  public boolean EsNombreValido(String s) {
    if (s == null && s.length() > 3) {
      return true;
    }
    return false;
  }
}
`

// Salida literal sobre ese archivo, código de salida 4 (= encontró violaciones).
// Seis violaciones con prioridades 1, 2 y 3 mezcladas, y las comillas simples
// escapadas como \u0027 tal cual las manda el renderer JSON de PMD.
const salidaPMDViolaciones = `{
  "formatVersion": 0,
  "pmdVersion": "7.26.0",
  "timestamp": "2026-08-12T16:41:11.056-06:00",
  "files": [
    {
      "filename": "src\\main\\java\\com\\ejemplo\\ConProblemas.java",
      "violations": [
        {
          "beginline": 10,
          "begincolumn": 5,
          "endline": 16,
          "endcolumn": 6,
          "description": "This for loop can be replaced by a foreach loop",
          "rule": "ForLoopCanBeForeach",
          "ruleset": "Best Practices",
          "priority": 3,
          "externalInfoUrl": "https://docs.pmd-code.org/snapshot/pmd_rules_java_bestpractices.html#forloopcanbeforeach"
        },
        {
          "beginline": 24,
          "begincolumn": 7,
          "endline": 26,
          "endcolumn": 6,
          "description": "Avoid empty catch blocks",
          "rule": "EmptyCatchBlock",
          "ruleset": "Error Prone",
          "priority": 3,
          "externalInfoUrl": "https://docs.pmd-code.org/snapshot/pmd_rules_java_errorprone.html#emptycatchblock"
        },
        {
          "beginline": 30,
          "begincolumn": 5,
          "endline": 34,
          "endcolumn": 6,
          "description": "This if statement can be replaced by ` + "`" + `return {condition};` + "`" + `",
          "rule": "SimplifyBooleanReturns",
          "ruleset": "Design",
          "priority": 3,
          "externalInfoUrl": "https://docs.pmd-code.org/snapshot/pmd_rules_java_design.html#simplifybooleanreturns"
        },
        {
          "beginline": 37,
          "begincolumn": 18,
          "endline": 37,
          "endcolumn": 32,
          "description": "The instance method name \u0027EsNombreValido\u0027 doesn\u0027t match \u0027[a-z][a-zA-Z0-9]*\u0027",
          "rule": "MethodNamingConventions",
          "ruleset": "Code Style",
          "priority": 1,
          "externalInfoUrl": "https://docs.pmd-code.org/snapshot/pmd_rules_java_codestyle.html#methodnamingconventions"
        },
        {
          "beginline": 38,
          "begincolumn": 5,
          "endline": 40,
          "endcolumn": 6,
          "description": "This if statement can be replaced by ` + "`" + `return {condition};` + "`" + `",
          "rule": "SimplifyBooleanReturns",
          "ruleset": "Design",
          "priority": 3,
          "externalInfoUrl": "https://docs.pmd-code.org/snapshot/pmd_rules_java_design.html#simplifybooleanreturns"
        },
        {
          "beginline": 38,
          "begincolumn": 22,
          "endline": 38,
          "endcolumn": 32,
          "description": "Dereferencing the qualifier of this expression will throw a NullPointerException",
          "rule": "BrokenNullCheck",
          "ruleset": "Error Prone",
          "priority": 2,
          "externalInfoUrl": "https://docs.pmd-code.org/snapshot/pmd_rules_java_errorprone.html#brokennullcheck"
        }
      ]
    }
  ],
  "suppressedViolations": [],
  "processingErrors": [],
  "configurationErrors": []
}`

// Archivo limpio: código de salida 0 y "files" VACÍO. Es la salida que hay que
// saber distinguir de la de un archivo inexistente, que trae exactamente este
// mismo JSON pero con código 1 — de ahí que el código de salida mande.
const salidaPMDLimpia = `{
  "formatVersion": 0,
  "pmdVersion": "7.26.0",
  "timestamp": "2026-08-12T16:41:49.434-06:00",
  "files": [],
  "suppressedViolations": [],
  "processingErrors": [],
  "configurationErrors": []
}`

// Archivo que no parsea: código de salida 5. El JSON sigue siendo válido y el
// detalle va en processingErrors. Del campo "detail" se ha recortado el stack
// trace de veinte líneas que trae de verdad — el motor no lo lee.
const salidaPMDErrorDeProceso = `{
  "formatVersion": 0,
  "pmdVersion": "7.26.0",
  "timestamp": "2026-08-12T16:41:52.064-06:00",
  "files": [],
  "suppressedViolations": [],
  "processingErrors": [
    {
      "filename": "Roto.java",
      "message": "ParseException: Parse exception in file \u0027Roto.java\u0027 at line 4, column 17: Encountered \"{\".\r\nWas expecting:\r\n    \")\" ...",
      "detail": "net.sourceforge.pmd.lang.ast.ParseException: Parse exception in file \u0027Roto.java\u0027 at line 4, column 17: Encountered \"{\".\r\n\tat net.sourceforge.pmd.lang.java.ast.JavaParserImpl.generateParseException(JavaParserImpl.java:14981)\r\n"
    }
  ],
  "configurationErrors": []
}`

// ── parseo de las violaciones ───────────────────────────────────────────────

func TestHallazgosPMDMapeaPrioridadesDesdeLaCapturaReal(t *testing.T) {
	fs, err := hallazgosPMD(`C:\repos\demo`, "backend", []byte(salidaPMDViolaciones))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 6 {
		t.Fatalf("esperaba 6 hallazgos, obtuve %d", len(fs))
	}
	for _, f := range fs {
		if f.Engine != "pmd" {
			t.Errorf("Engine = %q", f.Engine)
		}
		if f.File != "backend/src/main/java/com/ejemplo/ConProblemas.java" {
			t.Errorf("File = %q; debe venir relativa al repo, con / y con el proyecto delante", f.File)
		}
		if f.Pillar != finding.Quality || !f.Verified || f.Source != finding.Deterministic {
			t.Errorf("%s: pilar/verified/source mal puestos: %+v", f.RuleKey, f)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: sin fingerprint", f.RuleKey)
		}
		// El porqué tiene que dejar claro que esto no es un parecido textual.
		if !strings.Contains(f.Why, "AST") {
			t.Errorf("%s: el Why debe explicar que es análisis del AST: %q", f.RuleKey, f.Why)
		}
	}

	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
	}

	// Prioridad 1 y 2 → error que BLOQUEA (§7, como el lint de severidad error).
	for _, regla := range []string{"MethodNamingConventions", "BrokenNullCheck"} {
		f, ok := porRegla[regla]
		if !ok {
			t.Fatalf("falta el hallazgo de %s", regla)
		}
		if f.Severity != finding.Error || !f.Blocking {
			t.Errorf("%s: severity=%q blocking=%v; prioridad 1-2 debe bloquear", regla, f.Severity, f.Blocking)
		}
	}
	// Prioridad 3 → aviso que NO bloquea: en código existente hay cientos y
	// bloquear por ellas haría el hook inusable el primer día.
	for _, regla := range []string{"ForLoopCanBeForeach", "EmptyCatchBlock", "SimplifyBooleanReturns"} {
		f, ok := porRegla[regla]
		if !ok {
			t.Fatalf("falta el hallazgo de %s", regla)
		}
		if f.Severity != finding.Warning || f.Blocking {
			t.Errorf("%s: severity=%q blocking=%v; prioridad 3 avisa y no bloquea", regla, f.Severity, f.Blocking)
		}
	}

	// La posición viene del payload, con el rango completo.
	if f := porRegla["ForLoopCanBeForeach"]; f.Line != 10 || f.EndLine != 16 {
		t.Errorf("ForLoopCanBeForeach: line=%d endLine=%d, esperaba 10/16", f.Line, f.EndLine)
	}
	// RuleKey ES el nombre de la regla: es lo que el dev busca o silencia.
	if _, ok := porRegla["BrokenNullCheck"]; !ok {
		t.Error("la RuleKey debe ser el nombre de la regla de PMD")
	}
	// Y el consejo apunta a la ficha, que trae el ejemplo bueno y el malo.
	if fh := porRegla["BrokenNullCheck"].FixHint; !strings.Contains(fh, "pmd_rules_java_errorprone.html#brokennullcheck") {
		t.Errorf("el FixHint debe llevar la ficha de la regla, dice %q", fh)
	}
}

// Dos violaciones distintas de la MISMA regla en el mismo archivo no pueden
// colapsar en un solo fingerprint: el payload real trae dos
// SimplifyBooleanReturns (líneas 30 y 38).
func TestHallazgosPMDNoColapsaDosViolacionesDeLaMismaRegla(t *testing.T) {
	fs, err := hallazgosPMD(`C:\repos\demo`, ".", []byte(salidaPMDViolaciones))
	if err != nil {
		t.Fatal(err)
	}
	var lineas []int
	for _, f := range fs {
		if f.RuleKey == "SimplifyBooleanReturns" {
			lineas = append(lineas, f.Line)
		}
	}
	if len(lineas) != 2 {
		t.Fatalf("esperaba las 2 violaciones de SimplifyBooleanReturns, obtuve %v", lineas)
	}
}

func TestHallazgosPMDArchivoLimpioNoInventaNada(t *testing.T) {
	fs, err := hallazgosPMD(`C:\repos\demo`, ".", []byte(salidaPMDLimpia))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("un informe sin archivos no puede producir hallazgos: %+v", fs)
	}
}

// Un .java que no parsea NO se calla: PMD es el único motor de este producto que
// mira la sintaxis de Java (no hay compuerta de compilación como tsc o dotnet
// build), así que ignorarlo dejaría pasar un archivo roto con el informe en
// verde. Pero tampoco degrada el motor entero: los demás archivos sí se
// analizaron.
func TestHallazgosPMDReportaElArchivoQueNoPudoAnalizar(t *testing.T) {
	fs, err := hallazgosPMD(`C:\repos\demo`, "backend", []byte(salidaPMDErrorDeProceso))
	if err != nil {
		t.Fatalf("un archivo ilegible no debe degradar el motor entero: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo por el archivo sin analizar, obtuve %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleKey != "processing-error" {
		t.Errorf("RuleKey = %q", f.RuleKey)
	}
	if f.File != "backend/Roto.java" {
		t.Errorf("File = %q", f.File)
	}
	if !f.Blocking || f.Severity != finding.Error {
		t.Errorf("un archivo sin analizar debe bloquear: %+v", f)
	}
	if !strings.Contains(f.Message, "line 4, column 17") {
		t.Errorf("el mensaje debe conservar la posición que da el parser: %q", f.Message)
	}
	// El stack trace de veinte líneas no entra en el informe.
	if strings.Contains(f.Message, "JavaParserImpl.java") {
		t.Errorf("el volcado del parser no cabe en una línea del informe: %q", f.Message)
	}
	if !strings.Contains(f.Why, "SIN revisar") {
		t.Errorf("el Why tiene que decir que el archivo quedó sin revisar: %q", f.Why)
	}
}

func TestSeveridadPMDCubreLasCincoPrioridades(t *testing.T) {
	casos := map[int]struct {
		sev     finding.Severity
		bloquea bool
	}{
		1: {finding.Error, true},
		2: {finding.Error, true},
		3: {finding.Warning, false},
		4: {finding.Warning, false},
		5: {finding.Warning, false},
	}
	for p, esperado := range casos {
		sev, bloquea := severidadPMD(p)
		if sev != esperado.sev || bloquea != esperado.bloquea {
			t.Errorf("prioridad %d → %q/%v, esperaba %q/%v", p, sev, bloquea, esperado.sev, esperado.bloquea)
		}
	}
}

// Un error de configuración es NUESTRO —las reglas que le pasamos no cargaron—,
// así que NADA de lo que diga el informe es cobertura completa y la capa se
// declara degradada entera.
//
// Aviso honesto: este payload es el ÚNICO de este archivo que no es una captura.
// No se consiguió provocar un configurationError con PMD 7.26.0: un ruleset
// inexistente o con una propiedad inválida sale con código 1 y sin stdout (que
// el motor ya corta por el código de salida). El campo existe y viene vacío en
// todas las capturas reales, así que la FORMA sí está verificada; lo que se
// inventa es el contenido, para poder probar el corte.
const salidaPMDErrorDeConfiguracion = `{
  "formatVersion": 0,
  "pmdVersion": "7.26.0",
  "files": [],
  "suppressedViolations": [],
  "processingErrors": [],
  "configurationErrors": [
    { "rule": "UnusedPrivateMethod", "message": "This rule is for Java only" }
  ]
}`

func TestHallazgosPMDDegradaSiSusReglasNoCargaron(t *testing.T) {
	fs, err := hallazgosPMD(`C:\repos\demo`, ".", []byte(salidaPMDErrorDeConfiguracion))
	if err == nil {
		t.Fatal("un error de configuración debe degradar la capa, no devolver hallazgos")
	}
	if len(fs) != 0 {
		t.Errorf("una degradación no puede traer hallazgos, trajo %d", len(fs))
	}
	if !strings.Contains(err.Error(), "UnusedPrivateMethod") {
		t.Errorf("el error debe decir qué regla falló: %v", err)
	}
}

func TestHallazgosPMDSalidaIlegibleNoSeTragaEnSilencio(t *testing.T) {
	if _, err := hallazgosPMD(`C:\repos\demo`, ".", []byte("esto no es JSON")); err == nil {
		t.Fatal("un JSON ilegible tiene que degradar la capa, no pasar por limpio")
	}
}

// ── clave de caché ──────────────────────────────────────────────────────────

// La versión y el conjunto de reglas van DENTRO de la clave: actualizar PMD
// cambia los hallazgos sin tocar una línea de código, y servir la entrada
// guardada sería reportar las reglas de ayer.
func TestClaveJavaLintDistingueVersiones(t *testing.T) {
	a := claveJavaLint("7.26.0", "abc")
	b := claveJavaLint("7.27.0", "abc")
	if a == b {
		t.Error("dos versiones de PMD sobre el mismo contenido no pueden compartir clave")
	}
	if !strings.Contains(a, pmdRuleset) {
		t.Errorf("la clave debe llevar el conjunto de reglas: %q", a)
	}
}

func TestClaveJavaFmtDistingueVersiones(t *testing.T) {
	if claveJavaFmt("1.36.1", "abc") == claveJavaFmt("1.37.0", "abc") {
		t.Error("dos versiones de google-java-format no pueden compartir clave")
	}
}

// ── Applies ─────────────────────────────────────────────────────────────────

func TestJavaLintNoAplicaSinArchivosJava(t *testing.T) {
	raiz := t.TempDir()
	e := JavaLint{}
	if e.Applies(engines.Input{RepoRoot: raiz, Files: archivosJava("src/App.py", "pom.xml")}) {
		t.Error("sin .java tocados el motor no debe aplicar")
	}
	if !e.Applies(engines.Input{RepoRoot: raiz, Files: archivosJava("src/A.java")}) {
		t.Error("con un .java tocado el motor debe aplicar")
	}
}

// La ausencia de PMD se simula redefiniendo LOCALAPPDATA, y eso vale porque
// `Run` resuelve la herramienta ANTES de mirar java (javalint.go:110): el error
// que sale es el de PMD aunque la máquina no tenga JVM, así que la prueba mide
// lo que dice medir incluso donde los tests de integración se saltan.
func TestJavaLintSinHerramientaNoDiceQueEstaLimpio(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	raiz := t.TempDir()
	escribir(t, raiz, "src/A.java", fuenteJavaLimpio)

	hallazgos, err := JavaLint{}.Run(context.Background(), engines.Input{RepoRoot: raiz, Files: archivosJava("src/A.java")})
	if err == nil {
		t.Fatalf("sin PMD instalado debe fallar, devolvió %d hallazgos", len(hallazgos))
	}
	// Y no vale cualquier error: javalint.go promete en su línea 108 que envuelve
	// fs.ErrNotExist, y de ese centinela depende que el orquestador lo etiquete
	// «falta: pmd» —configuración, que el usuario puede arreglar— en vez de
	// declarar el análisis degradado. Es el mismo errors.Is que usa el propio
	// motor para decidir (javalint.go:125). Sin comprobarlo, el día que el error
	// deje de envolverlo el mensaje cambia de sentido y esta prueba sigue verde.
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("el error debe envolver fs.ErrNotExist para que salga como «falta: pmd» "+
			"y no como capa degradada: %v", err)
	}
	if len(hallazgos) != 0 {
		t.Errorf("una degradación no puede traer hallazgos, trajo %d", len(hallazgos))
	}
}

// ── integración con el binario real ─────────────────────────────────────────

func javaYPMDInstalados(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("sin java en el PATH de esta máquina")
	}
	if _, _, err := herramientaJava(pmdHomePatron, pmdHomePrefijo, pmdHomeSufijo); err != nil {
		t.Skipf("PMD no está instalado en %s", dirMotores())
	}
}

func TestIntegracionJavaLintEncuentraLasViolacionesReales(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYPMDInstalados(t)
	raiz := proyectoJavaDeJuguete(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	fs, err := JavaLint{}.Run(ctx, engines.Input{RepoRoot: raiz, Files: archivosJava(
		"backend/src/main/java/com/ejemplo/ConProblemas.java",
		"backend/src/main/java/com/ejemplo/Limpio.java",
	)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
		if f.File != "backend/src/main/java/com/ejemplo/ConProblemas.java" {
			t.Errorf("el archivo limpio no puede tener hallazgos: %+v", f)
		}
	}
	// Una bloqueante y una que sólo avisa: es el mapeo completo, extremo a
	// extremo, con el binario real.
	bloqueante, ok := porRegla["BrokenNullCheck"]
	if !ok {
		t.Fatalf("esperaba BrokenNullCheck (prioridad 2); hallazgos: %v", reglasDe(fs))
	}
	if !bloqueante.Blocking {
		t.Errorf("BrokenNullCheck es prioridad 2 y debe bloquear: %+v", bloqueante)
	}
	aviso, ok := porRegla["EmptyCatchBlock"]
	if !ok {
		t.Fatalf("esperaba EmptyCatchBlock (prioridad 3); hallazgos: %v", reglasDe(fs))
	}
	if aviso.Blocking {
		t.Errorf("EmptyCatchBlock es prioridad 3 y no debe bloquear: %+v", aviso)
	}
}

// El caso peligroso, medido: con un archivo inexistente PMD sale con 1 y escribe
// un JSON PERFECTAMENTE VÁLIDO con "files": []. Tomarlo por "limpio" sería la
// mentira que este proyecto persigue. Aquí el motor lo filtra antes de invocar,
// así que el resultado tiene que ser un análisis correcto de lo que SÍ existe.
func TestIntegracionJavaLintSobreviveAUnArchivoQueYaNoEsta(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYPMDInstalados(t)
	raiz := t.TempDir()
	escribir(t, raiz, "src/main/java/com/ejemplo/ConProblemas.java", fuenteJavaConProblemas)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	fs, err := JavaLint{}.Run(ctx, engines.Input{RepoRoot: raiz, Files: archivosJava(
		"src/main/java/com/ejemplo/ConProblemas.java",
		"src/main/java/com/ejemplo/Fantasma.java",
	)})
	if err != nil {
		t.Fatalf("un archivo desaparecido no debe tumbar el motor: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("el archivo que sí existe tiene violaciones: no puede salir limpio")
	}
}

// Un .java roto tiene que salir en el informe como "no lo pude analizar", no
// como silencio. Se comprueba con PMD de verdad porque el camino entero
// (código de salida 5 + processingErrors) sólo existe al ejecutarlo.
func TestIntegracionJavaLintNoCallaUnArchivoQueNoParsea(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYPMDInstalados(t)
	raiz := t.TempDir()
	escribir(t, raiz, "src/main/java/com/ejemplo/Roto.java",
		"package com.ejemplo;\n\npublic class Roto {\n  public int x( {\n}\n")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	fs, err := JavaLint{}.Run(ctx, engines.Input{RepoRoot: raiz,
		Files: archivosJava("src/main/java/com/ejemplo/Roto.java")})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 || fs[0].RuleKey != "processing-error" {
		t.Fatalf("esperaba un processing-error por el archivo que no parsea, obtuve %v", reglasDe(fs))
	}
	if !fs[0].Blocking {
		t.Error("un archivo que nadie pudo analizar debe bloquear")
	}
}

func reglasDe(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleKey)
	}
	return out
}
