package linters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Todas las capturas de este archivo son salida REAL de las herramientas, no
// payloads inventados: eslint 10.8.1 y 8.57.1, y biome 2.5.8, corridos sobre un
// proyecto de juguete en Windows. Se dejan literales —rutas absolutas con barra
// invertida incluidas— porque cada rareza del formato que contienen es una que
// el parseo tiene que sobrevivir en producción.

// raizESLint es el cwd real desde el que se capturó la salida de eslint. Hace
// falta para comprobar la conversión de rutas: eslint reporta ABSOLUTO.
const raizESLint = `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\toy-eslint`

// eslint 10.8.1: `eslint --format json src/malo.js`, código de salida 1.
// Trae los cuatro casos que importan: error con `fix` (auto-corregible), aviso
// con `suggestions` (que --fix NO aplica), error con suggestions y error pelado.
const salidaESLint10 = `[{"filePath":"C:\\Users\\hector.diaz.BODESA\\AppData\\Local\\Temp\\claude\\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-eslint\\src\\malo.js","messages":[{"ruleId":"prefer-const","severity":2,"message":"'noReasignada' is never reassigned. Use 'const' instead.","line":1,"column":5,"messageId":"useConst","endLine":1,"endColumn":17,"fix":{"range":[0,21],"text":"const noReasignada = 1;"}},{"ruleId":"no-unused-vars","severity":1,"message":"'sinUsar' is assigned a value but never used.","line":4,"column":9,"messageId":"unusedVar","endLine":4,"endColumn":16,"suggestions":[{"messageId":"removeVar","data":{"varName":"sinUsar"},"fix":{"range":[58,77],"text":""},"desc":"Remove unused variable 'sinUsar'."}]},{"ruleId":"eqeqeq","severity":2,"message":"Expected '===' and instead saw '=='.","line":5,"column":9,"messageId":"unexpected","endLine":5,"endColumn":11,"suggestions":[{"messageId":"replaceOperator","data":{"expectedOperator":"===","actualOperator":"=="},"fix":{"range":[86,88],"text":"==="},"desc":"Use '===' instead of '=='."}]},{"ruleId":"no-undef","severity":2,"message":"'desconocida' is not defined.","line":8,"column":10,"messageId":"undef","endLine":8,"endColumn":21}],"suppressedMessages":[],"errorCount":3,"fatalErrorCount":0,"warningCount":1,"fixableErrorCount":1,"fixableWarningCount":0,"source":"let noReasignada = 1;\n\nexport function comparar(a, b) {\n  const sinUsar = 42;\n  if (a == b) {\n    return noReasignada;\n  }\n  return desconocida;\n}\n","usedDeprecatedRules":[]}]`

// eslint 10.8.1 sobre `export const roto = (`: error de parseo. ruleId es null
// y fatal true — de ahí que el campo sea puntero.
const salidaESLintParseo = `[{"filePath":"C:\\Users\\hector.diaz.BODESA\\AppData\\Local\\Temp\\claude\\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-eslint\\src\\roto.js","messages":[{"ruleId":null,"fatal":true,"severity":2,"message":"Parsing error: Unexpected token","line":2,"column":1}],"suppressedMessages":[],"errorCount":1,"fatalErrorCount":1,"warningCount":0,"fixableErrorCount":0,"fixableWarningCount":0,"source":"export const roto = (\n","usedDeprecatedRules":[]}]`

// eslint 10.8.1 al pasarle un .ts a una config que sólo cubre .js, y un archivo
// bajo `ignores`. Los dos casos son ruleId null + fatal ausente, SIN línea, y
// los dos hablan del archivo y no del código: no son hallazgos.
const salidaESLintIgnorados = `[{"filePath":"C:\\Users\\hector.diaz.BODESA\\AppData\\Local\\Temp\\claude\\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-eslint\\src\\tipos.ts","messages":[{"ruleId":null,"fatal":false,"severity":1,"message":"File ignored because no matching configuration was supplied."}],"suppressedMessages":[],"errorCount":0,"warningCount":1,"fatalErrorCount":0,"fixableErrorCount":0,"fixableWarningCount":0,"usedDeprecatedRules":[]},{"filePath":"C:\\Users\\hector.diaz.BODESA\\AppData\\Local\\Temp\\claude\\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-eslint\\dist\\build.js","messages":[{"ruleId":null,"fatal":false,"severity":1,"message":"File ignored because of a matching ignore pattern. Use \"--no-ignore\" to disable file ignore settings or use \"--no-warn-ignored\" to suppress this warning."}],"suppressedMessages":[],"errorCount":0,"warningCount":1,"fatalErrorCount":0,"fixableErrorCount":0,"fixableWarningCount":0,"usedDeprecatedRules":[]}]`

// eslint 8.57.1 con .eslintrc.json heredado. Misma forma que la de eslint 10
// más un `nodeType` que no usamos: un solo struct sirve para las dos mayores,
// que es lo que permite soportar los repos que aún no migraron a flat config.
const salidaESLint8 = `[{"filePath":"C:\\Users\\hector.diaz.BODESA\\AppData\\Local\\Temp\\claude\\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-eslint8\\src\\legacy.js","messages":[{"ruleId":"no-unused-vars","severity":1,"message":"'sinUsar' is assigned a value but never used.","line":1,"column":7,"nodeType":"Identifier","messageId":"unusedVar","endLine":1,"endColumn":14},{"ruleId":"eqeqeq","severity":2,"message":"Expected '===' and instead saw '=='.","line":2,"column":36,"nodeType":"BinaryExpression","messageId":"unexpected","endLine":2,"endColumn":38}],"suppressedMessages":[],"errorCount":1,"fatalErrorCount":0,"warningCount":1,"fixableErrorCount":0,"fixableWarningCount":0,"source":"const sinUsar = 1;\nexport function f(a, b) { return a == b; }\n","usedDeprecatedRules":[]}]`

// biome 2.5.8: `biome check --reporter=json src/malo.ts`, código de salida 1.
// Rutas RELATIVAS con barra invertida, tres warnings del preset recommended,
// un error de regla y el diagnóstico de formato con línea 0.
const salidaBiome = `{"summary":{"changed":0,"unchanged":1,"matches":0,"duration":3396100,"errors":2,"warnings":3,"infos":0,"skipped":0,"suggestedFixesSkipped":0,"diagnosticsNotPrinted":0,"scannerDuration":3618100},"diagnostics":[{"severity":"warning","message":"Unexpected any. Specify a different type.","category":"lint/suspicious/noExplicitAny","location":{"path":"src\\malo.ts","start":{"line":1,"column":29},"end":{"line":1,"column":32}},"advices":[]},{"severity":"warning","message":"Unexpected any. Specify a different type.","category":"lint/suspicious/noExplicitAny","location":{"path":"src\\malo.ts","start":{"line":1,"column":37},"end":{"line":1,"column":40}},"advices":[]},{"severity":"warning","message":"This variable sinUsar is unused.","category":"lint/correctness/noUnusedVariables","location":{"path":"src\\malo.ts","start":{"line":2,"column":11},"end":{"line":2,"column":18}},"advices":[]},{"severity":"error","message":"Using == may be unsafe if you are relying on type coercion.","category":"lint/suspicious/noDoubleEquals","location":{"path":"src\\malo.ts","start":{"line":3,"column":11},"end":{"line":3,"column":13}},"advices":[]},{"severity":"error","message":"Formatter would have printed the following content:","category":"format","location":{"path":"src\\malo.ts","start":{"line":0,"column":0},"end":{"line":0,"column":0}},"advices":[]}],"command":"check"}`

// biome 2.5.8 sobre `let noReasignada = 1`: la corrección no viaja en un campo
// booleano sino en el TEXTO de un advice ("Safe fix: …").
const salidaBiomeFixable = `{"summary":{"changed":0,"unchanged":1,"matches":0,"duration":2758200,"errors":0,"warnings":1,"infos":0,"skipped":0,"suggestedFixesSkipped":0,"diagnosticsNotPrinted":0,"scannerDuration":3238100},"diagnostics":[{"severity":"warning","message":"This let declares a variable that is only assigned once.","category":"lint/style/useConst","location":{"path":"src\\fixable.ts","start":{"line":1,"column":1},"end":{"line":1,"column":4}},"advices":[{"start":{"line":1,"column":5},"end":{"line":1,"column":17},"text":"Safe fix: Use const instead."}]}],"command":"check"}`

// biome 2.5.8 con un archivo que no existe: código de salida 1 y un
// diagnóstico internalError/io con ruta ABSOLUTA y línea 0. Es el caso que no
// se puede confundir con un hallazgo — biome no analizó nada.
const salidaBiomeInternalError = `{"summary":{"changed":0,"unchanged":0,"matches":0,"duration":112900,"errors":0,"warnings":0,"infos":0,"skipped":0,"suggestedFixesSkipped":0,"diagnosticsNotPrinted":0,"scannerDuration":1907600},"diagnostics":[{"severity":"error","message":"The system cannot find the file specified. (os error 2)","category":"internalError/io","location":{"path":"C:\\Users\\hector.diaz.BODESA\\AppData\\Local\\Temp\\claude\\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-biome\\src\\no-existe.ts","start":{"line":0,"column":0},"end":{"line":0,"column":0}},"advices":[]}],"command":"check"}`

// Forma de biome 2.x —path como objeto, mensaje troceado, span de bytes y el
// código fuente adjunto— con un span NEGATIVO en el desplazamiento inicial.
const salidaBiomeSpanNegativo = `{"summary":{"changed":0,"unchanged":1,"errors":1,"warnings":0},"diagnostics":[{"severity":"error","message":[{"content":"Using "},{"elements":["Emphasis"],"content":"=="},{"content":" may be unsafe."}],"category":"lint/suspicious/noDoubleEquals","location":{"path":{"file":"src\\malo.ts"},"span":[-5,3],"sourceCode":"const a = 1;\nif (a == 2) {}\n"},"advices":[]}],"command":"check"}`

// ── parseo de eslint ────────────────────────────────────────────────────────

func TestHallazgosESLintMapeaSeveridadesYArreglos(t *testing.T) {
	fs, err := hallazgosESLint(raizESLint, ".", []byte(salidaESLint10))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("esperaba 4 hallazgos, obtuve %d", len(fs))
	}
	for _, f := range fs {
		if f.Engine != "eslint" {
			t.Errorf("Engine = %q; el hallazgo debe llevar la herramienta REAL", f.Engine)
		}
		if f.File != "src/malo.js" {
			t.Errorf("File = %q, esperaba src/malo.js (eslint reporta absoluto)", f.File)
		}
		if f.Pillar != finding.Quality || !f.Verified || f.Source != finding.Deterministic {
			t.Errorf("%s: pilar/verified/source mal puestos: %+v", f.RuleKey, f)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: sin fingerprint", f.RuleKey)
		}
		if !strings.Contains(f.Why, "PROPIO REPO") {
			t.Errorf("%s: Why debe dejar claro que la regla es del repo, no nuestra: %q", f.RuleKey, f.Why)
		}
	}

	// severity 2 → error y BLOQUEA (§7, igual que govet); severity 1 → aviso.
	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
	}
	for _, regla := range []string{"prefer-const", "eqeqeq", "no-undef"} {
		f, ok := porRegla[regla]
		if !ok {
			t.Fatalf("falta el hallazgo de %s", regla)
		}
		if f.Severity != finding.Error || !f.Blocking {
			t.Errorf("%s: severity=%q blocking=%v; severidad 2 debe bloquear", regla, f.Severity, f.Blocking)
		}
	}
	aviso := porRegla["no-unused-vars"]
	if aviso.Severity != finding.Warning || aviso.Blocking {
		t.Errorf("no-unused-vars: severity=%q blocking=%v; severidad 1 avisa y NO bloquea", aviso.Severity, aviso.Blocking)
	}

	// Línea y línea final llegan del payload.
	if pc := porRegla["no-undef"]; pc.Line != 8 || pc.EndLine != 8 {
		t.Errorf("no-undef: line=%d endLine=%d, esperaba 8/8", pc.Line, pc.EndLine)
	}

	// `fix` presente = --fix lo arregla. Se promete el comando concreto.
	if fh := porRegla["prefer-const"].FixHint; !strings.Contains(fh, "--fix") || !strings.Contains(fh, "src/malo.js") {
		t.Errorf("prefer-const trae fix: el FixHint debe dar el comando concreto, dice %q", fh)
	}
	// `suggestions` NO las aplica --fix: prometerlo haría que el dev deje de
	// creerse los FixHint cuando vea que no cambia nada. El consejo puede
	// nombrar --fix, pero para decir que NO sirve.
	if fh := porRegla["eqeqeq"].FixHint; !strings.Contains(fh, "a mano") || strings.Contains(fh, "Auto-corregible") {
		t.Errorf("eqeqeq sólo tiene suggestions: el FixHint no debe prometer corrección automática, dice %q", fh)
	}
}

func TestHallazgosESLintErrorDeParseoEsBloqueante(t *testing.T) {
	fs, err := hallazgosESLint(raizESLint, ".", []byte(salidaESLintParseo))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, obtuve %d", len(fs))
	}
	f := fs[0]
	// ruleId null obligaría a una RuleKey vacía, y sin RuleKey el fingerprint
	// colisionaría con cualquier otro hallazgo del mismo archivo.
	if f.RuleKey != "parsing-error" {
		t.Errorf("RuleKey = %q, esperaba parsing-error para el mensaje fatal sin regla", f.RuleKey)
	}
	if f.Severity != finding.Error || !f.Blocking {
		t.Errorf("un error de parseo debe bloquear: severity=%q blocking=%v", f.Severity, f.Blocking)
	}
	if f.Line != 2 || f.File != "src/roto.js" {
		t.Errorf("ubicación mal: %s:%d", f.File, f.Line)
	}
	if !strings.Contains(f.FixHint, "parser") {
		t.Errorf("el consejo debe mencionar el parser como causa alternativa: %q", f.FixHint)
	}
}

// El caso que llenaría el informe de basura: en cuanto se le pasa un .ts a una
// config que sólo cubre .js —lo más normal del mundo— eslint devuelve un aviso
// por archivo. No es un problema del código y no puede aparecer como hallazgo.
// Se filtra al parsear y no con --no-warn-ignored porque eslint 8.57 rechaza
// ese flag y saldría con 2, rompiendo todos los repos que aún no migraron.
func TestHallazgosESLintDescartaAvisosDeArchivoIgnorado(t *testing.T) {
	fs, err := hallazgosESLint(raizESLint, ".", []byte(salidaESLintIgnorados))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("esperaba 0 hallazgos, obtuve %d: %+v", len(fs), fs)
	}
}

func TestHallazgosESLint8LegacySeParseaIgual(t *testing.T) {
	raiz8 := strings.TrimSuffix(raizESLint, "toy-eslint") + "toy-eslint8"
	fs, err := hallazgosESLint(raiz8, ".", []byte(salidaESLint8))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos de eslint 8, obtuve %d", len(fs))
	}
	if fs[0].File != "src/legacy.js" {
		t.Errorf("File = %q, esperaba src/legacy.js", fs[0].File)
	}
	if fs[0].Severity != finding.Warning || fs[1].Severity != finding.Error {
		t.Errorf("severidades mal mapeadas: %q, %q", fs[0].Severity, fs[1].Severity)
	}
}

// En un monorepo eslint sigue devolviendo la ruta ABSOLUTA, así que la
// conversión a relativa-al-repo tiene que salir de ahí y no de concatenar el
// directorio del proyecto: hacer las dos cosas daría "frontend/frontend/src".
func TestHallazgosESLintNoDuplicaElDirectorioDelProyecto(t *testing.T) {
	raizRepo := strings.TrimSuffix(raizESLint, `\toy-eslint`)
	fs, err := hallazgosESLint(raizRepo, "toy-eslint", []byte(salidaESLint10))
	if err != nil {
		t.Fatal(err)
	}
	if fs[0].File != "toy-eslint/src/malo.js" {
		t.Fatalf("File = %q, esperaba toy-eslint/src/malo.js", fs[0].File)
	}
	// El comando del consejo va relativo al proyecto y dice desde dónde: `npx
	// eslint` en la raíz de un monorepo usa otro eslint y otra config.
	if fh := fs[0].FixHint; !strings.Contains(fh, "src/malo.js") || !strings.Contains(fh, "desde toy-eslint/") {
		t.Errorf("el FixHint debe indicar el directorio del proyecto: %q", fh)
	}
}

// ── parseo de biome ─────────────────────────────────────────────────────────

func TestHallazgosBiomeMapeaSeveridadesYFormato(t *testing.T) {
	fs, err := hallazgosBiome(`C:\repo`, "frontend", []byte(salidaBiome))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 5 {
		t.Fatalf("esperaba 5 hallazgos, obtuve %d", len(fs))
	}
	for _, f := range fs {
		if f.Engine != "biome" {
			t.Errorf("Engine = %q; debe ser la herramienta REAL, no el nombre del motor", f.Engine)
		}
		// biome da la ruta relativa a SU cwd y con barra invertida: hay que
		// prefijar el directorio del proyecto y normalizar el separador.
		if f.File != "frontend/src/malo.ts" {
			t.Errorf("File = %q, esperaba frontend/src/malo.ts", f.File)
		}
		if f.Line < 1 {
			t.Errorf("%s: línea %d; un 0 en el informe se lee como 'sin ubicación'", f.RuleKey, f.Line)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: sin fingerprint", f.RuleKey)
		}
	}

	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
	}
	// La RuleKey es la categoría entera de biome: es lo que el dev busca en su
	// documentación y lo que hay que poner en la config para silenciarla.
	dobleIgual, ok := porRegla["lint/suspicious/noDoubleEquals"]
	if !ok {
		t.Fatalf("falta noDoubleEquals; reglas vistas: %v", porRegla)
	}
	if dobleIgual.Severity != finding.Error || !dobleIgual.Blocking {
		t.Errorf("noDoubleEquals es error en biome: debe bloquear (%q, %v)", dobleIgual.Severity, dobleIgual.Blocking)
	}
	// El preset recommended marca varias como warning, y ésas NO paran el commit.
	for _, regla := range []string{"lint/suspicious/noExplicitAny", "lint/correctness/noUnusedVariables"} {
		f := porRegla[regla]
		if f.Severity != finding.Warning || f.Blocking {
			t.Errorf("%s: severity=%q blocking=%v; los warning de biome avisan", regla, f.Severity, f.Blocking)
		}
	}

	// El diagnóstico de formato llega con línea 0 y con un mensaje inservible
	// ("Formatter would have printed the following content:") porque el reporter
	// json deja vacío el advice que traía el contenido.
	form, ok := porRegla["format"]
	if !ok {
		t.Fatal("falta el hallazgo de formato")
	}
	if form.Line != 1 {
		t.Errorf("el hallazgo de formato debe caer en la línea 1, no en la 0 de biome (line=%d)", form.Line)
	}
	if strings.Contains(form.Message, "would have printed") {
		t.Errorf("el mensaje crudo de biome no dice nada útil sin el contenido: %q", form.Message)
	}
	if !form.Blocking || form.Severity != finding.Error {
		t.Errorf("el formato bloquea (§7, como gofmt): severity=%q blocking=%v", form.Severity, form.Blocking)
	}
	if !strings.Contains(form.FixHint, "--write") {
		t.Errorf("el formato es auto-corregible: el consejo debe dar el comando (%q)", form.FixHint)
	}
}

func TestHallazgosBiomeDetectaLaCorreccionSeguraEnLosAdvices(t *testing.T) {
	fs, err := hallazgosBiome(`C:\repo`, ".", []byte(salidaBiomeFixable))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, obtuve %d", len(fs))
	}
	fh := fs[0].FixHint
	if !strings.Contains(fh, "biome check --write") || !strings.Contains(fh, "Safe fix") {
		t.Errorf("biome no tiene campo 'fixable': la corrección se lee del texto del advice; FixHint = %q", fh)
	}
	if strings.Contains(fh, "--unsafe") {
		t.Errorf("es una corrección SEGURA: no debe pedir --unsafe (%q)", fh)
	}
}

// Un internalError es "no pude mirar", no "no hay nada". Contarlo como hallazgo
// le inventaría al dev un problema en su código; ignorarlo presentaría el
// análisis como completo con archivos sin analizar. Las dos cosas son mentira,
// así que la corrida se declara fallida y el orquestador degrada la capa —
// la misma lección que dejó el SemgrepError.
func TestHallazgosBiomeInternalErrorNoEsUnHallazgo(t *testing.T) {
	fs, err := hallazgosBiome(`C:\repo`, ".", []byte(salidaBiomeInternalError))
	if err == nil {
		t.Fatalf("un internalError debe fallar la corrida, no devolver %d hallazgos", len(fs))
	}
	if len(fs) != 0 {
		t.Errorf("no debe devolver hallazgos junto al error: %+v", fs)
	}
	if !strings.Contains(err.Error(), "internalError/io") {
		t.Errorf("el error debe nombrar la causa: %v", err)
	}
}

// El span de biome 2.x es un par de desplazamientos de BYTES que viene del JSON
// de una herramienta externa —que su propio equipo anuncia como experimental— y
// se usa para rebanar el código fuente. Se comprobaba la cota superior y se daba
// por supuesta la inferior: con un span negativo, `fuente[:desplazamiento]`
// panica con "slice bounds out of range" y se lleva por delante el análisis
// entero, no sólo el diagnóstico.
//
// La política que la propia función documenta es la contraria: ante datos
// inutilizables, degradar a la línea 1 y seguir. Un hallazgo en la línea
// equivocada sigue señalando el archivo correcto; un panic no señala nada.
func TestLineaBiomeAguantaSpansImposibles(t *testing.T) {
	const fuente = "a\nb\nc" // 5 bytes, 2 saltos

	casos := []struct {
		nombre string
		linea  int
		span   []int
		fuente string
		quiere int
	}{
		{nombre: "span negativo", span: []int{-5, 3}, fuente: fuente, quiere: 1},
		{nombre: "span dentro de rango", span: []int{2, 3}, fuente: fuente, quiere: 2},
		{nombre: "span justo al final", span: []int{5, 5}, fuente: fuente, quiere: 3},
		{nombre: "span pasado del final", span: []int{99, 100}, fuente: fuente, quiere: 1},
		{nombre: "span al principio", span: []int{0, 1}, fuente: fuente, quiere: 1},
		{nombre: "la línea explícita manda sobre un span roto", linea: 7, span: []int{-5, 3}, fuente: fuente, quiere: 7},
		{nombre: "sin span", fuente: fuente, quiere: 1},
		{nombre: "sin fuente", span: []int{2, 3}, quiere: 1},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := lineaBiome(c.linea, c.span, c.fuente); got != c.quiere {
				t.Errorf("lineaBiome(%d, %v, %q) = %d, esperaba %d", c.linea, c.span, c.fuente, got, c.quiere)
			}
		})
	}
}

// Y de punta a punta: el span roto llega dentro del JSON, así que el daño real
// es que el parseo de TODA la corrida se cae.
func TestHallazgosBiomeConSpanNegativoNoTumbaElAnalisis(t *testing.T) {
	fs, err := hallazgosBiome(`C:\repo`, ".", []byte(salidaBiomeSpanNegativo))
	if err != nil {
		t.Fatalf("un span imposible degrada la ubicación, no la corrida: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, obtuve %d", len(fs))
	}
	if fs[0].Line != 1 {
		t.Errorf("sin ubicación utilizable el hallazgo cae en la línea 1, no en %d", fs[0].Line)
	}
}

// ── descubrimiento de proyectos ─────────────────────────────────────────────

func escribirJS(t *testing.T, root, rel, contenido string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}

// El monorepo corporativo típico: la config de lint vive en frontend/, no en la
// raíz. Mirar sólo la raíz dejaría el motor enrolado sin correr jamás, en
// silencio — el mismo fallo que tuvo tsc antes de subir desde cada archivo.
func TestProyectosJSEncuentraLaConfigMasCercana(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "frontend/eslint.config.js", "export default [];")
	escribirJS(t, root, "frontend/src/app.tsx", "")
	escribirJS(t, root, "frontend/src/util.mts", "")
	escribirJS(t, root, "admin/biome.json", "{}")
	escribirJS(t, root, "admin/panel.ts", "")
	escribirJS(t, root, "suelto/nota.js", "") // sin config alcanzable: no aplica

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "frontend/src/app.tsx", Status: "M"},
		{Path: "frontend/src/util.mts", Status: "A"},
		{Path: "admin/panel.ts", Status: "M"},
		{Path: "suelto/nota.js", Status: "M"},
		{Path: "backend/main.go", Status: "M"},
	}}
	got := ESLint{}.proyectos(in)
	if len(got) != 2 {
		t.Fatalf("esperaba 2 proyectos, obtuve %d: %+v", len(got), got)
	}
	// Orden estable, alfabético por directorio.
	if got[0].dir != "admin" || got[0].tool != hBiome {
		t.Errorf("proyecto[0] = %s/%s, esperaba admin/biome", got[0].dir, got[0].tool)
	}
	if got[1].dir != "frontend" || got[1].tool != hESLint {
		t.Errorf("proyecto[1] = %s/%s, esperaba frontend/eslint", got[1].dir, got[1].tool)
	}
	// .mts entra: un módulo TS con extensión explícita es código igual.
	if len(got[1].archivos) != 2 {
		t.Errorf("frontend debe agrupar sus 2 archivos, tiene %d", len(got[1].archivos))
	}
	if !(ESLint{}).Applies(in) {
		t.Fatal("con dos proyectos configurados, Applies debe ser verdadero")
	}
}

// La decisión de producto: un repo que no configura linter no se toca. Imponer
// reglas de estilo que el equipo no eligió convierte al agente en un obstáculo,
// y un obstáculo se desinstala.
func TestProyectosJSSinConfigNoAplica(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "package.json", `{"name":"sin-linter"}`)
	escribirJS(t, root, "tsconfig.json", "{}") // tsc sí corre; el linter no
	escribirJS(t, root, "src/app.ts", "")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/app.ts", Status: "M"},
	}}
	if got := (ESLint{}).proyectos(in); len(got) != 0 {
		t.Fatalf("sin config de linter no hay proyecto que analizar, obtuve %+v", got)
	}
	if (ESLint{}).Applies(in) {
		t.Fatal("Applies debe ser falso: el repo no eligió ningún linter")
	}
}

// Cuando el MISMO directorio configura las dos, gana biome: biome.json aparece
// porque alguien migró, y la migración deja el eslintrc viejo atrás semanas.
// Elegir eslint ahí aplicaría las reglas que el equipo acaba de abandonar.
func TestProyectosJSBiomeGanaCuandoHayLosDos(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, ".eslintrc.json", "{}")
	escribirJS(t, root, "biome.json", "{}")
	escribirJS(t, root, "src/app.js", "")

	got := (ESLint{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/app.js", Status: "M"},
	}})
	if len(got) != 1 {
		t.Fatalf("esperaba 1 proyecto, obtuve %d", len(got))
	}
	if got[0].tool != hBiome {
		t.Errorf("tool = %s; con las dos configuradas gana biome", got[0].tool)
	}
	if got[0].dir != "." {
		t.Errorf("dir = %q, esperaba . (la config está en la raíz)", got[0].dir)
	}
}

// El desempate es POR NIVEL, no global: la config más cercana manda siempre.
// Un biome.json en la raíz no debe secuestrar un frontend/ que eligió eslint.
func TestProyectosJSElDesempateEsPorNivelNoGlobal(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "biome.json", "{}")
	escribirJS(t, root, "frontend/eslint.config.mjs", "export default [];")
	escribirJS(t, root, "frontend/src/app.tsx", "")
	escribirJS(t, root, "scripts/build.mjs", "")

	got := (ESLint{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "frontend/src/app.tsx", Status: "M"},
		{Path: "scripts/build.mjs", Status: "M"},
	}})
	if len(got) != 2 {
		t.Fatalf("esperaba 2 proyectos (raíz con biome, frontend con eslint), obtuve %+v", got)
	}
	if got[0].dir != "." || got[0].tool != hBiome {
		t.Errorf("scripts/ cae en la raíz con biome, obtuve %s/%s", got[0].dir, got[0].tool)
	}
	if got[1].dir != "frontend" || got[1].tool != hESLint {
		t.Errorf("frontend/ eligió eslint y está más cerca, obtuve %s/%s", got[1].dir, got[1].tool)
	}
}

// Los archivos borrados no se analizan (ya no existen) y node_modules jamás:
// lintar las dependencias tardaría minutos y no es código del repo.
func TestProyectosJSIgnoraBorradosYNodeModules(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "eslint.config.js", "export default [];")
	escribirJS(t, root, "node_modules/paquete/index.js", "")
	escribirJS(t, root, "src/vivo.js", "")

	got := (ESLint{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/borrado.js", Status: "D"},
		{Path: "node_modules/paquete/index.js", Status: "M"},
		{Path: "src/vivo.js", Status: "M"},
	}})
	if len(got) != 1 {
		t.Fatalf("esperaba 1 proyecto, obtuve %+v", got)
	}
	if len(got[0].archivos) != 1 || got[0].archivos[0].Path != "src/vivo.js" {
		t.Errorf("sólo src/vivo.js debe analizarse, tiene %+v", got[0].archivos)
	}
}

// ── caché ───────────────────────────────────────────────────────────────────

// La clave lleva la huella de la CONFIG además del contenido: editar .eslintrc
// cambia los hallazgos sin tocar una línea de código, y servir el resultado
// viejo sería reportar las reglas de ayer.
func TestClaveDeArchivoDistingueConfigYHerramienta(t *testing.T) {
	base := claveDeArchivo(hESLint, "cfgA", "shaArchivo")
	if base == claveDeArchivo(hESLint, "cfgB", "shaArchivo") {
		t.Error("mismo archivo con OTRA config debe dar otra clave")
	}
	if base == claveDeArchivo(hBiome, "cfgA", "shaArchivo") {
		t.Error("eslint y biome dan hallazgos distintos del mismo archivo: claves distintas")
	}
	if base == claveDeArchivo(hESLint, "cfgA", "otroSha") {
		t.Error("otro contenido debe dar otra clave")
	}
	if !strings.HasPrefix(base, "eslint:") {
		t.Errorf("la clave debe llevar el prefijo de la herramienta: %q", base)
	}
}

// cachéFalso registra lo que se guarda para poder afirmar que "analizado y
// limpio" también se cachea: es el resultado que más veces se reutiliza.
type cacheFalso struct {
	datos     map[string][]finding.Finding
	guardados map[string][]finding.Finding
}

func (c *cacheFalso) Leer(claves []string) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, k := range claves {
		if fs, ok := c.datos[k]; ok {
			out[k] = fs
		}
	}
	return out
}

func (c *cacheFalso) Guardar(porClave map[string][]finding.Finding) {
	if c.guardados == nil {
		c.guardados = map[string][]finding.Finding{}
	}
	for k, v := range porClave {
		c.guardados[k] = v
	}
}

// El caché está direccionado por CONTENIDO, sin la ruta en la clave: dos
// archivos idénticos comparten entrada. Al reproducir un acierto hay que
// reescribir la ruta y recalcular el fingerprint, o el hallazgo saldría
// atribuido al otro archivo.
func TestCacheReescribeLaRutaAlReproducirUnAcierto(t *testing.T) {
	guardado := finding.Finding{
		Engine: "eslint", RuleKey: "eqeqeq", File: "src/original.js",
		Line: 5, Message: "Expected '===' and instead saw '=='.",
		LineContent: "Expected '===' and instead saw '=='.",
	}
	huellaOriginal := guardado.ComputeFingerprint()

	clave := claveDeArchivo(hESLint, "cfg", "shaCompartido")
	c := &cacheFalso{datos: map[string][]finding.Finding{clave: {guardado}}}

	pendientes := []objetivoJS{{rel: "src/copia.js", enPry: "src/copia.js", clave: clave}}
	var out []finding.Finding
	for _, o := range pendientes {
		for _, f := range c.Leer([]string{o.clave})[o.clave] {
			if f.File != o.rel {
				f.File = o.rel
				f.ComputeFingerprint()
			}
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("esperaba 1 hallazgo del caché, obtuve %d", len(out))
	}
	if out[0].File != "src/copia.js" {
		t.Errorf("File = %q; el acierto debe atribuirse al archivo de ESTA corrida", out[0].File)
	}
	if out[0].Fingerprint == huellaOriginal {
		t.Error("al cambiar la ruta el fingerprint tiene que recalcularse")
	}
}

func TestCacheDeArchivosGuardaTambienLosLimpios(t *testing.T) {
	analizados := []objetivoJS{
		{rel: "src/sucio.js", clave: "eslint:cfg:sha1"},
		{rel: "src/limpio.js", clave: "eslint:cfg:sha2"},
		{rel: "src/sin-huella.js", clave: ""}, // no cacheable
	}
	fs := []finding.Finding{{File: "src/sucio.js", RuleKey: "eqeqeq"}}

	got := cacheDeArchivosJS(fs, analizados)
	if len(got) != 2 {
		t.Fatalf("esperaba 2 claves (la sin huella queda fuera), obtuve %v", got)
	}
	if len(got["eslint:cfg:sha1"]) != 1 {
		t.Errorf("el archivo con hallazgo debe guardar su hallazgo: %v", got["eslint:cfg:sha1"])
	}
	limpio, ok := got["eslint:cfg:sha2"]
	if !ok || len(limpio) != 0 {
		t.Errorf(`"analizado y limpio" debe guardarse como lista vacía, no omitirse: %v, %v`, limpio, ok)
	}
}

// ── troceado ────────────────────────────────────────────────────────────────

// Windows corta CreateProcess en 32767 caracteres. Un lote que no arranca es
// un análisis que no ocurre, y eso no puede pasar en silencio.
func TestLotesDeRutasRespetaElLimite(t *testing.T) {
	rutas := make([]string, 200)
	for i := range rutas {
		rutas[i] = strings.Repeat("a", 100) + ".ts"
	}
	lotes := lotesDeRutas(rutas, 1000)
	if len(lotes) < 2 {
		t.Fatalf("200 rutas de 103 caracteres no caben en 1000: esperaba varios lotes, obtuve %d", len(lotes))
	}
	total := 0
	for _, l := range lotes {
		largo := 0
		for _, r := range l {
			largo += len(r) + 3
		}
		if largo > 1000 && len(l) > 1 {
			t.Errorf("lote de %d caracteres se pasa del límite", largo)
		}
		total += len(l)
	}
	if total != len(rutas) {
		t.Errorf("se perdieron rutas al trocear: %d de %d", total, len(rutas))
	}
}

// Una ruta que por sí sola excede el límite va en su propio lote: recortarla
// dejaría un archivo sin analizar, que es justo lo que el troceado evita.
func TestLotesDeRutasNoDescartaUnaRutaEnorme(t *testing.T) {
	larga := strings.Repeat("b", 2000) + ".ts"
	lotes := lotesDeRutas([]string{"a.ts", larga, "c.ts"}, 100)
	visto := 0
	for _, l := range lotes {
		visto += len(l)
	}
	if visto != 3 {
		t.Fatalf("las 3 rutas deben sobrevivir al troceado, sobrevivieron %d", visto)
	}
}

// ── rutas ───────────────────────────────────────────────────────────────────

func TestRutaRepoJSNormalizaLasDosFormas(t *testing.T) {
	casos := []struct {
		nombre, repoRoot, dir, entrada, quiero string
	}{
		// biome: relativa a su cwd, con barra invertida de Windows.
		{"biome en la raíz", `C:\repo`, ".", `src\a.ts`, "src/a.ts"},
		{"biome en subproyecto", `C:\repo`, "frontend", `src\a.ts`, "frontend/src/a.ts"},
		// eslint: absoluta; el directorio del proyecto NO se concatena.
		{"eslint absoluta", `C:\repo`, ".", `C:\repo\src\a.ts`, "src/a.ts"},
		{"eslint absoluta en subproyecto", `C:\repo`, "frontend", `C:\repo\frontend\src\a.ts`, "frontend/src/a.ts"},
	}
	for _, c := range casos {
		if got := rutaRepoJS(c.repoRoot, c.dir, c.entrada); got != c.quiero {
			t.Errorf("%s: rutaRepoJS(%q, %q, %q) = %q, quiero %q", c.nombre, c.repoRoot, c.dir, c.entrada, got, c.quiero)
		}
	}
}

// ── integración con los binarios de verdad ──────────────────────────────────

// Corre eslint DE VERDAD sobre el proyecto de juguete con el que se capturaron
// los payloads de arriba. Es la única prueba que demuestra que los argumentos
// que le pasamos son los que acepta, no sólo que sabemos leer su salida.
func TestIntegracionESLintBinarioReal(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de eslint")
	}
	root := prepararProyectoESLint(t)
	if _, err := os.Stat(filepath.Join(root, "node_modules", ".bin", "eslint.cmd")); err != nil {
		t.Skip("eslint no está instalado en el proyecto de prueba")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/malo.js", Status: "M", SHA256: "sha-de-prueba"},
	}}
	e := ESLint{}
	if !e.Applies(in) {
		t.Fatal("con eslint.config.js y un .js tocado, Applies debe ser verdadero")
	}
	fs, err := e.Run(ctx, in)
	if err != nil {
		t.Fatalf("eslint real falló: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("el archivo tiene problemas de sobra: esperaba hallazgos")
	}
	reglas := map[string]bool{}
	bloqueantes := 0
	for _, f := range fs {
		if f.Engine != "eslint" {
			t.Errorf("Engine = %q", f.Engine)
		}
		if f.File != "src/malo.js" {
			t.Errorf("File = %q, esperaba src/malo.js", f.File)
		}
		reglas[f.RuleKey] = true
		if f.Blocking {
			bloqueantes++
		}
	}
	if !reglas["eqeqeq"] {
		t.Errorf("esperaba el hallazgo de eqeqeq; vistos: %v", reglas)
	}
	if bloqueantes == 0 {
		t.Error("las reglas de severidad error deben bloquear")
	}
}

// El mismo trato para biome, que es el otro camino del motor.
func TestIntegracionBiomeBinarioReal(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de biome")
	}
	root := prepararProyectoBiome(t)
	if _, err := os.Stat(filepath.Join(root, "node_modules", ".bin", "biome.cmd")); err != nil {
		t.Skip("biome no está instalado en el proyecto de prueba")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/malo.ts", Status: "M", SHA256: "sha-de-prueba"},
	}}
	fs, err := ESLint{}.Run(ctx, in)
	if err != nil {
		t.Fatalf("biome real falló: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("esperaba hallazgos de biome")
	}
	vioFormato := false
	for _, f := range fs {
		if f.Engine != "biome" {
			t.Errorf("Engine = %q, con biome.json debe reportar biome", f.Engine)
		}
		if f.File != "src/malo.ts" {
			t.Errorf("File = %q, esperaba src/malo.ts", f.File)
		}
		if f.Line < 1 {
			t.Errorf("%s: línea %d", f.RuleKey, f.Line)
		}
		if f.RuleKey == "format" {
			vioFormato = true
		}
	}
	if !vioFormato {
		t.Error("el archivo está indentado con espacios y biome formatea con tabs: esperaba el hallazgo de formato")
	}
}

// El caso monorepo con el binario de verdad: la config vive en un subdirectorio
// y no en la raíz del repo. Es donde se juntan las tres cosas que pueden salir
// mal a la vez —resolver el binario del subproyecto, invocarlo con su
// directorio como cwd y prefijar las rutas que devuelve— y con biome es la más
// delicada, porque sus rutas llegan relativas a ese cwd y hay que completarlas.
func TestIntegracionBiomeEnMonorepo(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de biome")
	}
	proyecto := prepararProyectoBiome(t)
	if _, err := os.Stat(filepath.Join(proyecto, "node_modules", ".bin", "biome.cmd")); err != nil {
		t.Skip("biome no está instalado en el proyecto de prueba")
	}
	// La raíz del "repo" es el padre; el proyecto queda como un subdirectorio.
	raiz := filepath.Dir(proyecto)
	sub := filepath.Base(proyecto)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	in := engines.Input{RepoRoot: raiz, Files: []gitdiff.ChangedFile{
		{Path: sub + "/src/malo.ts", Status: "M", SHA256: "sha-de-prueba"},
	}}
	e := ESLint{}
	proyectos := e.proyectos(in)
	if len(proyectos) != 1 || proyectos[0].dir != sub || proyectos[0].tool != hBiome {
		t.Fatalf("descubrimiento mal: %+v (esperaba %s con biome)", proyectos, sub)
	}
	fs, err := e.Run(ctx, in)
	if err != nil {
		t.Fatalf("biome real falló en monorepo: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("esperaba hallazgos")
	}
	quiero := sub + "/src/malo.ts"
	conComando := 0
	for _, f := range fs {
		if f.File != quiero {
			t.Errorf("File = %q, esperaba %q: biome reporta relativo a SU cwd y hay que prefijar el subproyecto", f.File, quiero)
		}
		// Sólo los consejos que traen un comando tienen que decir desde dónde
		// ejecutarlo; los que sólo nombran la regla no llevan ninguno a propósito.
		if strings.Contains(f.FixHint, "npx") {
			conComando++
			if !strings.Contains(f.FixHint, "desde "+sub+"/") {
				t.Errorf("%s: el comando debe indicar el directorio del subproyecto: %q", f.RuleKey, f.FixHint)
			}
		}
	}
	if conComando == 0 {
		t.Error("el hallazgo de formato trae comando de corrección: esperaba al menos un consejo con npx")
	}
}

// prepararProyectoESLint deja el proyecto de juguete en un estado conocido y
// devuelve su ruta.
//
// La prueba corre DENTRO del proyecto instalado en vez de montar un t.TempDir
// con un enlace a su node_modules: Windows no deja crear enlaces simbólicos sin
// privilegios de administrador, así que esa versión se saltaba siempre y la
// integración no se probaba nunca — un test verde que no ejecutaba nada. Copiar
// node_modules no es alternativa (decenas de miles de archivos por corrida).
// A cambio, la prueba se hace dueña de sus ficheros y los reescribe cada vez.
func prepararProyectoESLint(t *testing.T) string {
	t.Helper()
	root := proyectoDeJuguete(t, "toy-eslint")
	escribirJS(t, root, "package.json", `{"name":"toy-eslint","private":true,"version":"1.0.0","type":"module"}`)
	escribirJS(t, root, "eslint.config.js",
		"export default [\n  { files: [\"**/*.js\"], rules: { \"no-unused-vars\": \"warn\", \"eqeqeq\": \"error\", \"prefer-const\": \"error\", \"no-undef\": \"error\" } },\n];\n")
	escribirJS(t, root, "src/malo.js",
		"let noReasignada = 1;\n\nexport function comparar(a, b) {\n  const sinUsar = 42;\n  if (a == b) {\n    return noReasignada;\n  }\n  return desconocida;\n}\n")
	return root
}

func prepararProyectoBiome(t *testing.T) string {
	t.Helper()
	root := proyectoDeJuguete(t, "toy-biome")
	escribirJS(t, root, "package.json", `{"name":"toy-biome","private":true,"version":"1.0.0"}`)
	escribirJS(t, root, "biome.json",
		`{"formatter":{"enabled":true,"indentStyle":"tab"},"linter":{"enabled":true,"rules":{"preset":"recommended"}}}`)
	escribirJS(t, root, "src/malo.ts",
		"export function comparar(a: any, b: any) {\n    const sinUsar = 'texto';\n    if (a == b) {\n        return 1;\n    }\n    return 2;\n}\n")
	return root
}

// proyectoDeJuguete localiza el proyecto con node_modules ya instalado. Se puede
// apuntar con CODEGUARD_TOY_JS; si no existe, la prueba se salta sola en
// cualquier máquina que no sea la que instaló las dependencias.
func proyectoDeJuguete(t *testing.T, nombre string) string {
	t.Helper()
	base := os.Getenv("CODEGUARD_TOY_JS")
	if base == "" {
		base = filepath.Join(os.TempDir(), "claude",
			"C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal",
			"21867769-946e-43a7-a2eb-657c824f2799", "scratchpad")
	}
	root := filepath.Join(base, nombre)
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Skipf("no encuentro el proyecto de juguete con node_modules en %s (apunta CODEGUARD_TOY_JS)", root)
	}
	return root
}
