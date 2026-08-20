package linters

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Todas las capturas de este archivo son salida REAL de mypy 2.3.0 corrido en
// Windows sobre proyectos de juguete, igual que se hizo con semgrep,
// govulncheck, staticcheck y eslint. Se dejan literales —rutas absolutas con
// barra invertida escapada incluidas— porque cada rareza del formato que
// contienen es una que el parseo tiene que sobrevivir en producción: el `hint`
// null, el `code` null, la línea -1.

// raizMypy es el cwd real desde el que se capturó la salida. Hace falta para
// comprobar la conversión de rutas: con --show-absolute-path mypy reporta
// ABSOLUTO.
const raizMypy = `C:\Users\dev\AppData\Local\Temp\claude\C--Users-dev-proyecto\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\toy-mypy`

// mypy 2.3.0: `mypy --no-error-summary --show-absolute-path --output=json
// src/malo.py` con un mypy.ini que pone disallow_untyped_defs. Código 1.
// JSON Lines: una línea por diagnóstico, NO un array.
const salidaMypy = `{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\malo.py", "line": 5, "column": 17, "end_line": 5, "end_column": 27, "message": "Incompatible types in assignment (expression has type \"int\", variable has type \"str\")", "hint": null, "code": "assignment", "severity": "error"}
{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\malo.py", "line": 6, "column": 5, "end_line": 6, "end_column": 10, "message": "Argument 1 to \"suma\" has incompatible type \"str\"; expected \"int\"", "hint": null, "code": "arg-type", "severity": "error"}
{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\malo.py", "line": 9, "column": 0, "end_line": 10, "end_column": 12, "message": "Function is missing a type annotation", "hint": null, "code": "no-untyped-def", "severity": "error"}
{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\malo.py", "line": 14, "column": 11, "end_line": 14, "end_column": 18, "message": "Incompatible return value type (got \"str\", expected \"int\")", "hint": null, "code": "return-value", "severity": "error"}`

// La misma corrida sobre src/importa.py, que importa un paquete sin stubs
// (yaml) y otro inexistente. Trae las cuatro cosas que dan forma al motor:
//   - import-untyped CON hint (las tres notas de mypy ya plegadas por el JSON;
//     el formato de texto las habría dado como tres diagnósticos sueltos)
//   - import-not-found
//   - una nota suelta (severity note), que el JSON sí deja como diagnóstico
//     propio porque no correlaciona con ningún error
//   - no-any-return: la CONSECUENCIA del import roto, que demuestra por qué los
//     errores de import no se pueden callar — el análisis se vuelve hueco
const salidaMypyImports = `{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\importa.py", "line": 1, "column": 0, "end_line": 1, "end_column": 1, "message": "Library stubs not installed for \"yaml\"", "hint": "Hint: \"python3 -m pip install types-PyYAML\"\n(or run \"mypy --install-types\" to install all missing stub packages)\nSee https://mypy.readthedocs.io/en/stable/running_mypy.html#missing-imports", "code": "import-untyped", "severity": "error"}
{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\importa.py", "line": 2, "column": 0, "end_line": 2, "end_column": 1, "message": "Cannot find implementation or library stub for module named \"paquete_que_no_existe\"", "hint": null, "code": "import-not-found", "severity": "error"}
{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\importa.py", "line": 7, "column": 16, "end_line": 7, "end_column": 21, "message": "Revealed type is \"Any\"", "hint": null, "code": "misc", "severity": "note"}
{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy\\src\\importa.py", "line": 8, "column": 4, "end_line": 8, "end_column": 46, "message": "Returning Any from function declared to return \"int\"", "hint": null, "code": "no-any-return", "severity": "error"}`

// Un .py con `def roto(:`. mypy sale con código 2 —para él es un blocker, no
// puede seguir— pero ESCRIBE su diagnóstico igual, con código de error y línea
// buenos. Es el payload que prohíbe tratar el 2 como degradación a secas.
const salidaMypySintaxis = `{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy-dup\\a\\sintaxis.py", "line": 1, "column": 10, "end_line": 1, "end_column": 11, "message": "Invalid syntax", "hint": null, "code": "syntax", "severity": "error"}`

// El otro código 2: dos archivos tocados con el mismo nombre de módulo y sin
// __init__.py. line -1, code null y stderr VACÍO — el diagnóstico va en stdout
// como cualquier otro. mypy no comprobó nada.
const salidaMypyDuplicado = `{"file": "C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toy-mypy-dup\\b\\util.py", "line": -1, "column": -1, "end_line": -1, "end_column": 0, "message": "Duplicate module named \"util\" (also at \"a\\util.py\")", "hint": "See https://mypy.readthedocs.io/en/stable/running_mypy.html#mapping-file-paths-to-modules for more info\nCommon resolutions include:\n    a) using ` + "`--exclude`" + ` to avoid checking one of them,\n    b) adding ` + "`__init__.py`" + ` somewhere,\n    c) using ` + "`--explicit-package-bases`" + ` or adjusting MYPYPATH", "code": null, "severity": "error"}`

// ── parseo ──────────────────────────────────────────────────────────────────

func TestHallazgosMypyMapeaErroresDeTipos(t *testing.T) {
	fs, err := hallazgosMypy(raizMypy, ".", []byte(salidaMypy))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("esperaba 4 hallazgos, obtuve %d", len(fs))
	}
	for _, f := range fs {
		if f.Engine != "mypy" {
			t.Errorf("Engine = %q", f.Engine)
		}
		if f.File != "src/malo.py" {
			t.Errorf("File = %q, esperaba src/malo.py (mypy reporta absoluto con --show-absolute-path)", f.File)
		}
		if f.Pillar != finding.Quality || !f.Verified || f.Source != finding.Deterministic {
			t.Errorf("%s: pilar/verified/source mal puestos: %+v", f.RuleKey, f)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: sin fingerprint", f.RuleKey)
		}
		// §7: un error de tipos bloquea, igual que tsc y govet.
		if f.Severity != finding.Error || !f.Blocking {
			t.Errorf("%s: severity=%q blocking=%v; un error de tipos debe bloquear", f.RuleKey, f.Severity, f.Blocking)
		}
		if !strings.Contains(f.Why, "PROPIO REPO") {
			t.Errorf("%s: Why debe dejar claro que la config de tipos es del repo, no nuestra: %q", f.RuleKey, f.Why)
		}
	}

	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
	}
	// La RuleKey es el código entre corchetes de mypy: es lo que el dev busca en
	// la documentación y lo que pone en un `type: ignore[...]`.
	for _, regla := range []string{"assignment", "arg-type", "no-untyped-def", "return-value"} {
		if _, ok := porRegla[regla]; !ok {
			t.Errorf("falta el hallazgo de %s; reglas vistas: %v", regla, porRegla)
		}
	}
	if a := porRegla["arg-type"]; a.Line != 6 || a.EndLine != 6 {
		t.Errorf("arg-type: line=%d endLine=%d, esperaba 6/6", a.Line, a.EndLine)
	}
	// El diagnóstico de no-untyped-def abarca dos líneas: end_line viaja.
	if n := porRegla["no-untyped-def"]; n.Line != 9 || n.EndLine != 10 {
		t.Errorf("no-untyped-def: line=%d endLine=%d, esperaba 9/10", n.Line, n.EndLine)
	}
	// Sin hint de mypy, el consejo lo pone el motor y nombra la regla para que
	// el dev sepa qué silenciar.
	if fh := porRegla["assignment"].FixHint; !strings.Contains(fh, "assignment") {
		t.Errorf("el consejo debe nombrar la regla para poder silenciarla: %q", fh)
	}
}

// El corazón del trato con los errores de import: se VEN (el análisis se vuelve
// hueco sin ellos) pero NO bloquean (el binario de mypy es nuestro, no el del
// venv del repo, y un stub ausente aquí no es un error del código del dev).
func TestHallazgosMypyLosErroresDeImportAvisanPeroNoBloquean(t *testing.T) {
	fs, err := hallazgosMypy(raizMypy, ".", []byte(salidaMypyImports))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("esperaba 4 hallazgos, obtuve %d", len(fs))
	}
	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
	}

	for _, regla := range []string{"import-untyped", "import-not-found"} {
		f, ok := porRegla[regla]
		if !ok {
			t.Fatalf("falta %s: los errores de import se conservan, no se filtran (si no, el informe parecería limpio con el análisis hueco)", regla)
		}
		// mypy los manda como severity "error"; el motor los degrada a aviso a
		// propósito, porque el binario que corre es el nuestro y no el del venv
		// del repo: un stub ausente aquí no es un error del código del dev.
		if f.Blocking {
			t.Errorf("%s NO puede bloquear: es el entorno de esta máquina, no el código del dev", regla)
		}
		if f.Severity != finding.Warning {
			t.Errorf("%s: severity=%q, esperaba warning", regla, f.Severity)
		}
	}

	// El hint de mypy trae el comando literal, y es la razón por la que se eligió
	// --output=json: en el formato de texto esas tres notas serían tres
	// diagnósticos sueltos indistinguibles de un hallazgo.
	fh := porRegla["import-untyped"].FixHint
	if !strings.Contains(fh, "types-PyYAML") {
		t.Errorf("el consejo debe usar el hint de mypy con el comando exacto: %q", fh)
	}
	if strings.Contains(fh, "\n") {
		t.Errorf("el hint viene en varias líneas y hay que aplastarlo para el informe: %q", fh)
	}
	if !strings.Contains(fh, "no es tu código") {
		t.Errorf("el consejo debe decir que la causa está en el entorno: %q", fh)
	}
	// Sin hint, el motor pone el suyo y menciona la salida de escape del repo.
	if fh := porRegla["import-not-found"].FixHint; !strings.Contains(fh, "ignore_missing_imports") {
		t.Errorf("sin hint de mypy, el consejo debe ofrecer la config del repo: %q", fh)
	}

	// Una nota suelta avisa y no bloquea: es información, no veredicto.
	nota, ok := porRegla["misc"]
	if !ok {
		t.Fatal("falta la nota suelta (Revealed type)")
	}
	if nota.Severity != finding.Warning || nota.Blocking {
		t.Errorf("una nota avisa y NO bloquea: severity=%q blocking=%v", nota.Severity, nota.Blocking)
	}

	// La consecuencia del import roto sigue siendo un error de mypy y se
	// reporta como tal: no se puede atribuir al import con certeza.
	if any := porRegla["no-any-return"]; !any.Blocking {
		t.Errorf("no-any-return es un error de tipos normal y bloquea: %+v", any)
	}
}

// Un error de sintaxis sale con código 2 pero ES un hallazgo, y de los graves.
// Si el motor tratara el 2 como degradación tiraría justo el problema que más
// tiene que parar un commit.
func TestHallazgosMypySintaxisEsHallazgoAunqueMypySalgaCon2(t *testing.T) {
	raizDup := strings.TrimSuffix(raizMypy, "toy-mypy") + "toy-mypy-dup"
	fs, err := hallazgosMypy(raizDup, ".", []byte(salidaMypySintaxis))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, obtuve %d", len(fs))
	}
	f := fs[0]
	if f.RuleKey != "syntax" || f.File != "a/sintaxis.py" || f.Line != 1 {
		t.Errorf("hallazgo mal formado: %s en %s:%d", f.RuleKey, f.File, f.Line)
	}
	if !f.Blocking || f.Severity != finding.Error {
		t.Errorf("un error de sintaxis debe bloquear: severity=%q blocking=%v", f.Severity, f.Blocking)
	}
}

// El otro código 2, el que sí es degradación: mypy no comprobó NADA. Contarlo
// como hallazgo le inventaría al dev un problema en su código; ignorarlo
// presentaría el análisis como completo. Misma lección que el internalError de
// biome y el SemgrepError.
func TestHallazgosMypyModuloDuplicadoDegradaLaCapa(t *testing.T) {
	fs, err := hallazgosMypy(raizMypy, ".", []byte(salidaMypyDuplicado))
	if err == nil {
		t.Fatalf("un módulo duplicado aborta la comprobación: debe fallar la corrida, no devolver %d hallazgos", len(fs))
	}
	if len(fs) != 0 {
		t.Errorf("no debe devolver hallazgos junto al error: %+v", fs)
	}
	if !strings.Contains(err.Error(), "Duplicate module") {
		t.Errorf("el error debe nombrar la causa: %v", err)
	}
	// El hint de mypy lista las tres salidas (__init__.py, --exclude,
	// --explicit-package-bases) y viaja en el mensaje de degradación: es lo
	// único que el dev puede hacer al respecto.
	if !strings.Contains(err.Error(), "__init__.py") {
		t.Errorf("el mensaje debe llevar el consejo de mypy: %v", err)
	}
}

// En un monorepo mypy sigue devolviendo la ruta ABSOLUTA (--show-absolute-path),
// así que la conversión sale de ahí y no de concatenar el directorio del
// proyecto: hacer las dos cosas daría "backend/backend/src".
func TestHallazgosMypyNoDuplicaElDirectorioDelProyecto(t *testing.T) {
	raizRepo := strings.TrimSuffix(raizMypy, `\toy-mypy`)
	fs, err := hallazgosMypy(raizRepo, "toy-mypy", []byte(salidaMypy))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("esperaba hallazgos de mypy, obtuvo 0")
	}
	if fs[0].File != "toy-mypy/src/malo.py" {
		t.Fatalf("File = %q, esperaba toy-mypy/src/malo.py", fs[0].File)
	}
}

// ── descubrimiento de proyectos ─────────────────────────────────────────────

// LA prueba de la decisión de diseño. Se verificó que mypy corre igual de
// contento en un repo con pyproject.toml sin [tool.mypy] y reporta errores: si
// el motor no mirara DENTRO del archivo, aplicaría en casi todos los repos de
// Python del mundo e impondría comprobación de tipos a equipos que no la
// eligieron. Un obstáculo se desinstala.
func TestProyectosMypyPyprojectSinSeccionNoAplica(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "pyproject.toml", "[project]\nname = \"sin-mypy\"\nversion = \"0.1.0\"\n\n[tool.ruff]\nline-length = 100\n")
	escribirJS(t, root, "setup.cfg", "[metadata]\nname = sin-mypy\n\n[flake8]\nmax-line-length = 100\n")
	escribirJS(t, root, "src/app.py", "")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/app.py", Status: "M"},
	}}
	if got := (Mypy{}).proyectos(in); len(got) != 0 {
		t.Fatalf("un pyproject.toml sin [tool.mypy] NO es configuración de mypy, obtuve %+v", got)
	}
	if (Mypy{}).Applies(in) {
		t.Fatal("Applies debe ser falso: el repo no eligió comprobar tipos")
	}
}

// [tool.mypyc] es OTRA herramienta (el compilador), no la comprobación de
// tipos. Confundirlas volvería a abrir la puerta que el test de arriba cierra.
func TestProyectosMypyNoConfundeMypycConMypy(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "pyproject.toml", "[tool.mypyc]\nopt_level = \"3\"\n")
	escribirJS(t, root, "src/app.py", "")

	if got := (Mypy{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/app.py", Status: "M"},
	}}); len(got) != 0 {
		t.Fatalf("[tool.mypyc] es el compilador, no la comprobación de tipos: %+v", got)
	}
}

// Las cuatro formas de declarar "este proyecto comprueba tipos", cada una en su
// propio subárbol, y el subárbol que no declara ninguna quedándose fuera.
func TestProyectosMypyReconoceLasCuatroConfiguraciones(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "uno/mypy.ini", "[mypy]\nstrict = True\n")
	escribirJS(t, root, "uno/a.py", "")
	escribirJS(t, root, "dos/.mypy.ini", "[mypy]\n")
	escribirJS(t, root, "dos/b.py", "")
	escribirJS(t, root, "tres/setup.cfg", "[metadata]\nname = tres\n\n[mypy]\nwarn_unused_ignores = True\n")
	escribirJS(t, root, "tres/c.py", "")
	// Con tabla anidada y sin [tool.mypy] a secas: TOML crea igual la tabla
	// padre y mypy toma el archivo como configuración suya.
	escribirJS(t, root, "cuatro/pyproject.toml", "[project]\nname = \"cuatro\"\n\n[[tool.mypy.overrides]]\nmodule = \"requests.*\"\nignore_missing_imports = true\n")
	escribirJS(t, root, "cuatro/d.py", "")
	escribirJS(t, root, "cinco/e.py", "") // sin configuración alcanzable

	got := (Mypy{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "uno/a.py", Status: "M"},
		{Path: "dos/b.py", Status: "A"},
		{Path: "tres/c.py", Status: "M"},
		{Path: "cuatro/d.py", Status: "M"},
		{Path: "cinco/e.py", Status: "M"},
		{Path: "otro/main.go", Status: "M"},
	}})
	if len(got) != 4 {
		t.Fatalf("esperaba 4 proyectos, obtuve %d: %+v", len(got), got)
	}
	// Orden estable, alfabético por directorio.
	for i, quiero := range []string{"cuatro", "dos", "tres", "uno"} {
		if got[i].dir != quiero {
			t.Errorf("proyecto[%d] = %q, esperaba %q", i, got[i].dir, quiero)
		}
	}
}

// El monorepo corporativo típico: la configuración vive en backend/, no en la
// raíz. Mirar sólo la raíz dejaría la compuerta de tipos enrolada sin correr
// jamás, en silencio — el mismo fallo que tuvo tsc.
func TestProyectosMypyEncuentraLaConfigMasCercanaEnMonorepo(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "backend/mypy.ini", "[mypy]\ndisallow_untyped_defs = True\n")
	escribirJS(t, root, "backend/app/servicio.py", "")
	escribirJS(t, root, "backend/app/modelos.py", "")
	escribirJS(t, root, "scripts/migrar.py", "") // fuera de backend/: sin config

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/app/servicio.py", Status: "M"},
		{Path: "backend/app/modelos.py", Status: "M"},
		{Path: "scripts/migrar.py", Status: "M"},
	}}
	got := (Mypy{}).proyectos(in)
	if len(got) != 1 {
		t.Fatalf("esperaba 1 proyecto, obtuve %+v", got)
	}
	if got[0].dir != "backend" {
		t.Errorf("dir = %q, esperaba backend (la config no está en la raíz)", got[0].dir)
	}
	if len(got[0].archivos) != 2 {
		t.Errorf("backend debe agrupar sus 2 archivos, tiene %d", len(got[0].archivos))
	}
	if !(Mypy{}).Applies(in) {
		t.Fatal("con backend/mypy.ini y .py tocados, Applies debe ser verdadero")
	}
}

// Gana la configuración MÁS CERCANA: una raíz con mypy.ini no debe secuestrar
// un backend/ que trae la suya, porque las opciones son distintas (strict en
// uno, permisivo en el otro) y mypy sólo lee la de su cwd.
func TestProyectosMypyGanaLaConfigMasCercana(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "mypy.ini", "[mypy]\n")
	escribirJS(t, root, "backend/pyproject.toml", "[tool.mypy]\nstrict = true\n")
	escribirJS(t, root, "backend/app.py", "")
	escribirJS(t, root, "tools/gen.py", "")

	got := (Mypy{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/app.py", Status: "M"},
		{Path: "tools/gen.py", Status: "M"},
	}})
	if len(got) != 2 {
		t.Fatalf("esperaba 2 proyectos (raíz y backend), obtuve %+v", got)
	}
	if got[0].dir != "." || got[1].dir != "backend" {
		t.Errorf("dirs = %q y %q, esperaba . y backend", got[0].dir, got[1].dir)
	}
}

// Los archivos borrados no se analizan (ya no existen) y el entorno virtual
// jamás: es el node_modules de Python, tarda minutos y no es código del repo.
func TestProyectosMypyIgnoraBorradosYEntornosVirtuales(t *testing.T) {
	root := t.TempDir()
	escribirJS(t, root, "mypy.ini", "[mypy]\n")
	escribirJS(t, root, ".venv/Lib/site-packages/paquete/mod.py", "")
	escribirJS(t, root, "src/vivo.py", "")

	got := (Mypy{}).proyectos(engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/borrado.py", Status: "D"},
		{Path: ".venv/Lib/site-packages/paquete/mod.py", Status: "M"},
		{Path: "src/vivo.py", Status: "M"},
	}})
	if len(got) != 1 {
		t.Fatalf("esperaba 1 proyecto, obtuve %+v", got)
	}
	if len(got[0].archivos) != 1 || got[0].archivos[0].Path != "src/vivo.py" {
		t.Errorf("sólo src/vivo.py debe analizarse, tiene %+v", got[0].archivos)
	}
}

// ── lectura de secciones ────────────────────────────────────────────────────

func TestTieneSeccionDistingueLoQueCuentaDeLoQueNo(t *testing.T) {
	root := t.TempDir()
	casos := []struct {
		nombre, contenido, seccion string
		quiero                     bool
	}{
		{"tool.mypy pelada", "[tool.mypy]\nstrict = true\n", "tool.mypy", true},
		{"tool.mypy con espacios", "[ tool.mypy ]\n", "tool.mypy", true},
		{"tabla anidada", "[[tool.mypy.overrides]]\nmodule = \"x\"\n", "tool.mypy", true},
		{"mypyc no cuenta", "[tool.mypyc]\n", "tool.mypy", false},
		{"comentada no cuenta", "# [tool.mypy]\n", "tool.mypy", false},
		{"mypy en setup.cfg", "[metadata]\nname = x\n\n[mypy]\n", "mypy", true},
		{"solo por módulo no cuenta", "[mypy-requests.*]\nignore_missing_imports = True\n", "mypy", false},
		{"CRLF", "[metadata]\r\nname = x\r\n[mypy]\r\n", "mypy", true},
		{"sin la sección", "[flake8]\nmax-line-length = 100\n", "mypy", false},
	}
	for _, c := range casos {
		abs := filepath.Join(root, "cfg-"+strings.ReplaceAll(c.nombre, " ", "-"))
		if err := os.WriteFile(abs, []byte(c.contenido), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := tieneSeccion(abs, c.seccion); got != c.quiero {
			t.Errorf("%s: tieneSeccion(%q) = %v, quiero %v", c.nombre, c.seccion, got, c.quiero)
		}
	}
	// Un archivo que no existe no configura nada, y no puede reventar.
	if tieneSeccion(filepath.Join(root, "no-existe.toml"), "tool.mypy") {
		t.Error("un archivo ausente no declara ninguna sección")
	}
}

// ── caché ───────────────────────────────────────────────────────────────────

// La diferencia con claveProyecto de tsc.go, y la razón de que exista esta
// función: a mypy se le pasa una LISTA de archivos y sólo reporta sobre ella.
// Sin el conjunto en la clave, un commit de un archivo sembraría el caché y el
// siguiente —con dos archivos y la misma huella de módulo— acertaría y dejaría
// el archivo nuevo sin analizar, en silencio.
func TestClaveProyectoMypyDistingueElConjuntoDeArchivos(t *testing.T) {
	// HuellaModulo necesita un repo git enumerable; en t.TempDir devuelve vacío
	// y la clave queda vacía (no cacheable), que es el comportamiento correcto.
	// Aquí se comprueba la parte que sí es determinista: la composición.
	uno := claveProyectoMypy(t.TempDir(), ".", []string{"a.py"})
	if uno != "" {
		t.Fatalf("sin repo enumerable la clave debe quedar vacía (no cacheable), obtuve %q", uno)
	}

	// La composición se comprueba con la parte pura: mismo dir y misma huella,
	// distinta lista de archivos → distinta clave.
	base := componerClaveMypy(".", "cfg", []string{"a.py"})
	if base == componerClaveMypy(".", "cfg", []string{"a.py", "b.py"}) {
		t.Error("el conjunto de archivos analizados TIENE que entrar en la clave: si no, un commit de más archivos acertaría el caché del commit anterior y el archivo nuevo se quedaría sin analizar")
	}
	if base == componerClaveMypy("backend", "cfg", []string{"a.py"}) {
		t.Error("dos proyectos del monorepo tienen configuraciones distintas: claves distintas")
	}
	if base == componerClaveMypy(".", "otraHuella", []string{"a.py"}) {
		t.Error("otra huella de módulo (fuentes, config o dependencias) debe dar otra clave")
	}
	if !strings.HasPrefix(base, "mypy:") {
		t.Error("la clave debe llevar el prefijo del motor: el caché es compartido con los demás")
	}
	// La clave describe el CONJUNTO, no la lista: dos corridas con los mismos
	// archivos en distinto orden analizan lo mismo y deben acertar el caché.
	if componerClaveMypy(".", "cfg", []string{"a.py", "b.py"}) != componerClaveMypy(".", "cfg", []string{"b.py", "a.py"}) {
		t.Error("el orden de la lista no puede cambiar la clave: el análisis es el mismo")
	}
}

// ── integración con el binario real ─────────────────────────────────────────

// Corre mypy DE VERDAD sobre el proyecto de juguete con el que se capturaron
// los payloads de arriba. Es la única prueba que demuestra que las banderas que
// le pasamos son las que acepta —incluida --output=json, que no existe en mypy
// anteriores a 1.11— y no sólo que sabemos leer su salida.
func TestIntegracionMypyBinarioReal(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de mypy")
	}
	if _, err := exec.LookPath("mypy"); err != nil {
		t.Skip("mypy no está en el PATH")
	}
	root := prepararProyectoMypy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/malo.py", Status: "M", SHA256: "sha-de-prueba"},
	}}
	e := Mypy{}
	if !e.Applies(in) {
		t.Fatal("con mypy.ini y un .py tocado, Applies debe ser verdadero")
	}
	fs, err := e.Run(ctx, in)
	if err != nil {
		t.Fatalf("mypy real falló: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("el archivo tiene errores de tipos de sobra: esperaba hallazgos")
	}
	reglas := map[string]bool{}
	bloqueantes := 0
	for _, f := range fs {
		if f.Engine != "mypy" {
			t.Errorf("Engine = %q", f.Engine)
		}
		if f.File != "src/malo.py" {
			t.Errorf("File = %q, esperaba src/malo.py", f.File)
		}
		if f.Line < 1 {
			t.Errorf("%s: línea %d; un 0 en el informe se lee como 'sin ubicación'", f.RuleKey, f.Line)
		}
		reglas[f.RuleKey] = true
		if f.Blocking {
			bloqueantes++
		}
	}
	if !reglas["assignment"] && !reglas["arg-type"] {
		t.Errorf("esperaba los errores de tipos del archivo; vistos: %v", reglas)
	}
	if bloqueantes == 0 {
		t.Error("los errores de tipos deben bloquear (§7)")
	}
}

// El caso monorepo con el binario de verdad: la configuración vive en un
// subdirectorio y no en la raíz del repo. Es donde se juntan las tres cosas que
// pueden salir mal a la vez —encontrar la config subiendo, invocar mypy con ese
// directorio como cwd para que la lea, y devolver rutas relativas al REPO y no
// al proyecto—.
func TestIntegracionMypyEnMonorepo(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de mypy")
	}
	if _, err := exec.LookPath("mypy"); err != nil {
		t.Skip("mypy no está en el PATH")
	}
	proyecto := prepararProyectoMypy(t)
	raiz := filepath.Dir(proyecto)
	sub := filepath.Base(proyecto)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	in := engines.Input{RepoRoot: raiz, Files: []gitdiff.ChangedFile{
		{Path: sub + "/src/malo.py", Status: "M", SHA256: "sha-de-prueba"},
	}}
	e := Mypy{}
	proyectos := e.proyectos(in)
	if len(proyectos) != 1 || proyectos[0].dir != sub {
		t.Fatalf("descubrimiento mal: %+v (esperaba %s)", proyectos, sub)
	}
	fs, err := e.Run(ctx, in)
	if err != nil {
		t.Fatalf("mypy real falló en monorepo: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("esperaba hallazgos")
	}
	quiero := sub + "/src/malo.py"
	for _, f := range fs {
		if f.File != quiero {
			t.Errorf("File = %q, esperaba %q", f.File, quiero)
		}
	}
}

// Un repo de Python SIN configuración de mypy no se toca, ni siquiera con el
// binario delante. Es la decisión de producto entera en una prueba.
func TestIntegracionMypyNoAplicaSinConfiguracion(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de mypy")
	}
	if _, err := exec.LookPath("mypy"); err != nil {
		t.Skip("mypy no está en el PATH")
	}
	root := t.TempDir()
	escribirJS(t, root, "pyproject.toml", "[project]\nname = \"sin-tipos\"\nversion = \"0.1.0\"\n")
	escribirJS(t, root, "app.py", "resultado: str = 1 + 1\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "app.py", Status: "M", SHA256: "sha-de-prueba"},
	}}
	if (Mypy{}).Applies(in) {
		t.Fatal("Applies debe ser falso: el repo no configuró mypy")
	}
	fs, err := (Mypy{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run sin proyectos no debe fallar: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("el archivo TIENE un error de tipos y aun así no se reporta: esa es la decisión (%+v)", fs)
	}
}

// prepararProyectoMypy deja el proyecto de juguete en un estado conocido y
// devuelve su ruta. Mismo trato que el de eslint: la prueba se hace dueña de
// sus ficheros y los reescribe cada vez, así el payload capturado y lo que
// corre la integración no pueden divergir.
// EL CONTROL DEL ARREGLO DEL SILENCIO DE MYPY.
//
// `mypy --output=json` sin errores escribe 0 bytes y sale con 0 (medido), o sea
// que su «está todo bien» es exactamente el mismo silencio que el de una
// herramienta que no analizó nada. Ante ese silencio el motor le pregunta a mypy
// quién es, y si la respuesta no se reconoce, la capa de tipos se declara
// degradada.
//
// El riesgo es el inverso del fallo que se cierra: con el patrón mal escrito,
// TODOS los commits limpios de Python verían la capa de tipos en naranja para
// siempre. Los tres tests de integración que ya había usan un proyecto con
// errores de tipos a propósito; ninguno pasa por el caso limpio.
//
// Va con t.TempDir() y no con el proyecto de juguete compartido a propósito:
// como no produce hallazgos, no hay rutas que relativizar, así que no le afecta
// el asunto del TEMP en forma corta 8.3 que tiene a esos tres a medias en esta
// máquina.
func TestIntegracionMypyLimpioSigueSiendoLimpio(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de integración: lanza el binario real de mypy")
	}
	if _, err := exec.LookPath("mypy"); err != nil {
		t.Skip("mypy no está en el PATH")
	}
	root := t.TempDir()
	escribirJS(t, root, "mypy.ini", "[mypy]\ndisallow_untyped_defs = True\nwarn_return_any = True\n")
	escribirJS(t, root, "src/bien.py", "def suma(a: int, b: int) -> int:\n    return a + b\n\n\n"+
		"resultado: int = suma(1, 2)\n")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	fs, err := (Mypy{}).Run(ctx, engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "src/bien.py", Status: "M", SHA256: "sha-de-prueba"},
	}})
	if err != nil {
		t.Fatalf("mypy analizó código bien tipado y el motor se declaró incapaz.\n"+
			"Con esto, cada commit limpio de Python pinta la capa de tipos en naranja: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("código bien tipado no tiene hallazgos, y salieron %d: %+v", len(fs), fs)
	}
}

func prepararProyectoMypy(t *testing.T) string {
	t.Helper()
	base := os.Getenv("CODEGUARD_TOY_PY")
	if base == "" {
		// t.TempDir da un directorio real, único y anónimo que se limpia solo:
		// antes esto era una ruta hardcodeada con un nombre de usuario y un GUID
		// de sesión reales, y además frágil (el prefijo que devuelve mypy tenía
		// que coincidir con esa ruta a mano para que la relativización cuadrara).
		base = t.TempDir()
	}
	root := filepath.Join(base, "toy-mypy")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Skipf("no se pudo preparar el proyecto de juguete en %s (apunta CODEGUARD_TOY_PY): %v", root, err)
	}
	escribirJS(t, root, "mypy.ini", "[mypy]\ndisallow_untyped_defs = True\nwarn_return_any = True\n")
	escribirJS(t, root, "src/malo.py",
		"def suma(a: int, b: int) -> int:\n    return a + b\n\n\nresultado: str = suma(1, 2)\nsuma(\"uno\", 2)\n\n\ndef sin_anotar(x):\n    return x\n\n\ndef devuelve_mal() -> int:\n    return \"texto\"\n")
	return root
}
