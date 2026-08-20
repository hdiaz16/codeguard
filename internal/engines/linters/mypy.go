package linters

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Mypy cierra la última casilla que le faltaba a Python. Hasta aquí ese lado
// del producto tenía formato y lint (ruff) y dependencias (trivy), pero NADA de
// comprobación de tipos: un `resultado: str = suma(1, 2)` llegaba entero al CI
// mientras Go llevaba govet+staticcheck y TypeScript llevaba tsc.
//
// La decisión que da forma al motor es la MISMA que tomó eslint.go, y por la
// misma razón: SÓLO APLICA SI EL REPO YA CONFIGURÓ MYPY. En código sin
// anotaciones mypy no produce hallazgos, produce ruido —cada función sin
// anotar es un "Function is missing a type annotation"—, y obligar a comprobar
// tipos a un equipo que no lo eligió convierte al agente en un obstáculo. Un
// obstáculo se desinstala.
//
// Y no basta con preguntarle a mypy: se verificó que mypy corre igual de
// contento en un directorio con un pyproject.toml SIN sección [tool.mypy] y
// reporta sus errores. La compuerta tiene que ponerla el motor mirando dentro
// del archivo, o aplicaría en casi todos los repos de Python del mundo.
type Mypy struct {
	// Cache es POR PROYECTO, no por archivo. mypy no analiza archivos sueltos:
	// sigue los imports, así que los errores de a.py dependen del contenido de
	// los módulos que a.py importa. Una clave direccionada sólo por el
	// contenido del archivo —la de eslint— serviría hallazgos de ayer en
	// cuanto cambiara un módulo vecino sin tocar el archivo. Ver
	// claveProyectoMypy.
	Cache engines.Cache
}

func (Mypy) Name() string { return "mypy" }

func (e Mypy) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// configsMypyPropias son los archivos que EXISTEN sólo para configurar mypy: su
// mera presencia ya declara la intención y no hay que leerlos.
var configsMypyPropias = []string{"mypy.ini", ".mypy.ini"}

// proyectoPy es un grupo de .py tocados que comparten configuración de mypy: el
// directorio donde vive esa configuración (relativo a la raíz, "." si es la
// propia raíz) y los archivos que le tocan.
type proyectoPy struct {
	dir      string
	archivos []gitdiff.ChangedFile
}

// proyectos agrupa los .py tocados por la configuración de mypy más cercana,
// subiendo desde cada archivo. Es el mismo descubrimiento de tsc.go y
// eslint.go, y por el mismo motivo: en el monorepo corporativo típico la
// configuración vive en backend/, no en la raíz, y mirar sólo la raíz dejaría
// la compuerta enrolada sin correr JAMÁS, en silencio.
func (Mypy) proyectos(in engines.Input) []proyectoPy {
	idx := map[string]*proyectoPy{}
	for _, f := range in.Files {
		// Los .pyi disparan igual que los .py: un stub ES tipado, y la huella
		// del módulo (claveProyectoMypy) ya los cuenta, así que la clave de caché
		// reconocía el cambio mientras el disparador lo ignoraba — un commit que
		// sólo tocaba stubs se iba sin que mypy corriera.
		ext := strings.ToLower(path.Ext(f.Path))
		if f.Status == "D" || (ext != ".py" && ext != ".pyi") {
			continue
		}
		dir, ok := configMypyDe(in.RepoRoot, f.Path)
		if !ok {
			continue // el repo no configuró mypy aquí: no es asunto nuestro
		}
		p := idx[dir]
		if p == nil {
			p = &proyectoPy{dir: dir}
			idx[dir] = p
		}
		p.archivos = append(p.archivos, f)
	}
	out := make([]proyectoPy, 0, len(idx))
	for _, p := range idx {
		out = append(out, *p)
	}
	// Orden estable: el informe no debe cambiar de forma entre dos corridas
	// idénticas sólo por el recorrido de un mapa.
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// configMypyDe sube desde el archivo hasta el primer directorio que configure
// mypy, sin salirse de la raíz ni entrar en un entorno virtual.
//
// El orden dentro de un mismo directorio es el de cercanía declarada en la
// documentación de mypy, pero da igual cuál gane: los cuatro significan lo
// mismo —"este proyecto comprueba tipos"— y el motor no lee la configuración,
// sólo la detecta. Quien la lee es mypy, al que se invoca con ese directorio
// como cwd para que la encuentre él solito.
func configMypyDe(repoRoot, rel string) (string, bool) {
	if enEntornoVirtual(rel) {
		return "", false
	}
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
		if hayAlguno(abs, configsMypyPropias) {
			return dir, true
		}
		// setup.cfg y pyproject.toml son archivos COMPARTIDOS: existen en casi
		// todo repo de Python y no dicen nada por sí solos. Sólo cuentan si
		// alojan la sección de mypy, y eso exige mirar dentro.
		if tieneSeccion(filepath.Join(abs, "setup.cfg"), "mypy") {
			return dir, true
		}
		if tieneSeccion(filepath.Join(abs, "pyproject.toml"), "tool.mypy") {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

// enEntornoVirtual reconoce las carpetas donde vive el intérprete y sus
// dependencias. Es el node_modules de Python: analizar ahí tarda minutos y no
// es código del repo. Normalmente están en .gitignore y no llegarían al diff,
// pero un repo que versione su venv por error no debe tumbar el pre-commit.
func enEntornoVirtual(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".venv", "venv", "site-packages", ".tox", ".mypy_cache", "__pycache__":
			return true
		}
	}
	return false
}

// tieneSeccion dice si un archivo INI o TOML declara alguna de las secciones
// dadas. Se parsea a mano —sólo las cabeceras— en vez de traer un lector de
// TOML: la pregunta es "¿existe esta sección?", no "¿qué dice?", y una
// dependencia nueva para eso no se paga.
//
// Acepta la forma de tabla anidada, para que un pyproject.toml que sólo traiga
// [[tool.mypy.overrides]] cuente igual: TOML crea la tabla padre y mypy toma el
// archivo como suyo. Lo que NO cuenta es [tool.mypyc] —mypyc es el compilador,
// otra herramienta— y de ahí que el prefijo se compare con el punto incluido.
//
// Un setup.cfg con sólo secciones [mypy-modulo] por módulo y sin [mypy] queda
// fuera: es la lectura literal de la documentación, y equivocarse hacia "no
// aplica" es el lado seguro de esta decisión.
func tieneSeccion(abs string, nombres ...string) bool {
	datos, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	for _, linea := range strings.Split(string(datos), "\n") {
		// TrimSpace se come también el \r de los repos en CRLF, que en Windows
		// son la mayoría.
		s := strings.TrimSpace(linea)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || !strings.HasPrefix(s, "[") {
			continue
		}
		cierre := strings.IndexByte(s, ']')
		if cierre < 0 {
			continue
		}
		titulo := strings.TrimSpace(strings.Trim(s[:cierre+1], "[]"))
		for _, n := range nombres {
			if titulo == n || strings.HasPrefix(titulo, n+".") {
				return true
			}
		}
	}
	return false
}

// maxLineaComandosPy acota los argumentos de una invocación.
//
// El límite es el de semgrep (32767 de CreateProcess) y no el de eslint (8191
// de cmd.exe): pip instala mypy como mypy.exe, un ejecutable de verdad, no como
// el shim .cmd que reparte npm. Se verificó mirando el directorio de scripts
// del usuario. 30000 deja margen para la ruta del binario y las tres banderas.
const maxLineaComandosPy = 30000

func (e Mypy) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range e.proyectos(in) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fs, err := e.correrProyectoPy(ctx, in.RepoRoot, p)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (e Mypy) correrProyectoPy(ctx context.Context, repoRoot string, p proyectoPy) ([]finding.Finding, error) {
	rutas := make([]string, 0, len(p.archivos))
	for _, f := range p.archivos {
		rutas = append(rutas, enProyecto(p.dir, f.Path))
	}
	// Ordenar antes de nada: la lista entra en la clave de caché, y dos
	// corridas con los mismos archivos en distinto orden tienen que acertar.
	sort.Strings(rutas)

	clave := ""
	if e.Cache != nil {
		if clave = claveProyectoMypy(repoRoot, p.dir, rutas); clave != "" {
			if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
				return fs, nil
			}
		}
	}

	// Trocear parte el análisis: mypy ve menos módulos por corrida y un error
	// que cruce dos lotes puede escapársele. Es el coste asumido de no
	// desbordar la línea de comandos, el mismo que aceptó semgrep — y sólo se
	// paga en commits de cientos de archivos, que es exactamente cuando la
	// alternativa sería no analizar nada.
	var nuevos []finding.Finding
	for _, lote := range lotesDeRutas(rutas, maxLineaComandosPy) {
		fs, err := correrMypy(ctx, repoRoot, p.dir, lote)
		if err != nil {
			return nil, err
		}
		nuevos = append(nuevos, fs...)
	}
	if e.Cache != nil && clave != "" {
		e.Cache.Guardar(map[string][]finding.Finding{clave: nuevos})
	}
	return nuevos, nil
}

// claveProyectoMypy identifica una comprobación de tipos completa.
//
// Lleva tres cosas y las tres hacen falta:
//
//   - La huella del módulo: los .py/.pyi del proyecto, su configuración de mypy
//     y los manifiestos de dependencias. Los últimos no son decoración — los
//     stubs de terceros (types-requests, el py.typed de una librería) cambian
//     los resultados sin que se toque una línea del repo, y subir una versión
//     en requirements.txt es la única señal legible de ese cambio.
//   - El directorio, porque dos proyectos del mismo monorepo tienen
//     configuraciones distintas.
//   - EL CONJUNTO DE ARCHIVOS ANALIZADOS, que es lo que la distingue de
//     claveProyecto de tsc.go. tsc compila el proyecto entero y le da igual qué
//     se tocó; a mypy se le pasa una lista explícita y sólo reporta sobre ella.
//     Sin esto, un commit de un archivo sembraría el caché y el commit
//     siguiente —con dos archivos y la misma huella de módulo, porque el
//     segundo ya estaba en el árbol— acertaría y se quedaría sin analizar el
//     archivo nuevo. En silencio, que es la peor forma.
//
// Devuelve vacío —no cacheable— si el repo no se puede enumerar, que es lo que
// pasa en los tests con t.TempDir y está bien: sin caché se analiza de nuevo.
func claveProyectoMypy(repoRoot, dir string, rutas []string) string {
	huella := engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		case "mypy.ini", ".mypy.ini", "setup.cfg", "setup.py", "pyproject.toml",
			"poetry.lock", "pdm.lock", "uv.lock", "pipfile", "pipfile.lock",
			"constraints.txt":
			return true
		}
		if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			return true
		}
		return strings.HasSuffix(base, ".py") || strings.HasSuffix(base, ".pyi")
	})
	if huella == "" {
		return ""
	}
	return componerClaveMypy(dir, huella, rutas)
}

// componerClaveMypy es la parte pura de la clave, separada para poder afirmar
// sobre ella en las pruebas sin montar un repo git (HuellaModulo necesita uno
// de verdad, y con t.TempDir devuelve vacío).
//
// Ordena su propia copia porque la clave describe el CONJUNTO de archivos
// analizados, no la lista: dos corridas con los mismos archivos en distinto
// orden dan el mismo análisis y tienen que acertar el mismo caché. Que
// correrProyectoPy ya ordene no lo hace redundante — allí el orden existe para
// que el troceado en lotes sea reproducible, que es otro invariante.
func componerClaveMypy(dir, huella string, rutas []string) string {
	ordenadas := append([]string(nil), rutas...)
	sort.Strings(ordenadas)
	sum := sha256.Sum256([]byte(strings.Join(ordenadas, "\n")))
	return "mypy:" + dir + ":" + huella + ":" + hex.EncodeToString(sum[:])
}

// mypyDiag es un diagnóstico de `--output=json`: una línea JSON por
// diagnóstico (JSON Lines, no un array).
//
// POR QUÉ JSON Y NO EL FORMATO DE TEXTO. Se midieron los dos con mypy 2.3.0
// sobre el mismo archivo y no dan la misma información:
//
//	texto: importa.py:1: error: Library stubs not installed for "yaml"  [import-untyped]
//	       importa.py:1: note: Hint: "python3 -m pip install types-PyYAML"
//	       importa.py:1: note: (or run "mypy --install-types" to install…)
//	       importa.py:1: note: See https://mypy.readthedocs.io/…
//	json:  un solo diagnóstico, con esas tres notas dentro de "hint"
//
// El texto convierte UN problema en CUATRO líneas indistinguibles, todas en la
// misma línea del archivo: parsearlo daría cuatro hallazgos, tres de ellos con
// mensajes que no son problemas sino la explicación del primero. JSON las
// correlaciona por (archivo, línea, columna) y las pliega —está en
// create_errors de mypy/errors.py—, así que el hallazgo sale entero y además
// regala el texto del consejo, que es justo lo que hay que poner en FixHint.
// La bandera existe desde mypy 1.11 y se verificó presente en la versión que
// instala dist/engines.ps1; no hay respaldo al formato de texto porque el
// binario lo ponemos nosotros, no el repo.
type mypyDiag struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
	Message string `json:"message"`
	// Hint son las notas correlacionadas, ya unidas con saltos de línea. Es
	// null en la mayoría de los diagnósticos: unmarshal de null sobre string
	// deja "" y no hace falta puntero.
	Hint string `json:"hint"`
	// Code es null en los errores que no vienen de una regla concreta —el
	// "Duplicate module named" que aborta el análisis es el caso real—, y por
	// eso se comprueba vacío antes de usarlo como RuleKey.
	Code     string `json:"code"`
	Severity string `json:"severity"` // error | note (mypy no emite más: errors.py lo afirma)
}

// codigosDeImport son los diagnósticos que hablan del ENTORNO, no del código.
//
// Se conservan pero NO bloquean, y es una decisión con dos partes.
//
// No se bloquea porque el binario de mypy es NUESTRO, no el del repo: sale del
// pip install de dist/engines.ps1, no del venv del proyecto. Ve por tanto otros
// site-packages que el CI, y "Library stubs not installed for yaml" significa
// casi siempre que en esta máquina falta types-PyYAML, no que el código esté
// mal. Parar un commit por un paquete ausente en el intérprete que resultó
// estar en el PATH es exactamente el obstáculo que este motor no quiere ser.
//
// No se filtran porque un import sin resolver deja en Any todo lo que venía de
// ese módulo, y con ello desaparecen los errores de tipos de verdad: el
// análisis se vuelve hueco sin avisar. Verificado en el proyecto de juguete —
// el mismo import roto arrastra un `Revealed type is "Any"` y un "Returning Any
// from function declared to return int". Callarlo presentaría como limpio un
// análisis que apenas miró. El dev ve el aviso, entiende por qué el informe
// viene flojo y puede instalar los stubs.
//
// Punto ciego asumido: esas consecuencias río abajo (el no-any-return del
// ejemplo) no se pueden atribuir al import con certeza, así que se reportan
// como lo que mypy dice que son.
var codigosDeImport = map[string]bool{
	"import-untyped":   true,
	"import-not-found": true,
	"import":           true,
}

const porQueMypy = "Es la configuración de tipos DEL PROPIO REPO (mypy.ini/[tool.mypy]), no una regla de CodeGuard: el CI la aplicará igual."

// diceSerMypy reconoce la respuesta de `mypy --version`. En esta máquina:
// "mypy 2.3.0 (compiled: yes)". Vale su nombre o un número de versión suelto,
// por si algún envoltorio de entorno virtual responde sólo con el número.
var diceSerMypy = regexp.MustCompile(`(?i)mypy|^\s*\d+\.\d+`)

func correrMypy(ctx context.Context, repoRoot, dir string, rutas []string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(dir))

	// --no-error-summary: el "Found 4 errors in 1 file" no es JSON y ensucia la
	// salida. --show-absolute-path: mypy reporta relativo a SU cwd, y con la
	// ruta absoluta la conversión a relativa-al-repo sale bien también en
	// monorepos, sin concatenar el directorio del proyecto dos veces.
	// El "--" separa banderas de operandos: sin él, un archivo cuyo nombre
	// empiece por "-" (p. ej. "--config=x.py") se leería como bandera de
	// mypy y no como dato. argparse lo consume como fin de opciones.
	args := append([]string{"--no-error-summary", "--show-absolute-path", "--output=json", "--"}, rutas...)
	cmd := exec.CommandContext(ctx, "mypy", args...)
	// El cwd es el directorio de la configuración: mypy busca su mypy.ini /
	// setup.cfg / pyproject.toml ahí, y así aplica la del proyecto y no la de
	// la raíz del monorepo.
	cmd.Dir = abs
	// Sin esto las herramientas de Python leen y escriben en cp1252 en Windows
	// y rompen los acentos de los mensajes. Misma lección que semgrep y ruff.
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)

	// Sólo stdout: los avisos de configuración de mypy ("mypy.ini: [mypy]:
	// Unrecognized option") salen por stderr y pegarlos al JSON lo volvería
	// imparseable. El stderr se guarda para poder explicar los fallos.
	out := bytes.TrimSpace(salida.Stdout)
	motivo := diagnosticoJS(salida.Stderr, salida.Stdout)

	if salida.Recortada {
		return nil, fmt.Errorf("mypy devolvió más de %d MB en %s: el JSON llega a medias y no se puede parsear", proc.MaxSalida>>20, dir)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		// No arrancó: binario ausente, permisos, plazo agotado. El orquestador
		// lo etiqueta "falta:" y `codeguard repair` lo instala con pip.
		return nil, fmt.Errorf("mypy no corrió en %s: %w", dir, runErr)
	}
	codigo := 0
	if exitErr != nil {
		codigo = exitErr.ExitCode()
	}

	// Los códigos de mypy son 0 = limpio, 1 = encontró errores (señal legítima,
	// como semgrep) y 2 = algo abortó la comprobación. Pero el 2 NO se puede
	// tratar como degradación a secas, y esto se midió: un error de sintaxis en
	// un .py sale con 2 y AUN ASÍ escribe su diagnóstico JSON, porque para mypy
	// es un "blocker" —no puede seguir analizando— sin dejar de ser un problema
	// real del código, de los que más tienen que bloquear el commit. Descartar
	// esa salida por el código 2 tiraría el hallazgo más grave que sabe dar.
	//
	// La señal fiable es la de eslint: la ausencia de salida analizable. Si
	// mypy no dejó nada en stdout y salió con 2, entonces sí falló de verdad
	// (opción inválida, config ilegible) y la capa se declara degradada.
	if len(out) == 0 {
		if codigo >= 2 {
			return nil, fmt.Errorf("mypy falló en %s (código %d): %s", dir, codigo, motivo)
		}
		// EL 1 SE QUEDABA FUERA, Y ERA EL CASO QUE MÁS CLARO ESTÁ.
		//
		// El comentario de arriba razona con cuidado sobre el 2 y luego mete el 1
		// y el 0 en la misma frase —"no hay nada que reportar"— cuando significan
		// cosas opuestas. Para mypy el 1 es EXACTAMENTE «encontré errores de
		// tipos»: si salió con 1 y no escribió ni un diagnóstico, lo que encontró
		// se perdió por el camino. Llamar «limpio» a eso es la clase de fallo que
		// dejó entrar un `return centavos` en una función que promete string.
		if codigo == 1 {
			return nil, fmt.Errorf("mypy salió con 1 en %s —su forma de decir «encontré "+
				"errores de tipos»— y no escribió NI UN diagnóstico: %s. Los errores que "+
				"encontró se perdieron, así que la capa de tipos NO está revisada", dir, motivo)
		}
		// Y el 0 sin salida sí es «no hay errores de tipos»… siempre que quien
		// calló fuera mypy. Callar con éxito es justo lo que hace también una
		// herramienta que no analizó nada, y aquí no hay salida que mirar para
		// distinguirlas: hay que preguntarle quién es. Cuesta ~260 ms medidos, lo
		// paga sólo el análisis limpio, y una vez por binario.
		if err := contrato.Identidad(ctx, contrato.Version("mypy", "mypy", "--version",
			diceSerMypy,
			"Comprueba qué resuelve `mypy` en tu PATH (¿un entorno virtual sin activar?) "+
				"o reinstálalo con `codeguard repair`.",
		)); err != nil {
			return nil, err
		}
		return nil, nil
	}
	// La raíz se pasa CRUDA: adivinar de antemano en qué forma (corta 8.3 o
	// larga) escribe mypy sus rutas fue justamente lo que creó el mismatch —
	// esta máquina devuelve la corta. La conciliación de formas vive en
	// relTo, que canonicaliza ambos lados y sirve igual a todos los motores.
	return hallazgosMypy(repoRoot, dir, out)
}

func hallazgosMypy(repoRoot, dir string, raw []byte) ([]finding.Finding, error) {
	var findings []finding.Finding
	for _, linea := range strings.Split(string(raw), "\n") {
		linea = strings.TrimSpace(linea)
		if linea == "" {
			continue
		}
		var d mypyDiag
		if err := json.Unmarshal([]byte(linea), &d); err != nil {
			return nil, fmt.Errorf("salida de mypy ilegible en %s: %v", dir, err)
		}

		// Sin código Y sin ubicación, mypy no está señalando código: está
		// diciendo que no pudo montar el análisis. El caso real es
		// `Duplicate module named "util" (also at "a\util.py")`, que salta en
		// cuanto un commit toca a/util.py y b/util.py sin __init__.py —
		// cotidiano en Python— y llega con line -1, code null y código de
		// salida 2. Convertirlo en hallazgo le inventaría al dev un problema de
		// su código; ignorarlo presentaría como completo un análisis que no
		// ocurrió. Las dos cosas son mentira, así que la capa se degrada, igual
		// que con el internalError de biome.
		if d.Code == "" && d.Line < 1 {
			return nil, fmt.Errorf("mypy no llegó a comprobar tipos en %s: %s", dir, truncarJS(colapsar(d.Message+" "+d.Hint), 400))
		}

		regla := d.Code
		if regla == "" {
			// Sin RuleKey el fingerprint colisionaría con cualquier otro
			// hallazgo del mismo archivo, y `codeguard stats` no podría medir.
			regla = "mypy"
		}

		// Política §7: los errores de tipos BLOQUEAN, igual que tsc y govet.
		// Las notas de mypy (`Revealed type is …`, y las que no acompañan a
		// ningún error) avisan: son información, no veredicto. mypy 2.3.0 sólo
		// emite "error" y "note" —está aseverado en su errors.py—, pero
		// "warning" se contempla por si alguna versión lo estrena.
		sev := finding.Error
		switch strings.ToLower(d.Severity) {
		case "note", "warning":
			sev = finding.Warning
		}
		bloquea := sev == finding.Error
		if codigosDeImport[regla] {
			sev, bloquea = finding.Warning, false
		}

		f := finding.Finding{
			Engine:      "mypy",
			RuleKey:     regla,
			Pillar:      finding.Quality,
			Severity:    sev,
			Blocking:    bloquea,
			File:        rutaRepoJS(repoRoot, dir, d.File),
			Line:        maxLinea(d.Line),
			EndLine:     d.EndLine,
			Message:     d.Message,
			Why:         porQueMypy,
			FixHint:     arregloMypy(regla, d.Hint),
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: d.Message,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

// arregloMypy arma el consejo. Cuando mypy manda un `hint` se usa ÉL y no una
// frase nuestra: ahí viene el comando exacto (`python3 -m pip install
// types-PyYAML`) o el enlace a la explicación del error, y ninguna paráfrasis
// nuestra le va a ganar a eso. Las notas vienen en varias líneas y se aplastan
// a una, que es lo que cabe en el informe.
func arregloMypy(regla, hint string) string {
	if h := strings.TrimSpace(hint); h != "" {
		if codigosDeImport[regla] {
			return "Falta el stub de tipos, no es tu código: " + truncarJS(colapsar(h), 300)
		}
		return truncarJS(colapsar(h), 300)
	}
	if codigosDeImport[regla] {
		return "Instala los stubs del paquete o marca el módulo con `ignore_missing_imports` en la configuración de mypy del repo."
	}
	return "Corrige el tipo señalado; el mensaje de mypy indica el tipo esperado y el recibido. Para silenciarlo, la regla es " + regla + "."
}
