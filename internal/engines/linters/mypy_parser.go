package linters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

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
			Engine:   "mypy",
			RuleKey:  regla,
			Pillar:   finding.Quality,
			Severity: sev,
			Blocking: bloquea,
			File:     rutaRepoJS(repoRoot, dir, d.File),
			Line:     maxLinea(d.Line),
			EndLine:  d.EndLine,
			Message:  d.Message,
			Why:      porQueMypy,
			FixHint:  arregloMypy(regla, d.Hint),
			Verified: true,
			Source:   finding.Deterministic,
		}
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
