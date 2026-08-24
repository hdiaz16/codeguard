package linters

import (
	"encoding/json"
	"fmt"
	"strings"

	"codeguard/internal/finding"
	"codeguard/internal/textutil"
)

// ── biome ───────────────────────────────────────────────────────────────────

type biomeReporte struct {
	Diagnostics []biomeDiag `json:"diagnostics"`
}

// biomeDiag es un diagnóstico del reporter json de biome, que la propia
// herramienta anuncia como experimental ("The `json` and `json-pretty`
// reporters are experimental and may change in patch releases"). Si el formato
// cambia, el unmarshal falla y la capa queda degradada con un mensaje claro —
// preferible a inventar una tolerancia que acabe tragándose hallazgos.
type biomeDiag struct {
	Severity string `json:"severity"` // error | warning | info
	// Message llega de DOS formas según la versión de biome, y por eso no es un
	// string a secas:
	//
	//	biome antiguo:  "message": "This variable is unused."
	//	biome 2.x:      "message": [{"content": "This variable "},
	//	                            {"elements": ["Emphasis"], "content": "x"},
	//	                            {"content": " is unused."}]
	//
	// Con el tipo string, biome 2.x hacía fallar el unmarshal entero —"cannot
	// unmarshal array into Go struct field"— y la capa de JS/TS quedaba
	// degradada SIN revisar nada. Un repo que hubiera migrado a biome se habría
	// quedado sin linter de JS/TS sin más aviso que una línea de "capas no
	// revisadas".
	//
	// Se descubrió en la verificación de extremo a extremo de la fase 4, la
	// primera vez que alguien le puso a este motor un repo con biome delante.
	Message  mensajeBiome `json:"message"`
	Category string       `json:"category"` // lint/suspicious/noDoubleEquals, format, internalError/io…
	// Location cambió de forma entera en biome 2.x y hay que aceptar las dos.
	//
	//	biome 1.x: {"path": "a.ts", "start": {"line": 3}, "end": {"line": 3}}
	//	biome 2.x: {"path": {"file": "a.ts"}, "span": [42, 49],
	//	            "sourceCode": "…el archivo entero…"}
	//
	// En la 2.x ni siquiera hay número de línea: hay desplazamientos de BYTES
	// dentro del código fuente, que viene adjunto. La línea se cuenta a partir
	// de ahí. Un adaptador que no lo hiciera reportaría todo en la línea 0 —o
	// fallaría, que es lo que hacía— y en cualquiera de los dos casos la capa
	// de JS/TS de un repo con biome no revisaba nada.
	Location struct {
		Path   rutaBiome `json:"path"`
		Span   []int     `json:"span"`
		Fuente string    `json:"sourceCode"`
		Start  struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
	} `json:"location"`
	// Advices es donde biome esconde la corrección: no hay campo booleano de
	// "fixable", sino un consejo cuyo texto empieza por "Safe fix:" o
	// "Unsafe fix:". La distinción vale porque se aplican con comandos
	// distintos.
	//
	// Se recibe en CRUDO y se interpreta con tolerancia, a diferencia del resto
	// del diagnóstico. El motivo: biome 2.x cambió su forma —era un arreglo de
	// {text}, ahora es un objeto— y con un tipo rígido el unmarshal fallaba
	// ENTERO, dejando la capa de JS/TS degradada sin revisar nada. Perder la
	// pista de "cómo se arregla" es una molestia; perder los hallazgos es una
	// compuerta apagada. Los campos que SÍ son esenciales —categoría,
	// severidad, ubicación, mensaje— siguen siendo estrictos: si esos cambian,
	// tiene que fallar ruidosamente.
	Advices json.RawMessage `json:"advices"`
}

const porQueBiome = "Es la configuración de biome DEL PROPIO REPO (biome.json), no una regla de CodeGuard: el CI la aplicará igual."

func hallazgosBiome(repoRoot, dir string, raw []byte) ([]finding.Finding, error) {
	var rep biomeReporte
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("salida de biome ilegible en %s: %v", dir, err)
	}
	var findings []finding.Finding
	for _, d := range rep.Diagnostics {
		// internalError/*: biome NO analizó lo que se le pidió (no encontró el
		// archivo, no pudo leerlo) y lo cuenta como un diagnóstico más, con
		// código de salida 1, igual que un hallazgo de verdad. Tratarlo como
		// hallazgo sería reportarle al dev un problema de su código que no
		// existe; ignorarlo sería peor: presentaría el análisis como completo
		// cuando faltan archivos. Es el mismo fallo que semgrep enseñó con su
		// SemgrepError, y se corta igual — la capa se declara degradada.
		if strings.HasPrefix(d.Category, "internalError/") {
			return nil, fmt.Errorf("biome no llegó a analizar en %s (%s): %s", dir, d.Category, truncarJS(colapsar(string(d.Message)), 300))
		}
		file := rutaRepoJS(repoRoot, dir, string(d.Location.Path))
		enPry := enProyecto(dir, file)

		sev := finding.Warning
		switch strings.ToLower(d.Severity) {
		case "error":
			sev = finding.Error
		case "info":
			sev = finding.Info
		}

		regla := d.Category
		mensaje := string(d.Message)
		fix := arregloBiome(dir, enPry, regla, d.Advices)
		if d.Category == "format" {
			// El mensaje literal de biome es "Formatter would have printed the
			// following content:" y el contenido va en un advice que el reporter
			// json deja vacío: tal cual, el hallazgo no diría nada. Se sustituye
			// por el enunciado que ya usan gofmt y ruff para lo mismo, y la
			// posición se descarta porque biome manda línea 0 (el archivo entero
			// es lo que está mal formateado, no una línea).
			mensaje = "Archivo sin formatear (biome format)"
			fix = "Auto-corregible: " + comandoJS(dir, "npx biome format --write", enPry) + "."
		}

		f := finding.Finding{
			Engine:  string(hBiome),
			RuleKey: regla,
			Pillar:  finding.Quality,
			// Misma política §7 que eslint: error bloquea, warning e info avisan.
			// biome trae en su preset "recommended" bastantes reglas como warning
			// (noExplicitAny, noUnusedVariables) y ésas no paran el commit.
			Severity: sev,
			Blocking: sev == finding.Error,
			File:     file,
			Line:     lineaBiome(d.Location.Start.Line, d.Location.Span, d.Location.Fuente),
			EndLine:  d.Location.End.Line,
			Message:  mensaje,
			Why:      porQueBiome,
			FixHint:  fix,
			Verified: true,
			Source:   finding.Deterministic,
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// arregloBiome traduce los advices a un consejo con el comando concreto.
// "Safe fix" lo aplica `biome check --write`; "Unsafe fix" exige --unsafe y
// que alguien lo revise, y decirlo evita que el dev lo ejecute a ciegas.
//
// Sin advice no se promete comando ninguno: el reporter json los deja vacíos a
// menudo, y decir "córrelo con --write" cuando biome no ofrece corrección haría
// que el dev lo ejecutara, no viera cambio alguno y dejara de leer los consejos.
// Se le da entonces el nombre exacto de la regla, que es lo que necesita para
// buscarla o silenciarla en biome.json.
func arregloBiome(dir, enPry, categoria string, advices json.RawMessage) string {
	for _, t := range textosDeAdvices(advices) {
		switch {
		case strings.HasPrefix(t, "Safe fix"):
			return "Auto-corregible: " + comandoJS(dir, "npx biome check --write", enPry) + " (" + t + ")."
		case strings.HasPrefix(t, "Unsafe fix"):
			return "Corrección disponible pero marcada insegura por biome: " +
				comandoJS(dir, "npx biome check --write --unsafe", enPry) + " (" + t + "). Revisa el resultado."
		}
	}
	return "Revisa la regla " + categoria + " en la configuración de biome del repo."
}

// mensajeBiome acepta las dos formas del campo `message` de biome: la cadena de
// las versiones antiguas y el arreglo de fragmentos de la 2.x.
//
// Se implementa como UnmarshalJSON y no relajando el tipo a `any` porque la
// diferencia hay que resolverla una vez, aquí, y no en cada sitio que use el
// mensaje. Si mañana biome inventa una tercera forma, esto falla con un texto
// que dice cuál es — mejor que devolver una cadena vacía y reportar hallazgos
// sin mensaje, que es la variante silenciosa del mismo problema.
type mensajeBiome string

func (m *mensajeBiome) UnmarshalJSON(b []byte) error {
	var texto string
	if err := json.Unmarshal(b, &texto); err == nil {
		*m = mensajeBiome(texto)
		return nil
	}
	var fragmentos []struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(b, &fragmentos); err != nil {
		return fmt.Errorf("mensaje de biome en un formato desconocido: %s", recorteBiome(b))
	}
	var sb strings.Builder
	for _, f := range fragmentos {
		sb.WriteString(f.Content)
	}
	*m = mensajeBiome(sb.String())
	return nil
}

func recorteBiome(b []byte) string {
	if len(b) > 120 {
		return textutil.TruncarRunas(string(b), 117) + "…"
	}
	return string(b)
}

// textosDeAdvices saca los textos de los consejos, sea cual sea la forma que
// tenga hoy ese campo en biome.
//
// Recorre el JSON en crudo recogiendo cualquier cadena que aparezca: es
// deliberadamente laxo porque de aquí sólo sale una PISTA de corrección, y una
// pista que falta no puede costar el análisis entero. Lo único que se busca es
// un texto que empiece por "Safe fix" o "Unsafe fix".
func textosDeAdvices(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var out []string
	var recorrer func(any)
	recorrer = func(x any) {
		switch t := x.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				out = append(out, s)
			}
		case []any:
			for _, e := range t {
				recorrer(e)
			}
		case map[string]any:
			for _, e := range t {
				recorrer(e)
			}
		}
	}
	recorrer(v)
	return out
}

// rutaBiome acepta el campo `path` en sus dos formas: la cadena de biome 1.x y
// el objeto {"file": "..."} de la 2.x.
type rutaBiome string

func (r *rutaBiome) UnmarshalJSON(b []byte) error {
	var texto string
	if err := json.Unmarshal(b, &texto); err == nil {
		*r = rutaBiome(texto)
		return nil
	}
	var obj struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("ruta de biome en un formato desconocido: %s", recorteBiome(b))
	}
	*r = rutaBiome(obj.File)
	return nil
}

// lineaBiome resuelve el número de línea del diagnóstico.
//
// Si biome dio la línea directamente (1.x) se usa esa. Si dio un span de bytes
// y el código fuente (2.x), se cuenta: la línea es 1 más los saltos que haya
// antes del desplazamiento inicial.
//
// Devolver 1 cuando no hay forma de saberlo es deliberado: un hallazgo en la
// línea equivocada sigue señalando el archivo correcto, y eso vale más que
// descartarlo. Lo que no puede pasar es reportar línea 0, que ningún editor
// abre.
func lineaBiome(linea int, span []int, fuente string) int {
	if linea > 0 {
		return linea
	}
	if len(span) == 0 || fuente == "" {
		return 1
	}
	// El span sale del JSON de biome sin pasar por ninguna validación, y se usa
	// para rebanar. Se comprobaba sólo la cota superior, dando por supuesta la
	// inferior porque biome "debería" mandar desplazamientos válidos: con un
	// valor negativo, la rebanada panica y tumba el análisis ENTERO —los demás
	// diagnósticos, los demás proyectos—, no sólo la línea de este hallazgo.
	// Se comprueba el invariante completo.
	desplazamiento := span[0]
	if desplazamiento < 0 || desplazamiento > len(fuente) {
		return 1
	}
	return 1 + strings.Count(fuente[:desplazamiento], "\n")
}
