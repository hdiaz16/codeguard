package linters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// ESLint cubre el hueco de formato y estilo en TS/JS. Hasta aquí ese lado del
// producto sólo tenía tsc (tipos) y las reglas de la casa de semgrep: nada de
// formato ni de convenciones, mientras Go llevaba gofmt+govet+staticcheck.
//
// La decisión que da forma a todo el motor: NO IMPONE ESTILO. Corre el linter
// que el repo YA configuró y aplica SUS reglas, no las nuestras. Un proyecto
// que no configura ninguno queda fuera (Applies falso para él), por el mismo
// motivo por el que gofmt no bloquea por finales de línea: hacer fallar un
// commit por una convención que el equipo no eligió convierte al agente en un
// obstáculo, y un obstáculo se desinstala.
//
// Un solo Engine sabe correr las dos herramientas del ecosistema porque son
// alternativas excluyentes del mismo trabajo, no capas distintas. El nombre que
// viaja en el hallazgo es el de la herramienta REAL —"eslint" o "biome"— para
// que el dev sepa quién le habla y `codeguard stats` mida por herramienta.
type ESLint struct {
	// Cache es por ARCHIVO (estos linters analizan archivo a archivo, a
	// diferencia de tsc que compila el proyecto entero). La clave lleva además
	// la huella de la configuración: ver claveDeArchivo.
	Cache engines.Cache
}

func (ESLint) Name() string { return "eslint" }

func (e ESLint) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// herramienta es cuál de las dos configuró el repo. Es también el valor que va
// en Finding.Engine.
type herramienta string

const (
	hESLint herramienta = "eslint"
	hBiome  herramienta = "biome"
)

// extensionesJS son los archivos que estos linters entienden.
//
// .mts y .cts entran aunque tsc.go sólo mire .ts/.tsx: un módulo TypeScript con
// extensión explícita es código de producción igual, y dejarlo sin lintar sería
// exactamente el punto ciego silencioso que este motor viene a cerrar.
var extensionesJS = []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}

// configsBiome y configsESLint son los manifiestos que declaran "este proyecto
// tiene linter". No se leen: sólo su presencia decide, y su contenido entra en
// la clave de caché.
var configsBiome = []string{"biome.json", "biome.jsonc"}

// El orden importa dentro de eslint: da igual cuál se encuentre primero, todos
// significan lo mismo. Se incluyen los .eslintrc heredados a propósito — eslint
// 10 ya no los soporta, pero un repo con .eslintrc tiene eslint 8 clavado en su
// package.json, y es SU binario el que corremos. Detectar la intención del repo
// y ejecutar su herramienta son dos cosas distintas.
var configsESLint = []string{
	"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts",
	"eslint.config.mts", "eslint.config.cts",
	".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.mjs",
	".eslintrc.json", ".eslintrc.yml", ".eslintrc.yaml",
}

// proyectoJS es un grupo de archivos tocados que comparten configuración: el
// directorio del manifiesto, la herramienta que declara y los archivos que le
// tocan.
type proyectoJS struct {
	dir      string // relativo a la raíz, "." si es la propia raíz
	tool     herramienta
	archivos []gitdiff.ChangedFile
}

// proyectos agrupa los archivos JS/TS tocados por el manifiesto de linter más
// cercano, subiendo desde cada archivo (el mismo descubrimiento que tsc.go: en
// el monorepo típico la configuración vive en frontend/, no en la raíz, y mirar
// sólo la raíz deja la compuerta enrolada sin correr jamás).
func (ESLint) proyectos(in engines.Input) []proyectoJS {
	idx := map[string]*proyectoJS{}
	for _, f := range in.Files {
		if f.Status == "D" || !esJS(f.Path) {
			continue
		}
		dir, tool, ok := linterDe(in.RepoRoot, f.Path)
		if !ok {
			continue // proyecto sin linter configurado: no es asunto nuestro
		}
		clave := dir + "\x00" + string(tool)
		p := idx[clave]
		if p == nil {
			p = &proyectoJS{dir: dir, tool: tool}
			idx[clave] = p
		}
		p.archivos = append(p.archivos, f)
	}
	out := make([]proyectoJS, 0, len(idx))
	for _, p := range idx {
		out = append(out, *p)
	}
	// Orden estable: el informe no debe cambiar de forma entre dos corridas
	// idénticas sólo por el recorrido de un mapa.
	sort.Slice(out, func(i, j int) bool {
		if out[i].dir != out[j].dir {
			return out[i].dir < out[j].dir
		}
		return out[i].tool < out[j].tool
	})
	return out
}

func esJS(rel string) bool {
	ext := strings.ToLower(path.Ext(rel))
	for _, e := range extensionesJS {
		if ext == e {
			return true
		}
	}
	return false
}

// linterDe sube desde el archivo hasta el primer directorio que configure un
// linter, sin salirse de la raíz ni entrar a node_modules.
//
// Cuando un mismo directorio configura las dos, gana biome. No es un empate
// arbitrario: biome.json aparece en un repo porque alguien MIGRÓ a biome, y la
// migración deja el eslintrc viejo atrás durante semanas. Elegir eslint ahí
// aplicaría las reglas que el equipo acaba de abandonar. El orden inverso
// —biome primero— es el que respeta la decisión más reciente.
//
// La comprobación es por nivel, no global: si la raíz tiene biome.json y
// frontend/ tiene eslint.config.js, un archivo de frontend/ se linta con
// eslint. Gana lo más cercano, y sólo se desempata dentro del mismo directorio.
func linterDe(repoRoot, rel string) (string, herramienta, bool) {
	if strings.Contains(rel, "node_modules/") {
		return "", "", false
	}
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
		if hayAlguno(abs, configsBiome) {
			return dir, hBiome, true
		}
		if hayAlguno(abs, configsESLint) {
			return dir, hESLint, true
		}
		if dir == "." || dir == "/" {
			return "", "", false
		}
		dir = path.Dir(dir)
	}
}

func hayAlguno(absDir string, nombres []string) bool {
	for _, n := range nombres {
		if st, err := os.Stat(filepath.Join(absDir, n)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// maxLineaComandosJS acota los argumentos de una invocación.
//
// El límite aquí NO es el de semgrep. Los binarios de node se instalan como
// shims .cmd (node_modules\.bin\eslint.cmd, y npx.cmd), o sea scripts batch:
// Windows los ejecuta a través de cmd.exe, que corta en 8191 caracteres — no en
// los 32767 de CreateProcess. La primera versión de este motor usó 30000
// copiando la razón de semgrep (que invoca un .exe de verdad) y murió en el
// primer repo real con frontend: `codeguard report` sobre bds.portal degradó el
// motor con el mensaje de cmd.exe, "The command line is too long".
//
// 6000 deja sitio de sobra para la ruta del binario y las banderas. El troceado
// existía ya; lo que estaba mal era el número.
const maxLineaComandosJS = 6000

// objetivoJS es un archivo a analizar: la ruta que recibe la herramienta
// (relativa al proyecto), la que viaja en el hallazgo (relativa al repo) y su
// clave de caché.
type objetivoJS struct {
	rel   string // relativo al repo, separador /
	enPry string // relativo al directorio del proyecto
	clave string // vacío = no cacheable
}

func (e ESLint) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range e.proyectos(in) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fs, err := e.correrProyectoJS(ctx, in.RepoRoot, p)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (e ESLint) correrProyectoJS(ctx context.Context, repoRoot string, p proyectoJS) ([]finding.Finding, error) {
	// La huella de la configuración se calcula UNA vez por proyecto: es la parte
	// cara de la clave y es idéntica para todos sus archivos.
	huella := ""
	if e.Cache != nil {
		huella = huellaConfigJS(repoRoot, p.dir)
	}

	var pendientes []objetivoJS
	for _, f := range p.archivos {
		o := objetivoJS{rel: f.Path, enPry: enProyecto(p.dir, f.Path)}
		if huella != "" && f.SHA256 != "" {
			o.clave = claveDeArchivo(p.tool, huella, f.SHA256)
		}
		pendientes = append(pendientes, o)
	}

	// ── Aciertos de caché ──
	// El caché está direccionado por CONTENIDO (la clave no lleva la ruta), así
	// que dos archivos idénticos comparten entrada; al reproducir un acierto hay
	// que reescribir la ruta y recalcular el fingerprint para el archivo de esta
	// corrida. Mismo mecanismo que semgrep.
	var findings []finding.Finding
	if e.Cache != nil {
		var claves []string
		for _, o := range pendientes {
			if o.clave != "" {
				claves = append(claves, o.clave)
			}
		}
		aciertos := e.Cache.Leer(claves)
		var quedan []objetivoJS
		for _, o := range pendientes {
			fs, ok := aciertos[o.clave]
			if o.clave == "" || !ok {
				quedan = append(quedan, o)
				continue
			}
			for _, f := range fs {
				if f.File != o.rel {
					f.File = o.rel
					f.ComputeFingerprint()
				}
				findings = append(findings, f)
			}
		}
		pendientes = quedan
	}
	if len(pendientes) == 0 {
		return findings, nil
	}

	rutas := make([]string, len(pendientes))
	for i, o := range pendientes {
		rutas[i] = o.enPry
	}

	var nuevos []finding.Finding
	for _, lote := range lotesDeRutas(rutas, maxLineaComandosJS) {
		fs, err := correrLinterJS(ctx, repoRoot, p.dir, p.tool, lote)
		if err != nil {
			return nil, err
		}
		nuevos = append(nuevos, fs...)
	}
	if e.Cache != nil {
		e.Cache.Guardar(cacheDeArchivosJS(nuevos, pendientes))
	}
	return append(findings, nuevos...), nil
}

// claveDeArchivo compone la clave de caché de un archivo.
//
// El sha del contenido NO basta. Las reglas que se aplican a ese contenido
// vienen de la configuración del repo, y editar .eslintrc cambia los hallazgos
// sin tocar una sola línea de código: servir el resultado viejo sería reportar
// las reglas de ayer. Por eso la clave es herramienta + huella de la config +
// contenido, y no sólo lo último.
//
// La herramienta va delante porque eslint y biome dan hallazgos distintos para
// el mismo archivo, y un repo a mitad de migración tiene proyectos de las dos
// convivendo.
func claveDeArchivo(tool herramienta, huellaConfig, shaArchivo string) string {
	return string(tool) + ":" + huellaConfig + ":" + shaArchivo
}

// huellaConfigJS resume la configuración de lint que gobierna un proyecto.
//
// Incluye los manifiestos de linter y TAMBIÉN package.json y los lockfiles, y
// eso es deliberado: en eslint las reglas no viven en el archivo de config sino
// en los plugins que éste extiende (eslint-config-airbnb,
// @typescript-eslint/...). Subir la versión de un plugin cambia los hallazgos
// con el .eslintrc intacto, y el lockfile es la única señal de ese cambio que
// se puede leer sin resolver node_modules entero.
//
// Punto ciego asumido, el mismo que tsc.go: el estado real de node_modules más
// allá del lockfile no se comprueba, y una config compartida que se importe
// desde FUERA del directorio del proyecto queda fuera de la huella. Devuelve
// vacío —no cacheable— si el repo no se puede enumerar, que es lo que pasa en
// los tests con t.TempDir y está bien: sin caché se analiza de nuevo.
func huellaConfigJS(repoRoot, dir string) string {
	return engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
			"npm-shrinkwrap.json", "bun.lock", "bun.lockb", ".eslintignore":
			return true
		}
		for _, n := range configsBiome {
			if base == n {
				return true
			}
		}
		return strings.HasPrefix(base, "eslint.config.") || strings.HasPrefix(base, ".eslintrc")
	})
}

// enProyecto pasa una ruta relativa al repo a relativa al directorio del
// proyecto, que es el cwd con el que se invoca la herramienta.
func enProyecto(dir, rel string) string {
	if dir == "." || dir == "" {
		return rel
	}
	return strings.TrimPrefix(rel, strings.TrimSuffix(dir, "/")+"/")
}

// cacheDeArchivosJS atribuye los hallazgos nuevos a su archivo y devuelve
// clave → hallazgos. Los archivos analizados sin hallazgos entran con lista
// vacía: "analizado y limpio" es el resultado que más veces se reutiliza.
func cacheDeArchivosJS(fs []finding.Finding, analizados []objetivoJS) map[string][]finding.Finding {
	clavePorRel := make(map[string]string, len(analizados))
	out := make(map[string][]finding.Finding, len(analizados))
	for _, o := range analizados {
		if o.clave == "" {
			continue
		}
		clavePorRel[o.rel] = o.clave
		out[o.clave] = []finding.Finding{}
	}
	for _, f := range fs {
		if clave, ok := clavePorRel[f.File]; ok {
			out[clave] = append(out[clave], f)
		}
	}
	return out
}

// lotesDeRutas reparte las rutas en grupos que caben en el límite. Una ruta que
// por sí sola lo excediera va en su propio lote: recortarla dejaría un archivo
// sin analizar en silencio, que es justo lo que el troceado evita.
func lotesDeRutas(rutas []string, limite int) [][]string {
	var out [][]string
	actual := []string{}
	largo := 0
	for _, r := range rutas {
		coste := len(r) + 3 // +3: el espacio separador y las comillas del shell
		if len(actual) > 0 && largo+coste > limite {
			out = append(out, actual)
			actual, largo = []string{}, 0
		}
		actual = append(actual, r)
		largo += coste
	}
	if len(actual) > 0 {
		out = append(out, actual)
	}
	return out
}

// binarioJS resuelve el ejecutable de la herramienta: primero el del propio
// proyecto, que es el que usa el CI y el que fija la versión; si no está, npx
// con --no-install para que NUNCA descargue nada a mitad de un pre-commit.
//
// En Windows los binarios de npm son .cmd, no .exe. Con workspaces el
// node_modules suele estar hoisted a la raíz del monorepo y no junto al
// manifiesto: ahí falla el lookup local y entra npx, que sí resuelve subiendo.
func binarioJS(absProyecto string, tool herramienta) (string, []string) {
	if st, err := os.Stat(filepath.Join(absProyecto, "node_modules", ".bin", string(tool)+".cmd")); err == nil && !st.IsDir() {
		return filepath.Join(absProyecto, "node_modules", ".bin", string(tool)+".cmd"), nil
	}
	paquete := "eslint"
	if tool == hBiome {
		paquete = "@biomejs/biome" // el paquete no se llama como su binario
	}
	return "npx.cmd", []string{"--no-install", paquete}
}

func correrLinterJS(ctx context.Context, repoRoot, dir string, tool herramienta, rutas []string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
	bin, args := binarioJS(abs, tool)

	if tool == hBiome {
		args = append(args, "check", "--reporter=json")
	} else {
		// --no-error-on-unmatched-pattern: sin esto, UN archivo que desapareció
		// entre el diff y el análisis hace salir a eslint con 2 y se pierde el
		// lote completo. Verificado en eslint 8.57 y 10.8: ambos lo aceptan.
		//
		// Lo que NO se pasa es --no-warn-ignored, y esa ausencia es empírica:
		// eslint 8.57 lo rechaza ("Invalid option '--warn-ignored'") y sale con
		// 2, así que pasarlo convertiría en fallo duro todos los repos que aún
		// van con eslint 8 y .eslintrc — que son muchos. Los avisos de archivo
		// ignorado se filtran al parsear, que funciona con cualquier versión.
		args = append(args, "--format", "json", "--no-error-on-unmatched-pattern")
	}
	args = append(args, rutas...)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = abs
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)

	// Se lee stdout SOLO, nunca la salida combinada: biome escribe en stderr
	// "The `json` and `json-pretty` reporters are experimental…" más su barra de
	// progreso, y pegar eso al JSON lo vuelve imparseable. El stderr se guarda
	// para poder explicar los fallos.
	out := bytes.TrimSpace(salida.Stdout)
	motivo := diagnosticoJS(salida.Stderr, salida.Stdout)

	if salida.Recortada {
		return nil, fmt.Errorf("%s devolvió más de %d MB en %s: el JSON llega a medias y no se puede parsear", tool, proc.MaxSalida>>20, dir)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		// No arrancó: binario ausente, permisos, plazo agotado. El orquestador lo
		// etiqueta "falta:" — eslint y biome son dependencias DEL PROYECTO, no
		// herramientas nuestras, así que no hay nada que instalemos por él.
		return nil, fmt.Errorf("%s no corrió en %s: %w", tool, dir, runErr)
	}
	codigo := 0
	if exitErr != nil {
		codigo = exitErr.ExitCode()
	}

	// Aquí está la distinción que importa: salir con 1 es la forma NORMAL de
	// decir "encontré problemas" —como semgrep— y su JSON es válido y completo.
	// eslint reserva el 2 para el fallo real (config ilegible, opción inválida) y
	// entonces no escribe JSON en absoluto, sino un "Oops! Something went wrong!"
	// en stderr. Confundir los dos casos significaría, en un sentido, ignorar
	// hallazgos legítimos y, en el otro, anunciar "0 problemas" cuando el linter
	// ni arrancó.
	if tool == hESLint && codigo >= 2 {
		return nil, fmt.Errorf("eslint falló en %s (código %d): %s", dir, codigo, motivo)
	}
	// biome no documenta un código dedicado al fallo real: su config rota también
	// sale con 1, pero sin nada en stdout. La ausencia de JSON es la señal fiable
	// para las dos herramientas, y cubre el caso en que eslint cambie de códigos.
	if len(out) == 0 {
		return nil, fmt.Errorf("%s no dejó salida analizable en %s (código %d): %s", tool, dir, codigo, motivo)
	}

	if tool == hBiome {
		return hallazgosBiome(repoRoot, dir, out)
	}
	return hallazgosESLint(repoRoot, dir, out)
}

// diagnosticoJS elige el texto con el que explicarle al dev por qué no hubo
// análisis. stderr primero: es donde las dos herramientas ponen el motivo real.
func diagnosticoJS(stderr, stdout []byte) string {
	txt := strings.TrimSpace(string(stderr))
	if txt == "" {
		txt = strings.TrimSpace(string(stdout))
	}
	if txt == "" {
		return "sin salida"
	}
	return truncarJS(colapsar(txt), 400)
}

// colapsar aplasta el texto a una línea: las dos herramientas adornan sus
// errores con barras de progreso y marcos de caracteres que en una sola línea
// del informe no aportan nada.
func colapsar(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func truncarJS(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── eslint ──────────────────────────────────────────────────────────────────

type eslintArchivo struct {
	FilePath string          `json:"filePath"`
	Messages []eslintMensaje `json:"messages"`
}

type eslintMensaje struct {
	// RuleID es null en los mensajes que no vienen de una regla: los errores de
	// parseo y los avisos sobre el archivo (ignorado, sin config que lo cubra).
	// Por eso es puntero y no string.
	RuleID   *string `json:"ruleId"`
	Severity int     `json:"severity"`
	Message  string  `json:"message"`
	Line     int     `json:"line"`
	EndLine  int     `json:"endLine"`
	Fatal    bool    `json:"fatal"`
	// Fix presente = `eslint --fix` lo arregla solo. Distinto de Suggestions,
	// que --fix NO aplica porque exigen que alguien elija.
	Fix         *json.RawMessage  `json:"fix"`
	Suggestions []json.RawMessage `json:"suggestions"`
}

// porQueESLint: el dev tiene que entender que esto no es una regla nuestra.
const porQueESLint = "Es la configuración de lint DEL PROPIO REPO (eslint.config/.eslintrc), no una regla de CodeGuard: el CI la aplicará igual."

func hallazgosESLint(repoRoot, dir string, raw []byte) ([]finding.Finding, error) {
	var archivos []eslintArchivo
	if err := json.Unmarshal(raw, &archivos); err != nil {
		return nil, fmt.Errorf("salida de eslint ilegible en %s: %v", dir, err)
	}
	var findings []finding.Finding
	for _, a := range archivos {
		file := rutaRepoJS(repoRoot, dir, a.FilePath)
		enPry := enProyecto(dir, file)
		for _, m := range a.Messages {
			regla := ""
			if m.RuleID != nil {
				regla = *m.RuleID
			}
			// Sin regla y sin ser fatal, el mensaje habla DEL ARCHIVO, no del
			// código: "File ignored because of a matching ignore pattern" o
			// "File ignored because no matching configuration was supplied".
			// El segundo salta en cuanto se le pasa un .ts a una config que sólo
			// cubre .js —lo normal— y convertirlo en hallazgo llenaría el informe
			// de avisos sobre archivos que el repo decidió no lintar.
			if regla == "" && !m.Fatal {
				continue
			}
			sev := finding.Warning
			if m.Severity >= 2 {
				sev = finding.Error
			}
			mensaje := m.Message
			fix := "Revisa la regla " + regla + " en la configuración de lint del repo."
			switch {
			case regla == "":
				// Error de parseo: eslint no pudo ni leer el archivo. Se reporta
				// como error porque el CI dirá lo mismo, pero el consejo apunta al
				// otro motivo posible: que el parser del repo no cubra este tipo
				// de archivo.
				regla = "parsing-error"
				fix = "Corrige la sintaxis señalada; si el archivo es válido, la config de eslint no tiene parser para este tipo de archivo."
			case m.Fix != nil:
				fix = "Auto-corregible: " + comandoJS(dir, "npx eslint --fix", enPry) + "."
			case len(m.Suggestions) > 0:
				// Precisión deliberada: `--fix` no las aplica. Prometer lo
				// contrario haría que el dev lo ejecutara, viera que nada cambia y
				// dejara de creerse los FixHint.
				fix = "Hay que corregirlo a mano: la regla " + regla + " sólo ofrece sugerencias, y `--fix` no las aplica."
			}
			f := finding.Finding{
				Engine:  string(hESLint),
				RuleKey: regla,
				Pillar:  finding.Quality,
				// Política §7: lint de severidad error BLOQUEA, igual que govet.
				// severity 1 (warn) avisa: es lo que el repo marcó como "quiero
				// verlo, no quiero que me pare".
				Severity:    sev,
				Blocking:    sev == finding.Error,
				File:        file,
				Line:        maxLinea(m.Line),
				EndLine:     m.EndLine,
				Message:     mensaje,
				Why:         porQueESLint,
				FixHint:     fix,
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: mensaje,
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}

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
	Message  string `json:"message"`
	Category string `json:"category"` // lint/suspicious/noDoubleEquals, format, internalError/io…
	Location struct {
		Path  string `json:"path"`
		Start struct {
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
	Advices []struct {
		Text string `json:"text"`
	} `json:"advices"`
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
			return nil, fmt.Errorf("biome no llegó a analizar en %s (%s): %s", dir, d.Category, truncarJS(colapsar(d.Message), 300))
		}
		file := rutaRepoJS(repoRoot, dir, d.Location.Path)
		enPry := enProyecto(dir, file)

		sev := finding.Warning
		switch strings.ToLower(d.Severity) {
		case "error":
			sev = finding.Error
		case "info":
			sev = finding.Info
		}

		regla := d.Category
		mensaje := d.Message
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
			Severity:    sev,
			Blocking:    sev == finding.Error,
			File:        file,
			Line:        maxLinea(d.Location.Start.Line),
			EndLine:     d.Location.End.Line,
			Message:     mensaje,
			Why:         porQueBiome,
			FixHint:     fix,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: mensaje,
		}
		f.ComputeFingerprint()
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
func arregloBiome(dir, enPry, categoria string, advices []struct {
	Text string `json:"text"`
}) string {
	for _, a := range advices {
		t := strings.TrimSpace(a.Text)
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

// ── comunes ─────────────────────────────────────────────────────────────────

// rutaRepoJS normaliza la ruta que reportó la herramienta a "relativa al repo
// con separador /".
//
// Hay que aceptar las dos formas porque las dos herramientas no coinciden:
// eslint devuelve rutas ABSOLUTAS con barra invertida de Windows, y biome las
// devuelve relativas a su cwd —también con barra invertida, aunque se le pasen
// con barra normal—. Y biome mezcla: en sus internalError sí manda la absoluta.
//
// Las barras invertidas se normalizan a mano y no con filepath porque los
// payloads son de Windows: así el parseo da el mismo resultado en cualquier
// plataforma donde se compile el repo, y las pruebas que usan capturas reales
// no dependen de dónde corran.
func rutaRepoJS(repoRoot, dir, p string) string {
	if p == "" {
		return ""
	}
	limpia := strings.ReplaceAll(p, `\`, "/")
	if esAbsolutaJS(limpia) {
		// relTo comprueba que el resultado caiga DENTRO de la raíz y reintenta
		// con la raíz canónica si no. Antes se usaba filepath.Rel a secas, y
		// Rel "tiene éxito" devolviendo `../../..` cuando las dos rutas son del
		// mismo disco pero apuntan a sitios distintos — el hallazgo salía con
		// una ruta que ningún editor abre, que no casa con la baseline y que no
		// coincide con ningún archivo del diff: desaparecía en silencio.
		return relTo(repoRoot, filepath.FromSlash(limpia))
	}
	if dir != "." && dir != "" {
		return path.Join(dir, limpia)
	}
	return limpia
}

// esAbsolutaJS reconoce la forma de Windows (C:/…) y la de POSIX sin preguntarle
// al sistema operativo, por el motivo de arriba.
func esAbsolutaJS(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/'
}

// comandoJS arma la orden que el dev debe teclear. Cuando el proyecto no está
// en la raíz hay que decir desde dónde: `npx eslint` ejecutado en la raíz de un
// monorepo usa otro eslint (u ninguno) y otra config.
func comandoJS(dir, orden, enPry string) string {
	if dir == "." || dir == "" {
		return "`" + orden + " " + enPry + "`"
	}
	return "`" + orden + " " + enPry + "` desde " + dir + "/"
}

// maxLinea garantiza una línea válida. biome manda 0 en los diagnósticos que
// son del archivo entero (el de formato) y un 0 en el informe se lee como
// "sin ubicación", que rompe la navegación del editor.
func maxLinea(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
