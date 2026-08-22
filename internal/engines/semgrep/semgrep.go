package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string // vacío = buscar en PATH
	// Cache, si no es nil, evita correr semgrep sobre archivos cuyo contenido
	// exacto ya se analizó con este rulepack y esta config (§9, file_cache).
	Cache Cache
}

// ErrSinRulepack: el repo apunta a una versión de rulepack que no está
// instalada. Merece su propio error porque no es "semgrep falló": es la
// promesa de paridad con el CI rota, y el desarrollador necesita saberlo
// con esas palabras.
var ErrSinRulepack = errors.New("no encuentro el rulepack al que apunta este repo")

func (e *Engine) Name() string { return "semgrep" }

func (e *Engine) Applies(in engines.Input) bool {
	for _, f := range in.Files {
		if f.Status != "D" {
			return true
		}
	}
	return false
}

// maxLineaComandos acota lo que se le pasa a semgrep de una sola vez.
//
// Windows corta CreateProcess a 32767 caracteres de línea de comandos, y este
// motor pasa una ruta absoluta POR ARCHIVO. Un repo de 854 archivos genera
// 105 000 caracteres: semgrep no llega a arrancar y las 112 reglas de la casa
// quedan sin aplicar — en el análisis y, peor, en la baseline. El repo de
// pruebas del propio agente tiene 156 archivos (16 000 caracteres) y por eso
// nunca lo destapó.
//
// semgrep 1.172 no tiene ninguna opción para leer los objetivos de un archivo,
// así que la salida es trocear. 30 000 deja margen para el binario, las reglas
// y el resto de argumentos.
const maxLineaComandos = 30000

// Cache es el caché de resultados deterministas (§9). Aquí la clave es el
// sha del contenido de CADA archivo — semgrep es por archivo; los motores de
// módulo usan el mismo caché con su huella agregada.
type Cache = engines.Cache

// objetivo es un archivo a analizar: ruta absoluta para semgrep, relativa
// para atribuir hallazgos, y la huella del contenido como clave de caché.
type objetivo struct {
	abs, rel, sha string
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "semgrep"
	}
	rules := filepath.Join(in.RulepackDir, "semgrep")
	if _, err := os.Stat(rules); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSinRulepack, rules)
	}

	// Solo archivos tocados (sección 5, etapa 2): targets explícitos.
	var pendientes []objetivo
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		pendientes = append(pendientes, objetivo{
			abs: filepath.Join(in.RepoRoot, filepath.FromSlash(f.Path)),
			rel: f.Path,
			sha: f.SHA256,
		})
	}
	if len(pendientes) == 0 {
		return nil, nil
	}

	// ── Aciertos de caché: mismo contenido + mismas reglas = mismos hallazgos.
	// El caché es direccionado por CONTENIDO: dos archivos idénticos comparten
	// entrada, así que al reproducir un acierto se reescribe la ruta (y con
	// ella el fingerprint) para el archivo concreto de esta corrida.
	var findings []finding.Finding
	if e.Cache != nil {
		shas := make([]string, 0, len(pendientes))
		for _, o := range pendientes {
			if o.sha != "" {
				shas = append(shas, o.sha)
			}
		}
		aciertos := e.Cache.Leer(shas)
		var quedan []objetivo
		for _, o := range pendientes {
			fs, ok := aciertos[o.sha]
			if o.sha == "" || !ok {
				quedan = append(quedan, o)
				continue
			}
			for _, f := range fs { // copia: la entrada puede servir a dos rutas
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

	objetivos := make([]string, len(pendientes))
	for i, o := range pendientes {
		objetivos[i] = o.abs
	}

	var nuevos []finding.Finding
	rotasVistas := map[string]bool{}
	for _, lote := range lotes(objetivos, maxLineaComandos) {
		hallados, rotas, err := e.correrLote(ctx, bin, rules, in, lote)
		if err != nil {
			return nil, err
		}
		nuevos = append(nuevos, hallados...)
		for _, r := range rotas {
			rotasVistas[r] = true
		}
	}
	// Las reglas rotas se reportan una vez, no una por lote.
	if len(rotasVistas) > 0 {
		ids := make([]string, 0, len(rotasVistas))
		for r := range rotasVistas {
			ids = append(ids, r)
		}
		sort.Strings(ids)
		log.Printf("semgrep: %d regla(s) del rulepack no compilan y no se aplicaron: %s",
			len(ids), strings.Join(ids, ", "))
	}
	// Con reglas rotas NO se cachea: el resultado es de un pack incompleto, y
	// servirlo mañana —cuando las reglas ya compilen— sería cobertura perdida
	// que además parece un acierto.
	if e.Cache != nil && len(rotasVistas) == 0 {
		e.Cache.Guardar(porArchivo(nuevos, pendientes))
	}
	return append(findings, nuevos...), nil
}

// porArchivo atribuye los hallazgos recién producidos a su archivo y devuelve
// sha → hallazgos, listo para el caché. Los archivos analizados SIN hallazgos
// entran con lista vacía. Los archivos sin huella quedan fuera (no cacheables).
func porArchivo(fs []finding.Finding, analizados []objetivo) map[string][]finding.Finding {
	shaPorRel := make(map[string]string, len(analizados))
	out := make(map[string][]finding.Finding, len(analizados))
	for _, o := range analizados {
		if o.sha == "" {
			continue
		}
		// Dos archivos con el MISMO contenido comparten entrada, y la puebla
		// sólo el primero. Si entraran los dos, out[sha] acabaría con la unión de
		// sus hallazgos, y al servir el acierto cada ruta recibiría también los
		// del otro reescritos con su nombre —el bucle de arriba reescribe File y
		// recalcula la huella—: cada archivo reportaría el doble. Como el
		// contenido es idéntico, los hallazgos del primero son los de cualquiera,
		// que es justo lo que el caché por contenido da por supuesto.
		if _, ya := out[o.sha]; ya {
			continue
		}
		shaPorRel[o.rel] = o.sha
		out[o.sha] = []finding.Finding{}
	}
	for _, f := range fs {
		if sha, ok := shaPorRel[f.File]; ok {
			out[sha] = append(out[sha], f)
		}
	}
	return out
}

// lotes reparte los objetivos en grupos cuya longitud sumada cabe en el límite.
// Un objetivo que por sí solo lo excediera va en su propio lote: recortarlo
// sería dejar de analizar un archivo en silencio, que es justo lo que este
// troceado viene a impedir.
func lotes(objetivos []string, limite int) [][]string {
	var out [][]string
	actual := []string{}
	largo := 0
	for _, o := range objetivos {
		coste := len(o) + 1 // +1 por el espacio separador
		if len(actual) > 0 && largo+coste > limite {
			out = append(out, actual)
			actual, largo = []string{}, 0
		}
		actual = append(actual, o)
		largo += coste
	}
	if len(actual) > 0 {
		out = append(out, actual)
	}
	return out
}

// ajustesPropios devuelve la ruta del settings.yml que usa SÓLO CodeGuard.
//
// El directorio se crea si falta; si no se puede (disco lleno, política), se
// devuelve la ruta igual: semgrep se quejará de eso, y un aviso concreto es
// mejor que caer al archivo compartido y volver a competir por él en silencio.
func ajustesPropios() string {
	base, err := os.UserCacheDir() // %LOCALAPPDATA% en Windows
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "CodeGuard", "semgrep")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "settings.yml")
}

// correrLote invoca semgrep una vez sobre los objetivos dados y devuelve sus
// hallazgos y las reglas del pack que no compilaron.
func (e *Engine) correrLote(ctx context.Context, bin, rules string, in engines.Input, objetivos []string) ([]finding.Finding, []string, error) {
	args := append([]string{"scan", "--config", rules, "--json", "--metrics=off", "--quiet", "--disable-version-check"}, objetivos...)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	// Sin esto, el CLI de Python lee las reglas YAML con la codificación
	// regional de Windows (cp1252) y los mensajes con acentos salen rotos.
	//
	// SEMGREP_SETTINGS_FILE nos da un archivo PROPIO. Por defecto semgrep abre
	// y ESCRIBE ~/.semgrep/settings.yml, que no es nuestro: lo comparte con el
	// plugin del IDE, con un `semgrep` que el desarrollador corra a mano y con
	// cualquier otra herramienta que lo use. Escribir en el estado de las
	// herramientas ajenas no es asunto nuestro, y nos deja expuestos a lo que
	// otro proceso le haga a ese archivo.
	//
	// Honestidad sobre el alcance: esto es higiene, no el arreglo de un fallo
	// observado. Se llegó aquí sospechando que la contención sobre ese archivo
	// causaba un `semgrep:error` real, y el control lo desmintió — seis
	// semgrep simultáneos compartiendo settings terminaron los seis sin un solo
	// PermissionError. La causa de aquel error era otra y está arreglada en
	// gitdiff (rutas entrecomilladas por git). Se mantiene la separación porque
	// quitar un recurso mutable compartido es bueno por sí solo, no porque
	// arregle nada medido.
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8",
		"SEMGREP_SETTINGS_FILE="+ajustesPropios())
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Stdout
	// Semgrep sale con 1 cuando hay hallazgos bloqueantes; el JSON sigue siendo válido.
	if runErr != nil && len(out) == 0 {
		// %w: sin él, un semgrep ausente o un plazo agotado llegaban al
		// orquestador como un error genérico y se reportaban como fallo.
		return nil, nil, fmt.Errorf("semgrep no corrió: %w", runErr)
	}
	// Un JSON recortado no se puede parsear; decirlo es mejor que un error de sintaxis.
	if salida.Recortada {
		return nil, nil, fmt.Errorf("semgrep devolvió más de %d MB de salida; revisa el alcance de las reglas", proc.MaxSalida>>20)
	}

	var res sgResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, nil, fmt.Errorf("salida de semgrep ilegible: %v", err)
	}
	// Antes de mirar un solo hallazgo: ¿llegó semgrep a analizar? Un JSON válido
	// con cero resultados es indistinguible de un repo limpio salvo por aquí.
	if e := res.fatal(); e != nil {
		return nil, nil, fmt.Errorf("semgrep no llegó a analizar (%s): %s",
			e.Type, truncar(e.Message, 300))
	}

	findings := make([]finding.Finding, 0, len(res.Results))
	for _, r := range res.Results {
		sev := finding.Warning
		if strings.EqualFold(r.Extra.Severity, "ERROR") {
			sev = finding.Error
		}
		pillar := finding.Quality
		switch strings.ToLower(r.Extra.Metadata.Pillar) {
		case "security":
			pillar = finding.Security
		case "data":
			pillar = finding.Data
		}
		rel, err := filepath.Rel(in.RepoRoot, r.Path)
		if err != nil {
			rel = r.Path
		}
		f := finding.Finding{
			Engine:  "semgrep",
			RuleKey: shortRuleID(r.CheckID),
			Pillar:  pillar,
			// Política de compuertas §7: semgrep ERROR bloquea, WARNING avisa.
			Severity:    sev,
			Blocking:    sev == finding.Error,
			File:        filepath.ToSlash(rel),
			Line:        r.Start.Line,
			EndLine:     r.End.Line,
			Message:     r.Extra.Message,
			Why:         r.Extra.Metadata.Why,
			FixHint:     r.Extra.Metadata.FixHint,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: firstLine(r.Extra.Lines),
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, res.reglasRotas(), nil
}

